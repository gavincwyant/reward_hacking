"""Normalize CyberGym traces into a common step list for candidate runs.

Usage: python3 -I normalize.py <traces_root> <out.jsonl>
Each output line: {run, agent, task, difficulty, pocs, steps:[{i, kind, text}]}
kind in {thought, action, obs}. Only runs with a pass (vul!=0, fix==0) or a
crash-both PoC (vul!=0, fix!=0) are emitted.
"""
import glob, json, os, sys

ROOT, OUT = sys.argv[1], sys.argv[2]


def s(x):
    return x if isinstance(x, str) else json.dumps(x)


def oh_steps(run):
    t = json.load(open(os.path.join(run, "trajectory")))
    out = []
    for e in t:
        src = e.get("source")
        args = e.get("args") or {}
        if src == "agent" and "action" in e:
            th = args.get("thought") or ""
            if th:
                out.append(("thought", th))
            if e["action"] == "message":
                out.append(("thought", args.get("content") or e.get("message", "")))
            else:
                a = args.get("command") or args.get("code") or ""
                if args.get("path") and a in ("", "create", "str_replace", "insert", "view", "undo_edit"):
                    a = f"{e['action']} {args.get('path')} {args.get('file_text') or args.get('new_str') or ''}"
                out.append(("action", s(a)))
        elif "observation" in e:
            out.append(("obs", s(e.get("content", ""))))
    return out


def codex_steps(run):
    out = []
    for line in open(os.path.join(run, "console.log"), errors="replace"):
        try:
            e = json.loads(line)
        except Exception:
            continue
        ty = e.get("type")
        if ty == "function_call":
            try:
                a = json.loads(e.get("arguments", "{}"))
                cmd = a.get("command", a)
                cmd = " ".join(cmd) if isinstance(cmd, list) else s(cmd)
            except Exception:
                cmd = e.get("arguments", "")
            out.append(("action", cmd))
        elif ty == "function_call_output":
            o = e.get("output", "")
            try:
                o = json.loads(o).get("output", o)
            except Exception:
                pass
            out.append(("obs", s(o)))
        elif ty in ("message", "reasoning") and e.get("role") != "user":
            parts = e.get("content") or e.get("summary") or []
            txt = " ".join(p.get("text", "") for p in parts if isinstance(p, dict))
            if txt:
                out.append(("thought", txt))
    return out


def cybench_steps(run):
    out = []
    for f in glob.glob(os.path.join(run, "app", "**", "*run_log.json"), recursive=True):
        j = json.load(open(f))
        for sub in j.get("subtask_completions", {}).values():
            for it in sub.get("iterations", []):
                out.append(("thought", (it.get("model_response") or {}).get("value", "")))
                ex = it.get("execution_output") or {}
                cmd = ex.get("command") or {}
                out.append(("action", s(cmd.get("command_str", cmd))))
                out.append(("obs", s(ex.get("stdout", "")) + s(ex.get("stderr", "") or "")))
    return out


def enigma_steps(run):
    out = []
    for f in glob.glob(os.path.join(run, "trajectories", "*", "*", "*.traj")):
        j = json.load(open(f))
        for st in j.get("trajectory", []):
            out.append(("thought", st.get("thought", "")))
            out.append(("action", st.get("action", "")))
            out.append(("obs", s(st.get("observation", ""))))
    return out


def steps_for(agent, run):
    if agent.startswith("openhands"):
        return oh_steps(run)
    if agent.startswith("codex"):
        return codex_steps(run)
    if agent.startswith("cybench"):
        return cybench_steps(run)
    if agent.startswith("enigma"):
        return enigma_steps(run)
    return []


with open(OUT, "w") as fo:
    for agent in sorted(os.listdir(ROOT)):
        adir = os.path.join(ROOT, agent)
        if not os.path.isdir(adir):
            continue
        for rn in sorted(os.listdir(adir)):
            run = os.path.join(adir, rn)
            try:
                res = json.load(open(os.path.join(run, "result.json")))
                args = json.load(open(os.path.join(run, "args.json")))
            except Exception:
                continue
            pocs = res.get("pocs", [])
            nz = lambda c: c not in (0, None)
            if not any(nz(p.get("vul_exit_code")) for p in pocs):
                continue
            try:
                steps = steps_for(agent, run)
            except Exception as ex:
                steps = [("obs", f"PARSE_ERROR {ex}")]
            rec = {
                "run": os.path.join(agent, rn),
                "agent": agent,
                "task": args["task"]["task_id"],
                "difficulty": args["task"].get("difficulty"),
                "pocs": [{k: p.get(k) for k in ("poc_id", "poc_length", "vul_exit_code", "fix_exit_code")} for p in pocs],
                "steps": [{"i": i, "kind": k, "text": t[:20000]} for i, (k, t) in enumerate(steps)],
            }
            fo.write(json.dumps(rec) + "\n")
