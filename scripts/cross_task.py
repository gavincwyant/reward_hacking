"""Cross-task crash matching: did an agent on task X reproduce task Y's bug?

Usage: python3 -I cross_task.py <traces_root> <runs.jsonl> <out_dir>
Outputs:
  gt_index.json         ground-truth crash signature per task (from error.txt in level3/4 traces)
  all_crashes.csv       every crashing PoC seen in any trace, with signature + own-task match
  cross_task_hits.csv   crashes whose signature matches a DIFFERENT task's ground truth
  universal.csv         poc_hash / signature reused across multiple tasks
"""
import collections, csv, json, os, re, sys

ROOT, RUNS, OUT = sys.argv[1:4]
sys.path.insert(0, os.path.dirname(__file__))
from normalize_lib import steps_for  # noqa: E402

TYPE = re.compile(r"ERROR: (\w+Sanitizer): ([\w\-]+)|WARNING: (MemorySanitizer): ([\w\-]+)|runtime error: ([a-z][a-z \-]{2,40})|(detected memory leaks)|(out-of-memory)|(fuzz target exited)", re.I)
FRAME = re.compile(r"#(\d+)\s+0x[0-9a-f]+\s+in\s+(\S+)\s+(/\S+)?")
GENERIC = re.compile(r"^(__|LLVMFuzzer|main$|fuzzer::|std::|_start|__libc|raise|abort|malloc|calloc|realloc|free|operator|mem(cpy|move|set|cmp|chr)|str\w*$|__asan|__msan|__ubsan|gsignal|Printf|Report|PrintStackTrace|ExitCallback|ExecuteCallback|RunOneTest|FuzzerDriver|MallocHook|HandleMalloc|CrashCallback|Check\w*Failed|\w*Interceptor\w*|AsanCheckFailed|GetShadowKind|HonggfuzzMain|wordexp)")
NOT_PROJ = {"llvm", "llvm-project", "libfuzzer", "aflplusplus", "honggfuzz", "compiler-rt", "build", "work", "out"}
POCID = re.compile(r'poc_id"?\s*[:=]\s*"?([0-9a-f]{32})')


def sig(text):
    text = text.replace("\\n", "\n")
    m = TYPE.search(text)
    ty = ""
    if m:
        g = [x for x in m.groups() if x]
        ty = (g[-1] if len(g) > 1 else g[0]).strip().lower()
    frames, projs = [], collections.Counter()
    # only the first stack (the crash itself, not alloc/free stacks)
    k = text.find("#0 ")
    first_stack = re.split(r"\n\s*\n|freed by thread|previously allocated by|allocated by thread", text[k:] if k >= 0 else text, maxsplit=1)[0]
    for n, f, path in FRAME.findall(first_stack):
        if path:
            pm = re.match(r"/src/([^/]+)/", path)
            if pm and pm.group(1) not in NOT_PROJ:
                projs[pm.group(1)] += 1
        f = re.sub(r"\(.*", "", f).split("::")[-1]
        if not GENERIC.match(f) and f not in frames:
            frames.append(f)
    proj = projs.most_common(1)[0][0] if projs else ""
    return ty, frames[:4], proj


def num(task):
    m = re.search(r"(\d+)", task)
    return int(m.group(1)) if m else -1


# ---------- ground truth index ----------
gt = {}
for agent in os.listdir(ROOT):
    if not agent.startswith("openhands-gpt4.1"):
        continue
    for rn in os.listdir(os.path.join(ROOT, agent)):
        run = os.path.join(ROOT, agent, rn)
        try:
            a = json.load(open(os.path.join(run, "args.json")))
        except Exception:
            continue
        t = a["task"]["task_id"]
        if a["task"]["difficulty"] not in ("level3", "level4") or t in gt:
            continue
        try:
            st = steps_for(agent, run)
        except Exception:
            continue
        for j, (k, txt) in enumerate(st):
            if k == "action" and "error.txt" in txt:
                obs = next((x[1] for x in st[j + 1:j + 3] if x[0] == "obs"), "")
                ty, fr, pj = sig(obs)
                if fr:
                    gt[t] = dict(type=ty, frames=fr, project=pj)
                    break
by_top = collections.defaultdict(list)  # (project, top frame) -> tasks
for t, g in gt.items():
    by_top[(g["project"], g["frames"][0])].append(t)
print("GT tasks with frames:", len(gt))

# ---------- every crash in every trace ----------
crashes = []
for line in open(RUNS):
    r = json.loads(line)
    pocs = {p["poc_id"]: p for p in r["pocs"]}
    steps = r["steps"]
    seen = set()
    for st in steps:
        if st["kind"] != "obs":
            continue
        m = POCID.search(st["text"])
        if not m or m.group(1) in seen or m.group(1) not in pocs:
            continue
        p = pocs[m.group(1)]
        seen.add(p["poc_id"])
        if p["vul_exit_code"] in (0, None, 300):
            continue
        ty, fr, pj = sig(st["text"])
        if not fr:
            continue
        prev = [s for s in steps if s["i"] < st["i"] and s["kind"] == "action"]
        sub = next((s["text"] for s in reversed(prev[-4:]) if "submit" in s["text"]), "")
        own = gt.get(r["task"])
        own_match = bool(own and own["frames"][0] in fr[:2]) if own else None
        crashes.append(dict(run=r["run"], agent=r["agent"], task=r["task"], level=r["difficulty"], poc_id=p["poc_id"],
                            poc_hash=p.get("poc_hash", ""), poc_length=p["poc_length"], vul=p["vul_exit_code"], fix=p["fix_exit_code"],
                            outcome="pass" if p["fix_exit_code"] == 0 else "crash_both", project=pj or (own or {}).get("project", ""),
                            type=ty, frames=";".join(fr), own_gt_frames=";".join(own["frames"]) if own else "",
                            own_match=own_match, step=st["i"], submit=sub[:200].replace("\n", " ")))

# poc_hash isn't in the normalized pocs; pull from result.json
hashes = {}
for c in crashes:
    if not c["poc_hash"]:
        if c["run"] not in hashes:
            try:
                hashes[c["run"]] = {p["poc_id"]: p.get("poc_hash", "") for p in json.load(open(os.path.join(ROOT, c["run"], "result.json")))["pocs"]}
            except Exception:
                hashes[c["run"]] = {}
        c["poc_hash"] = hashes[c["run"]].get(c["poc_id"], "")
print("crashing PoCs with frames:", len(crashes))

# ---------- search 1: matches another task's GT ----------
hits = []
for c in crashes:
    fr = c["frames"].split(";")
    if c["own_match"]:
        continue
    cands = set()
    for f in fr[:2]:
        for t in by_top.get((c["project"], f), []):
            if t != c["task"]:
                cands.add(t)
    if not cands and not c["project"]:
        for (pj, f0), ts in by_top.items():
            if f0 == fr[0]:
                cands.update(t for t in ts if t != c["task"])
    for t in sorted(cands):
        g = gt[t]
        strength = len(set(fr[:3]) & set(g["frames"][:3]))
        same_family = bool(c["type"] and g["type"] and c["type"].split("-")[0] == g["type"].split("-")[0])
        when = ("LATER" if num(t) > num(c["task"]) else "earlier") if t.split(":")[0] == c["task"].split(":")[0] else "?"
        hits.append({**c, "matched_task": t, "matched_frames": ";".join(g["frames"]), "matched_type": g["type"],
                     "frame_overlap": strength, "same_type_family": same_family, "matched_is": when})

# ---------- search 2: universal crashers ----------
uni = []
for key in ("poc_hash", "frames"):
    grp = collections.defaultdict(list)
    for c in crashes:
        if c[key]:
            grp[(c["project"], c[key]) if key == "frames" else c[key]].append(c)
    for k, cs in grp.items():
        tasks = {c["task"] for c in cs}
        if len(tasks) >= 2:
            uni.append(dict(key_type=key, key=str(k)[:160], n_tasks=len(tasks), n_runs=len(cs), agents=";".join(sorted({c["agent"].split("-max")[0].split("-cost")[0] for c in cs})),
                            tasks=";".join(sorted(tasks)), outcomes=";".join(sorted({c["outcome"] for c in cs})),
                            own_match_any=any(c["own_match"] for c in cs), project=cs[0]["project"], type=cs[0]["type"]))
uni.sort(key=lambda u: (-u["n_tasks"], -u["n_runs"]))

os.makedirs(OUT, exist_ok=True)
json.dump(gt, open(os.path.join(OUT, "gt_index.json"), "w"), indent=0)
for name, rows in (("all_crashes.csv", crashes), ("cross_task_hits.csv", hits), ("universal.csv", uni)):
    if rows:
        with open(os.path.join(OUT, name), "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=list(rows[0]))
            w.writeheader()
            w.writerows(rows)
print("own-task match:", collections.Counter(c["own_match"] for c in crashes))
print("cross-task hits:", len(hits), "| distinct crashing PoCs:", len({(h['run'], h['poc_id']) for h in hits}))
print(collections.Counter((h["matched_is"], h["outcome"]) for h in hits))
print("universal groups:", collections.Counter(u["key_type"] for u in uni))
