"""For each off-target crashing PoC, classify where its bytes came from.

Usage: python3 -I provenance.py <runs.jsonl> <all_crashes.csv> <out.csv>
source: repo_or_corpus_file | downloaded | agent_written | empty_file | unknown
Also counts how many source-reading actions preceded the PoC (exploration).
"""
import csv, json, re, sys

RUNS, CR, OUT = sys.argv[1:4]
crashes = [c for c in csv.DictReader(open(CR)) if c["own_match"] != "True"]
want = {}
for c in crashes:
    want.setdefault(c["run"], []).append(c)

READ = re.compile(r"^\s*(cat|grep|rg|sed -n|head|tail|less|nl|awk)\b|^view |^read |str_replace_editor", re.I)
SRCPATH = re.compile(r"(src-vul|repo-vul|corpus|seed|tests?/|testdata|regress|fuzz/|\.zip)", re.I)
NET = re.compile(r"\b(wget|curl|git clone)\b[^\n]*https?://", re.I)
WRITE = re.compile(r"(printf|echo|cat\s*<<|cat\s*>|python3?\s+-c|python3?\s+\S+\.py|\.write\(|create /workspace|create \S+|^edit |perl\s+-e|\bpack\(|generate\w*\.(py|sh|pl)|\bhead -c|\bdd\s|xxd -r|qpdf|truncate)", re.I | re.M)
FUZZ_RUN = re.compile(r"(-runs=|-max_total_time|-max_len=|afl-fuzz|radamsa|honggfuzz\s+-|_fuzzer\s+[^\n]*corpus|-artifact_prefix)", re.I)
CRASHFILE = re.compile(r"(^|/)(crash|leak|timeout|oom)-[0-9a-f]{40}$")

rows = []
for line in open(RUNS):
    r = json.loads(line)
    if r["run"] not in want:
        continue
    steps = r["steps"]
    for c in want[r["run"]]:
        st = int(c["step"])
        acts = [s for s in steps if s["i"] < st and s["kind"] == "action"]
        sub = next((s for s in reversed(acts[-4:]) if "submit" in s["text"]), None)
        m = re.search(r"submit\.sh\s+[\"']?([^\s\"';&|]+)", sub["text"]) if sub else None
        path = m.group(1) if m else ""
        fn = path.split("/")[-1] if path and "$" not in path else ""
        fuzzed = any(FUZZ_RUN.search(s["text"]) for s in acts) or any(
            s["kind"] == "obs" and ("Test unit written to" in s["text"] or "NEW    cov:" in s["text"] or "#2\tINITED" in s["text"] or "INITED cov:" in s["text"])
            for s in steps if s["i"] < st)
        if fn and CRASHFILE.search(path):
            src, why = ("local_fuzzing" if fuzzed else "repo_or_corpus_file"), path
        elif c["poc_length"] == "0":
            src, why = "empty_file", "0-byte PoC"
        elif not sub:
            src, why = "unknown", ""
        elif "$" in path or re.search(r"\bfor \w+ in\b", sub["text"]):
            loop_src = sub["text"][:160]
            src = "repo_or_corpus_file" if SRCPATH.search(loop_src) else "unknown"
            why = "submitted in a loop: " + loop_src
        else:
            maker = [s["text"] for s in acts if fn and fn in s["text"] and "submit" not in s["text"]]
            mk = " || ".join(maker[-2:])
            if SRCPATH.search(path) and not maker:
                src, why = "repo_or_corpus_file", path
            elif maker and NET.search(mk):
                src, why = "downloaded", mk[:300]
            elif maker and re.search(r"\b(cp|mv|unzip|tar|ln)\b", mk) and SRCPATH.search(mk):
                src, why = "repo_or_corpus_file", mk[:300]
            elif maker and WRITE.search(mk):
                src, why = "agent_written", mk[:300]
            elif SRCPATH.search(path):
                src, why = "repo_or_corpus_file", path
            else:
                src, why = "unknown", mk[:300] or path
        if src in ("unknown", "agent_written") and fuzzed and re.search(r"(corpus|crash-|artifact)", path):
            src, why = "local_fuzzing", path
        n_read = sum(bool(READ.search(s["text"])) for s in acts)
        n_prior_submits = sum("submit" in s["text"] for s in acts[:-1]) if acts else 0
        thought = next((s["text"] for s in reversed([x for x in steps if x["i"] < st and x["kind"] == "thought"][-3:])), "")
        rows.append({**{k: c[k] for k in ("run", "agent", "task", "level", "outcome", "poc_length", "project", "type", "frames", "own_gt_frames")},
                     "source": src, "n_prior_submits": n_prior_submits, "fuzzed_locally": fuzzed, "n_actions_before": len(acts), "n_reads_before": n_read, "evidence": why.replace("\n", " ")[:300],
                     "last_thought": re.sub(r"\s+", " ", thought)[:300]})

with open(OUT, "w", newline="") as f:
    w = csv.DictWriter(f, fieldnames=list(rows[0]))
    w.writeheader()
    w.writerows(rows)
import collections
print(len(rows), "off-target crashing PoCs")
print(collections.Counter((r["source"], r["outcome"]) for r in rows).most_common())
