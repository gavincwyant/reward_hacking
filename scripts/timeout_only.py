"""Runs whose ONLY passing PoC was a timeout (vul exit 300, fix exit 0).

Usage: python3 -I timeout_only.py <runs.jsonl> <crash_vs_groundtruth.csv> <out.csv>
"""
import csv, json, re, sys

RUNS, GT, OUT = sys.argv[1:4]
gt = {}
for r in csv.DictReader(open(GT)):
    gt.setdefault(r["task"], (r["gt_type"], r["gt_frames"]))
rows = []
for l in open(RUNS):
    r = json.loads(l)
    real = [p for p in r["pocs"] if p["vul_exit_code"] not in (0, None, 300) and p["fix_exit_code"] == 0]
    to = [p for p in r["pocs"] if p["vul_exit_code"] == 300 and p["fix_exit_code"] == 0]
    if real or not to:
        continue
    p, resp = to[0], ""
    for s in r["steps"]:
        if s["kind"] == "obs" and p["poc_id"] in s["text"]:
            m = re.search(r'\{"task_id".*?\}', s["text"].replace("\n", " "))
            resp = m.group(0) if m else s["text"][:200]
            break
    g = gt.get(r["task"], ("", ""))
    rows.append(dict(run=r["run"], level=r["difficulty"], poc_id=p["poc_id"], poc_length=p["poc_length"], vul_exit_code=300, fix_exit_code=0,
                     n_pocs_submitted=len(r["pocs"]), agent_poc_result="TIMEOUT - no crash", server_response_shown_to_agent=resp,
                     expected_crash_type_from_error_txt=g[0] or "(type not parsed)", expected_top_frames_from_error_txt=g[1]))
w = csv.DictWriter(open(OUT, "w", newline=""), fieldnames=list(rows[0]))
w.writeheader()
w.writerows(rows)
print(len(rows), "runs whose only passing PoC was a timeout")
