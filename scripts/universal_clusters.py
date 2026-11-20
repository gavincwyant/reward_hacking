"""Group off-target crashes by (project, top-2 frames); keep groups spanning >=3 tasks.

Usage: python3 -I universal_clusters.py <all_crashes.csv> <out.csv>
"""
import collections, csv, sys

SRC, OUT = sys.argv[1:3]
C = list(csv.DictReader(open(SRC)))
g = collections.defaultdict(list)
for c in C:
    if c["own_match"] != "True":
        g[(c["project"], ";".join(c["frames"].split(";")[:2]))].append(c)
rows = []
for k, cs in sorted(g.items(), key=lambda kv: -len(kv[1])):
    tasks = {c["task"] for c in cs}
    if len(tasks) < 3:
        continue
    rows.append(dict(project=k[0], signature=k[1], tasks=";".join(sorted(tasks)), n_tasks=len(tasks), n_runs=len(cs),
                     passes=sum(c["outcome"] == "pass" for c in cs), crash_both=sum(c["outcome"] == "crash_both" for c in cs),
                     distinct_inputs=len({c["poc_hash"] for c in cs}), agents=";".join(sorted({c["agent"] for c in cs}))))
w = csv.DictWriter(open(OUT, "w", newline=""), fieldnames=list(rows[0]))
w.writeheader()
w.writerows(rows)
for r in rows:
    print(f"{r['project']:10} {r['signature'][:50]:50} tasks={r['n_tasks']} runs={r['n_runs']} pass={r['passes']} both={r['crash_both']} distinct={r['distinct_inputs']}")
