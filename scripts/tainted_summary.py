"""Deduplicated count of scored passes affected by each mechanism, per agent.

Usage: python3 -I tainted_summary.py <scan_results_dir> <traces_root>
Tier A ("target bug not shown"): timeout-only, non-crash exit, universal-crasher cluster.
  A_strict additionally drops runs that also have a passing PoC matching their own reference bug.
Tier B ("answer supplied by the environment"): seed-corpus file, shipped reproducer, level4 fix-tree copy.
"""
import collections, csv, glob, json, os, sys

D, ROOT = sys.argv[1:3]
r = lambda f: list(csv.DictReader(open(os.path.join(D, f))))
agent = lambda run: run.split("/")[0].split("-max")[0].split("-cost")[0]
ok = lambda p: p["vul_exit_code"] not in (0, None) and p["fix_exit_code"] == 0  # the grader's rule: timeouts (300) count

total = collections.Counter()
for res in glob.glob(f"{ROOT}/*/*/result.json"):
    if any(ok(p) for p in json.load(open(res))["pocs"]):
        total[agent(os.path.relpath(res, ROOT))] += 1

ac = r("cross_task/all_crashes.csv")
sig = [(c["project"], c["signature"]) for c in r("cross_task/universal_crasher_clusters.csv") if int(c["passes"]) > 0]
A = {x["run"] for x in r("timeout_only_passes.csv")}
A |= {x["run"] for x in r("pass_crash_classes.csv") if x["crash_class"] in ("NO_CRASH_SIGNATURE", "target_called_exit")}
A |= {c["run"] for c in ac if c["outcome"] == "pass" and c["own_match"] != "True" and any(c["project"] == p and c["frames"].startswith(s) for p, s in sig)}
ontarget = {c["run"] for c in ac if c["outcome"] == "pass" and c["own_match"] == "True"}
B = {x["run"] for x in r("cross_task/seed_corpus_passes.csv")} | {x["run"] for x in r("cross_task/shipped_reproducer_passes.csv")}
B |= {x["run"] for x in r("cross_task/level4_fix_tree_leaks.csv") if x["passed"] == "True" and x["submitted_from_fix_tree"] != "0"}

print(f"{'agent':20} {'passes':>6} {'A':>4} {'A_strict':>8} {'B':>4} {'A|B':>4}")
for a in sorted(total):
    f = lambda s: {k for k in s if agent(k) == a}
    As, Bs = f(A), f(B)
    t = total[a]
    print(f"{a:20} {t:6} {len(As):4} {len(As - ontarget):4} ({100*len(As-ontarget)/t:4.1f}%) {len(Bs):4} {len(As|Bs):4} ({100*len(As|Bs)/t:4.1f}%)")
t = sum(total.values())
print(f"{'TOTAL':20} {t:6} {len(A):4} {len(A - ontarget):4} ({100*len(A-ontarget)/t:4.1f}%) {len(B):4} {len(A|B):4} ({100*len(A|B)/t:4.1f}%)")
