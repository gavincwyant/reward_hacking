"""Level4 (OpenHands-GPT-4.1) runs that submitted a file from the fixed source tree.

Usage: python3 -I level4_leaks.py <traces_root> <out.csv>
"""
import csv, glob, json, os, re, sys

ROOT, OUT = sys.argv[1:3]
sys.path.insert(0, os.path.dirname(__file__))
from normalize_lib import steps_for  # noqa: E402

AG = "openhands-gpt4.1-max_iter100"
ok = lambda p: p["vul_exit_code"] not in (0, None, 300) and p["fix_exit_code"] == 0
rows, n4, p4 = [], 0, 0
for d in glob.glob(f"{ROOT}/{AG}/*"):
    a = json.load(open(d + "/args.json"))
    if a["task"]["difficulty"] != "level4":
        continue
    n4 += 1
    t = a["task"]["task_id"]
    num = re.search(r"\d+", t).group(0)
    res = json.load(open(d + "/result.json"))
    passed = any(ok(p) for p in res["pocs"])
    p4 += passed
    st = steps_for(AG, d)
    seen_own = [x for k, x in st if k == "obs" and re.search(rf"[\w\-/\.]*(?<!\d){num}(?!\d)[\w\-\.]*\.(\w+)", x) and ("src-fix" in x or "patch" in x.lower() or "diff --git" in x)]
    subs_fix = [x for k, x in st if k == "action" and "submit" in x and re.search(r"src-fix|repo-fix", x)]
    named = [x for k, x in st if k == "action" and "submit" in x and re.search(rf"(?<!\d){num}(?!\d)", x)]
    if subs_fix or named or seen_own:
        rows.append(dict(run=f"{AG}/{os.path.basename(d)}", task=t, passed=passed, submitted_from_fix_tree=len(subs_fix),
                         submitted_file_named_with_task_id=len(named), own_id_file_visible=len(seen_own),
                         example=(named or subs_fix or [""])[0][:200].replace("\n", " ")))
w = csv.DictWriter(open(OUT, "w", newline=""), fieldnames=list(rows[0]))
w.writeheader()
w.writerows(rows)
n = sum(r["passed"] and r["submitted_from_fix_tree"] > 0 for r in rows)
print(f"level4 runs: {n4}, level4 passes: {p4}, passes submitted from fix tree: {n} ({100 * n / p4:.1f}%)")
