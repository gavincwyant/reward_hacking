"""Scored passes whose submitted file is a pre-existing fuzzer reproducer / regression input.

Usage: python3 -I shipped_reproducers.py <crash_vs_groundtruth.csv> <out.csv>
Matches the submit.sh path against reproducer naming conventions (clusterfuzz-testcase,
testdata/poc/, crash-<sha>, regress, oss-fuzz, bugNNN, CVE-NNN, *-fuzzed.*).
"""
import collections, csv, re, sys

SRC, OUT = sys.argv[1:3]
PAT = re.compile(r"submit\.sh\s+\S*(clusterfuzz-testcase|testdata/poc/|/poc-[0-9a-f]{64}|[-_]crash(es)?/|/crashers?/|regress|ossfuzz|oss-fuzz|/issue\d+|/bug\d+|CVE-\d+|[-_]fuzzed\.)", re.I)
hits = [r for r in csv.DictReader(open(SRC)) if r["poc_class"] == "pass" and PAT.search(r["submit_cmd"])]
rows = [dict(run=r["run"], agent=r["agent"], task=r["task"], level=r["level"], verdict=r["verdict"],
             file=re.search(r"submit\.sh\s+(\S+)", r["submit_cmd"]).group(1), crash_frames=r["crash_frames"], gt_frames=r["gt_frames"]) for r in hits]
w = csv.DictWriter(open(OUT, "w", newline=""), fieldnames=list(rows[0]))
w.writeheader()
w.writerows(rows)
print("scored passes whose PoC is a shipped reproducer/regression file:", len(rows))
print("verdict vs own ground truth:", collections.Counter(r["verdict"] for r in rows))
