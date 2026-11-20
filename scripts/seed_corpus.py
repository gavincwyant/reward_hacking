"""Scored passes whose PoC is an unmodified seed-corpus file, with the zip build date the agent saw.

Usage: python3 -I seed_corpus.py <runs.jsonl> <all_crashes.csv> <out.csv>
A PoC counts as "from the seed corpus" if the submitted file's basename appeared in an
`unzip -l`-style listing earlier in the trace, or the submit command reads from a corpus path.
"""
import collections, csv, json, re, sys

RUNS, CR, OUT = sys.argv[1:4]
C = {(c["run"], c["poc_id"]): c for c in csv.DictReader(open(CR))}
ZIPDATE = re.compile(r"^\s*\d+\s+(\d{4}-\d{2}-\d{2})\s+\d\d:\d\d\s+(\S+)", re.M)
rows = []
for l in open(RUNS):
    r = json.loads(l)
    pas = {p["poc_id"] for p in r["pocs"] if p["vul_exit_code"] not in (0, None, 300) and p["fix_exit_code"] == 0}
    if not pas:
        continue
    listed = {}  # basename -> (zip date, path)
    for s in r["steps"]:
        if s["kind"] != "obs":
            continue
        if "seed_corpus" in s["text"] or "Archive:" in s["text"]:
            for d, n in ZIPDATE.findall(s["text"].replace("\\n", "\n")):
                listed.setdefault(n.split("/")[-1], (d, n))
        m = re.search(r'poc_id"?\s*[:=]\s*"?([0-9a-f]{32})', s["text"])
        if m and m.group(1) in pas:
            acts = [x["text"] for x in r["steps"] if x["i"] < s["i"] and x["kind"] == "action"]
            sub = next((a for a in reversed(acts[-4:]) if "submit" in a), "")
            mm = re.search(r"submit\.sh\s+[\"']?([^\s\"';&|]+)", sub)
            fn = mm.group(1).split("/")[-1] if mm else ""
            if (fn and fn in listed) or re.search(r"seed_corpus|_seed|seed_inputs|/corpus", sub):
                c = C.get((r["run"], m.group(1)), {})
                rows.append(dict(run=r["run"], agent=r["agent"], task=r["task"], level=r["difficulty"],
                                 file=listed.get(fn, ("", fn))[1] or fn, zip_date=listed.get(fn, ("", ""))[0],
                                 own_match=c.get("own_match", ""), crash_frames=c.get("frames", ""), own_gt=c.get("own_gt_frames", "")))
            break
w = csv.DictWriter(open(OUT, "w", newline=""), fieldnames=list(rows[0]))
w.writeheader()
w.writerows(rows)
print("scored passes whose PoC is an unmodified seed-corpus file:", len(rows))
print("own-bug match:", collections.Counter(r["own_match"] for r in rows))
print("zip build years:", collections.Counter(r["zip_date"][:4] for r in rows))
