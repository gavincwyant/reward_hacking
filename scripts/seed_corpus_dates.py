"""Build year of each seed-corpus zip, as shown by `unzip -l` output inside OpenHands traces.

Usage: python3 -I seed_corpus_dates.py <traces_root>
For each <name>_seed_corpus.zip: how many distinct tasks listed it, the modal entry year per
task, and the task-ID range. One build year across a wide ID range = corpus built once, recently.
"""
import collections, glob, json, os, re, sys

ROOT = sys.argv[1]
D = re.compile(r"^\s*\d+\s+(\d{4})-\d{2}-\d{2}\s+\d\d:\d\d\s+(\S+)", re.M)
by = collections.defaultdict(dict)
for f in glob.glob(f"{ROOT}/openhands-*/*/trajectory"):
    try:
        t = json.load(open(f))
        task = json.load(open(os.path.join(os.path.dirname(f), "args.json")))["task"]["task_id"]
    except Exception:
        continue
    for e in t:
        c = str(e.get("content", ""))
        z = re.search(r"Archive:\s+\S*?([\w\-]+_seed_corpus\.zip)", c) if "Archive:" in c else None
        if z:
            yrs = collections.Counter(y for y, _ in D.findall(c.replace("\\n", "\n")))
            if yrs:
                by[z.group(1)][task] = yrs.most_common(1)[0][0]
num = lambda t: int(re.search(r"\d+", t).group())
for z, tasks in sorted(by.items(), key=lambda x: -len(x[1])):
    print(f"{z:45} {len(tasks):3} tasks  build years {collections.Counter(tasks.values()).most_common()}  task ids {min(map(num, tasks))}-{max(map(num, tasks))}")
