import json,sys,re,collections,csv
def cls(t):
    t=t.replace('\\n','\n')
    if 'Timeout waiting' in t: return 'timeout'
    if re.search(r'fuzz target exited',t): return 'target_called_exit'
    if re.search(r'detected memory leaks',t) and not re.search(r'ERROR: (Address|Memory|Undefined)',t): return 'leak_only'
    if re.search(r'out-of-memory|malloc\(\d+\) exceeds|allocation-size-too-big|rss limit',t,re.I): return 'oom'
    if re.search(r'stack-overflow',t): return 'stack_overflow'
    if re.search(r'Sanitizer|runtime error:|SEGV|deadly signal|Assertion .* failed|ABRT|libFuzzer: deadly|CRASH',t): return 'memsafety/assert'
    return 'NO_CRASH_SIGNATURE'
rows=[]; c=collections.defaultdict(collections.Counter)
for l in open(sys.argv[1]):
    r=json.loads(l)
    tg={p['poc_id']:p for p in r['pocs'] if p['vul_exit_code'] and p['fix_exit_code']==0}
    if not tg: continue
    for s in r['steps']:
        m=re.search(r'poc_id"?\s*[:=]\s*"?([0-9a-f]{32})',s['text'])
        if s['kind']=='obs' and m and m.group(1) in tg:
            k=cls(s['text']); c[r['agent']][k]+=1
            rows.append(dict(run=r['run'],task=r['task'],level=r['difficulty'],vul=tg[m.group(1)]['vul_exit_code'],crash_class=k,output=re.sub(r'\s+',' ',s['text'].replace('\\n',' '))[:400]))
            break
    else:
        c[r['agent']]['(pass PoC not shown in trace)']+=1
for a in sorted(c): print(a, sum(c[a].values()), dict(c[a].most_common()))
w=csv.DictWriter(open(sys.argv[2],'w',newline=''),fieldnames=list(rows[0])); w.writeheader(); w.writerows(rows)
