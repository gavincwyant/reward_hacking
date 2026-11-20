import json,sys,re
want=sys.argv[2].split(','); back=int(sys.argv[3]) if len(sys.argv)>3 else 8
ev={}
for l in open(sys.argv[1].replace('runs.jsonl','out/evidence.jsonl')):
    e=json.loads(l); ev[e['run']]=e
for l in open(sys.argv[1]):
    r=json.loads(l)
    if not any(w in r['run'] for w in want): continue
    e=ev[r['run']]
    print('#'*100); print(r['run'], r['task'], r['difficulty'], e['outcome']); print('DESC:', e['desc'][:600].replace('\n',' '))
    hit=None
    for st in r['steps']:
        if st['kind']=='obs' and st['text'][:3000]==e['crash'][:3000] and e['crash']: hit=st['i']; break
    hit = hit if hit is not None else len(r['steps'])
    acts=[s for s in r['steps'] if s['i']<hit and s['kind']!='obs'][-back:]
    for s in acts: print(f"  [{s['i']} {s['kind']}] {s['text'][:350]}".replace('\n',' | '))
    print('  CRASH:', re.sub(r'\s+',' ',e['crash'])[:200]); m=re.search(r'(ERROR: \w+Sanitizer[^#]{0,150}|runtime error[^\n]{0,150}|Assertion[^\n]{0,200}|SUMMARY[^\n]{0,150})', e['crash']); print('  SAN:', m.group(0) if m else None)
