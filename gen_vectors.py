import json, os, sys, random
sys.path.insert(0,'reference')
from scope_ref import root_of, make_non_inclusion, membership_siblings
def b32hex(i): return '0x'+i.to_bytes(32,'big').hex()
random.seed(123)
# declared asset_set as 6 coordinates (sorted)
vals = sorted(random.sample(range(1000, 9000), 6))
coords = [v*7 for v in vals]                 # leave gaps for interior nominations
coords_b = [c.to_bytes(32,'big') for c in coords]
root = root_of(coords_b)
count = len(coords_b)
commitment = (0xABCDEF<<8).to_bytes(32,'big')  # stand-in OCP commitmentHash

def proof_json(c_int):
    cb = c_int.to_bytes(32,'big')
    p = make_non_inclusion(coords_b, cb)
    if p is None: return None
    mode = p['case']
    lo = p.get('loCoord', b'\x00'*32); hi = p.get('hiCoord', b'\x00'*32)
    idxLo = p.get('idxLo', 0)
    sibsLo = ['0x'+s.hex() for s in p.get('sibsLo', [])]
    sibsHi = ['0x'+s.hex() for s in p.get('sibsHi', [])]
    return {'mode':mode,'loCoord':'0x'+lo.hex(),'hiCoord':'0x'+hi.hex(),
            'idxLo':idxLo,'sibsLo':sibsLo,'sibsHi':sibsHi}

absent_below = coords[0]-1
absent_interior = coords[0]+1   # gap after first
absent_above = coords[-1]+1
present = coords[3]

out = {
  'commitmentHash': '0x'+commitment.hex(),
  'scopeRoot': '0x'+root.hex(),
  'count': count,
  'absent': {
     'below':   {'coord': b32hex(absent_below),   'proof': proof_json(absent_below)},
     'interior':{'coord': b32hex(absent_interior),'proof': proof_json(absent_interior)},
     'above':   {'coord': b32hex(absent_above),   'proof': proof_json(absent_above)},
  },
  # present coord: build a (doomed) interior proof using real neighbors to prove it REVERTS
  'present': {'coord': b32hex(present),
              'proof': {'mode':0,
                        'loCoord': b32hex(coords[2]), 'hiCoord': b32hex(coords[4]),
                        'idxLo': 2,
                        'sibsLo': ['0x'+s.hex() for s in membership_siblings(coords_b,2)],
                        'sibsHi': ['0x'+s.hex() for s in membership_siblings(coords_b,4)]}}
}
json.dump(out, open('vectors.json','w'), indent=2)
print('wrote vectors.json  root=%s count=%d' % (out['scopeRoot'][:18], count))
