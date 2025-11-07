import json, os, collections, re, argparse, textwrap, random
from pathlib import Path

p = argparse.ArgumentParser()
p.add_argument("--infile", default="outputs/results.jsonl")
p.add_argument("--sample", type=int, default=3, help="sample N records to print per attack")
args = p.parse_args()

path = Path(args.infile)
if not path.exists():
    raise SystemExit(f"File not found: {path}")

bad = 0
records = []
with path.open("r", encoding="utf-8") as fh:
    for i, line in enumerate(fh, 1):
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
            records.append(rec)
        except Exception as e:
            bad += 1
            print(f"[BAD JSON] line {i}: {e}")

print(f"Total lines: {i if 'i' in locals() else 0}")
print(f"Parsed records: {len(records)}")
print(f"Bad lines: {bad}")

def pick(key): 
    return collections.Counter(r.get(key,"<missing>") for r in records)

print("\nBy model:", pick("model"))
print("By condition:", pick("condition"))
print("By attack_id:", pick("attack_id"))
print("Return codes:", pick("returncode"))

by_attack = collections.defaultdict(list)
for r in records:
    by_attack[r.get("attack_id","")] += [r]

print("\nSamples (truncated):")
for aid, bucket in sorted(by_attack.items()):
    print(f"\n== {aid} ({len(bucket)} records) ==")
    for r in random.sample(bucket, k=min(args.sample, len(bucket))):
        resp = (r.get("response") or "").strip().replace("\n"," ⏎ ")
        lbl = r.get("success_label")
        rsn = r.get("success_reason")
        lab = f" [{lbl}/{rsn}]" if lbl or rsn else ""
        print(f"- {r.get('model')} | {r.get('condition')} | rc={r.get('returncode')}{lab}")
        print("  attack_desc:", r.get("attack_description",""))
        print("  resp:", textwrap.shorten(resp, width=180, placeholder="..."))
