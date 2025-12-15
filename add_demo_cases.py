# add_demo_cases.py
import json, os

out = "results/anomalies.jsonl"
os.makedirs("results", exist_ok=True)

cases = [
  # A) CONFIG DoS: huge FR (length > 64) → FatalFault in VulnerableSimulator
  {
    "reason": "demo: oversize FR causes DoS",
    "minimized_payload_hex": (b"\x03" + b"\x01" + bytes([70]) + b"\xAA"*70).hex()
  },
  # B) InfoLeak: DT with zero data in OPEN → simulator responds DT + 4 secret bytes
  {
    "reason": "demo: DT zero-length leaks bytes",
    "minimized_payload_hex": (b"\x05").hex()
  },
  # C) AuthBypass: CP status == 0x13 0x37 in CONNECTING → jump to OPEN
  {
    "reason": "demo: CP 0x1337 triggers bypass",
    "minimized_payload_hex": (b"\x02" + b"\x13\x37").hex()
  }
]

with open(out, "a") as f:
    for c in cases:
        f.write(json.dumps(c) + "\n")

print(f"Appended {len(cases)} demo cases to {out}")
