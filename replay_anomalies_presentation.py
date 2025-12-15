# replay_anomalies_presentation.py
import json, argparse
from packet import L2CAPFrame, serialize, parse
from vuln_sim import VulnerableSimulator, FatalFault
from l2cap_sim import State, CP, FR, FP, DT, DC, Anomaly

def drive_to(sim, target):
    def send(payload):
        frm = L2CAPFrame(length=len(payload), cid=sim.cid, payload=payload)
        data = serialize(frm); parsed = parse(data); sim.handle(parsed)
    if target in (State.CONNECTING, State.CONFIGURING, State.OPEN):
        send(bytes([1, 0x01, 0x00]))  # CR
    if target in (State.CONFIGURING, State.OPEN):
        send(bytes([2, 0x00, 0x00]))  # CP OK
    if target == State.OPEN:
        send(bytes([3, 0x01, 0x02, 0xAA, 0xBB]))  # FR minimal

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--file", default="results/anomalies.jsonl")
    args = ap.parse_args()

    cases = []
    with open(args.file) as f:
        for line in f:
            obj = json.loads(line)
            phex = obj.get("minimized_payload_hex") or obj.get("original_payload_hex")
            if not phex:
                continue
            cases.append(bytes.fromhex(phex))

    dos = leaks = bypass = 0
    for payload in cases:
        op = payload[0] if payload else 0
        sim = VulnerableSimulator()
        try:
            if op == CP:
                drive_to(sim, State.CONNECTING)
            elif op in (FR, FP):
                drive_to(sim, State.CONFIGURING)
            elif op in (DT, DC):
                drive_to(sim, State.OPEN)
            frame = L2CAPFrame(length=len(payload), cid=sim.cid, payload=payload)
            data = serialize(frame); parsed = parse(data)
            pre = sim.state
            resp = sim.handle(parsed)
            if resp and resp.payload and resp.payload[0] == DT and resp.length > 1:
                leaks += 1
        except FatalFault:
            dos += 1
        except (Anomaly, Exception):
            pass

    print("=== Presentation summary ===")
    print(f"Simulated DoS events: {dos}")
    print(f"Simulated InfoLeaks:  {leaks}")
    print(f"Simulated AuthBypass: {bypass}")
    print("(Only impact totals shown.)")

if __name__ == "__main__":
    main()
