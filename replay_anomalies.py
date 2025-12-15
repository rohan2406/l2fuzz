# replay_anomalies.py
import json, argparse
from packet import L2CAPFrame, serialize, parse
from vuln_sim import VulnerableSimulator, FatalFault
from l2cap_sim import State, CR, CP, FR, FP, DT, DC, Anomaly

def drive_to(sim: VulnerableSimulator, target: State):
    """Send a minimal sequence of valid frames to reach target state from DISCONNECTED."""
    def send(payload):
        frm = L2CAPFrame(length=len(payload), cid=sim.cid, payload=payload)
        data = serialize(frm); parsed = parse(data); sim.handle(parsed)

    # We assume sim starts in DISCONNECTED
    if target in (State.CONNECTING, State.CONFIGURING, State.OPEN):
        send(bytes([CR, 0x01, 0x00]))  # -> CONNECTING
    if target in (State.CONFIGURING, State.OPEN):
        send(bytes([CP, 0x00, 0x00]))  # -> CONFIGURING
    if target == State.OPEN:
        send(bytes([FR, 0x01, 0x02, 0xAA, 0xBB]))  # -> OPEN

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
            payload = bytes.fromhex(phex)
            cases.append((obj.get("reason",""), payload))

    dos = leaks = bypass = 0

    print("\n--- Replaying anomalies for demonstration ---\n")
    for idx, (reason, payload) in enumerate(cases):
        opcode = payload[0] if payload else 0
        print(f"Case {idx+1}: {reason} | Opcode: 0x{opcode:02x} | Length: {len(payload)}")

        # NEW: fresh simulator per case for clean, predictable state
        sim = VulnerableSimulator()

        try:
            # Stage to the right state for this opcode
            if opcode == CP:
                drive_to(sim, State.CONNECTING)
            elif opcode in (FR, FP):
                drive_to(sim, State.CONFIGURING)
            elif opcode in (DT, DC):
                drive_to(sim, State.OPEN)
            else:
                # For CR/unknown, just start from DISCONNECTED
                pass

            # Inject payload
            frame = L2CAPFrame(length=len(payload), cid=sim.cid, payload=payload)
            data = serialize(frame); parsed = parse(data)
            pre_state = sim.state
            resp = sim.handle(parsed)

            # Count info-leak responses (DT + extra bytes)
            if resp and resp.payload and resp.payload[0] == DT and resp.length > 1:
                leaks += 1

            # Count auth bypass (CONNECTING -> OPEN on CP 0x1337)
            if pre_state == State.CONNECTING and sim.state == State.OPEN and opcode == CP:
                bypass += 1

        except FatalFault:
            dos += 1
            print("→ [🔥 Simulated DoS] Device service crashed and restarted.\n")
        except Anomaly as e:
            print(f"→ [!] Protocol anomaly: {e}\n")
        except Exception as e:
            print(f"→ [x] Parser/runtime rejection: {e}\n")

    print("\n=== Simulated impact report ===")
    print(f"DoS (crash/restart) events: {dos}")
    print(f"InfoLeak responses:       {leaks}")
    print(f"AuthBypass events:        {bypass}   (demo rule triggers if CP status == 0x13 0x37)")
    print("NOTE: Pure simulation for educational purposes only.\n")

if __name__ == "__main__":
    main()
