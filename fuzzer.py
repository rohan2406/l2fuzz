import json, random, traceback
from typing import Dict, Any
from packet import L2CAPFrame, serialize, parse
from l2cap_sim import L2CAPSimulator, State, CR, CP, FR, FP, DT, DC, Anomaly
from mutation import mutate_payload_core, mutate_length_consistent

def build_valid_frame(state: State, cid: int) -> L2CAPFrame:
    if state == State.DISCONNECTED:
        payload = bytes([CR, 0x01, 0x00])                 # ConnectReq
    elif state == State.CONNECTING:
        payload = bytes([CP, 0x00, 0x00])                 # ConnectRsp OK
    elif state == State.CONFIGURING:
        if random.random() < 0.5:
            opt_value = bytes([0xAA, 0xBB])               # 2-byte option value
            payload = bytes([FR, 0x01, len(opt_value)]) + opt_value
        else:
            payload = bytes([FP, 0x00])                   # ConfigRsp OK
    elif state == State.OPEN:
        if random.random() < 0.25:
            payload = bytes([DC, 0x00])                   # Disconnect
        else:
            payload = bytes([DT, 0x42, 0x42])             # Data
    elif state == State.CLOSING:
        payload = bytes([DC, 0x00])                       # Disconnect
    else:
        payload = bytes([DC, 0x00])
    return L2CAPFrame(length=len(payload), cid=cid, payload=payload)

def minimize_bytes(b: bytes, test_fn):
    data = bytearray(b)
    changed = True
    while changed and len(data) > 1:
        changed = False
        for i in range(1, len(data)):
            trial = data[:i] + data[i+1:]
            try:
                if test_fn(bytes(trial)):
                    data = bytearray(trial)
                    changed = True
                    break
            except Exception:
                pass
    return bytes(data)

class StatefulFuzzer:
    def __init__(self, seed: int = 1337):
        random.seed(seed)
        self.sim = L2CAPSimulator()
        self.stats = {
            "trials": 0, "accepted": 0, "rejected": 0, "anomalies": 0,
            "visited_states": set(), "visited_transitions": set(),
        }
        self.anomalies = []

    def run_trial(self):
        st = self.sim.state
        base = build_valid_frame(st, self.sim.cid)

        if st in (State.DISCONNECTED, State.CONNECTING, State.CONFIGURING) and random.random() < 0.25:
            mutated_payload = base.payload
        else:
            mutated_payload = mutate_payload_core(base.payload)

        new_len = mutate_length_consistent(base.length, mutated_payload)
        frame = L2CAPFrame(length=new_len, cid=base.cid, payload=mutated_payload)

        self.stats["trials"] += 1
        try:
            data = serialize(frame)
            parsed = parse(data)

            self.stats["accepted"] += 1
            _ = self.sim.handle(parsed)

            self.stats["visited_states"].add(self.sim.state.name)
            for tr in list(self.sim.transitions):
                self.stats["visited_transitions"].add(f"{tr[0]}->{tr[1]}")
            return True
        except Anomaly as e:
            self.stats["anomalies"] += 1
            self._record_anomaly(frame, f"Anomaly: {str(e)}")
            return False
        except Exception as e:
            self.stats["rejected"] += 1
            self._record_anomaly(frame, f"Parser/Runtime error: {str(e)}")
            return False

    def _record_anomaly(self, frame, reason: str):
        def test_fn(min_payload: bytes):
            try:
                test_frame = L2CAPFrame(length=len(min_payload), cid=frame.cid, payload=min_payload)
                data = serialize(test_frame)
                parsed = parse(data)
                sim = L2CAPSimulator()
                sim.handle(parsed)
                return False
            except Exception:
                return True
        minimized = minimize_bytes(frame.payload, test_fn)
        self.anomalies.append({
            "reason": reason,
            "state_at_input": self.sim.state.name,
            "original_payload_hex": frame.payload.hex(),
            "minimized_payload_hex": minimized.hex(),
            "cid": frame.cid,
            "length": frame.length,
        })

    def summary(self) -> Dict[str, Any]:
        return {
            "trials": self.stats["trials"],
            "accepted": self.stats["accepted"],
            "rejected": self.stats["rejected"],
            "anomalies": self.stats["anomalies"],
            "visited_states": sorted(self.stats["visited_states"]),
            "visited_transitions": sorted(self.stats["visited_transitions"]),
        }
