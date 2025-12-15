# vuln_sim.py (SIMULATION ONLY — educational)
from l2cap_sim import L2CAPSimulator, State, Anomaly, CR, CP, FR, FP, DT, DC
from packet import L2CAPFrame

class FatalFault(Exception):
    """Simulated crash (DoS)"""

class VulnerableSimulator(L2CAPSimulator):
    """
    Extends the clean simulator with DELIBERATE flaws to demonstrate impact:
    - DoS: certain malformed inputs simulate a crash (FatalFault).
    - InfoLeak: certain requests return bytes from an internal buffer.
    - AuthBypass: a rare sequence jumps to OPEN without proper config.
    """
    def __init__(self):
        super().__init__()
        self._secret = b"SIMULATED_DEVICE_KEY\x00\xA5\x5A"  # fake secret in memory

    def handle(self, frame: L2CAPFrame) -> L2CAPFrame:
        # 1) DoS in CONFIGURING if length > 64
        if self.state == State.CONFIGURING and frame.length > 64:
            print("[⚠️  Simulated DoS] Oversized Config frame caused crash (service restarted).")
            raise FatalFault("Simulated crash: oversized config frame")

        # 2) InfoLeak in OPEN if DT with opcode only (length==1)
        if self.state == State.OPEN and frame.payload and frame.payload[0] == DT and frame.length == 1:
            leak = self._secret[:4]
            print(f"[⚠️  Simulated Info Leak] Device leaked bytes: {leak.hex()}")
            return L2CAPFrame(length=1 + len(leak), cid=self.cid, payload=bytes([DT]) + leak)

        # 3) AuthBypass in CONNECTING if CP status == 0x13 0x37
        if self.state == State.CONNECTING and frame.payload and frame.payload[0] == CP and frame.length == 3:
            status = frame.payload[1:3]
            if status == b"\x13\x37":
                print("[⚠️  Simulated Auth Bypass] Connection jumped directly to OPEN (unauthorized).")
                self.state = State.OPEN
                return L2CAPFrame(length=1, cid=self.cid, payload=bytes([DT]))

        # Otherwise, fall back to normal logic (may still raise Anomaly)
        return super().handle(frame)
