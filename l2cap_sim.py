# l2cap_sim.py
from enum import Enum, auto
from packet import L2CAPFrame  # OK: only l2cap_sim imports packet, not the other way

class State(Enum):
    DISCONNECTED = auto()
    CONNECTING = auto()
    CONFIGURING = auto()
    OPEN = auto()
    CLOSING = auto()

# Opcodes (1 byte)
CR = 0x01  # ConnectReq
CP = 0x02  # ConnectRsp
FR = 0x03  # ConfigReq
FP = 0x04  # ConfigRsp
DT = 0x05  # Data
DC = 0x06  # Disconnect

class Anomaly(Exception):
    pass

class L2CAPSimulator:
    """Tiny L2CAP signaling simulator with invariants and simple replies."""
    def __init__(self):
        self.reset()

    def reset(self):
        self.state = State.DISCONNECTED
        self.cid = 0x0040          # arbitrary channel id
        self.config_ok = False
        self.bytes_seen = 0
        self.transitions = set()   # (from, to)

    def _resp(self, opcode: int, payload: bytes) -> L2CAPFrame:
        pl = bytes([opcode]) + payload
        return L2CAPFrame(length=len(pl), cid=self.cid, payload=pl)

    def handle(self, frame: L2CAPFrame) -> L2CAPFrame:
        # Invariants
        if frame.cid != self.cid and self.state != State.DISCONNECTED:
            raise Anomaly(f"Unexpected CID {frame.cid:04x} in {self.state.name}, expected {self.cid:04x}")
        if len(frame.payload) == 0:
            raise Anomaly("Empty payload not allowed")

        opcode = frame.payload[0]
        s0 = self.state

        if self.state == State.DISCONNECTED:
            if opcode == CR:
                if frame.length < 2:  # minimal PSM in this toy model
                    raise Anomaly("ConnectReq too short")
                self.state = State.CONNECTING
                resp = self._resp(CP, b"\x00\x00")  # OK
            else:
                raise Anomaly("Must start with ConnectReq from DISCONNECTED")

        elif self.state == State.CONNECTING:
            if opcode == CP:
                if frame.length != 3:    # opcode + 2 status bytes
                    raise Anomaly("ConnectRsp wrong length")
                status = frame.payload[1:3]
                if status != b"\x00\x00":
                    raise Anomaly("ConnectRsp not OK")
                self.state = State.CONFIGURING
                resp = self._resp(FR, b"\x01\x00")  # request one option
            else:
                raise Anomaly("Expected ConnectRsp in CONNECTING")

        elif self.state == State.CONFIGURING:
            if opcode == FR:
                # FR: [opcode, opt_type(1), opt_len(1), opt_value...]
                if frame.length < 3:
                    raise Anomaly("ConfigReq too short")
                opt_len = frame.payload[2]
                if 3 + opt_len != frame.length:
                    raise Anomaly("ConfigReq option length mismatch")
                self.config_ok = True
                self.state = State.OPEN
                resp = self._resp(FP, b"\x00")    # OK
            elif opcode == FP:
                if frame.length != 2:
                    raise Anomaly("ConfigRsp wrong length")
                self.config_ok = True
                self.state = State.OPEN
                resp = self._resp(FP, b"\x00")
            else:
                raise Anomaly("Expected ConfigReq/ConfigRsp in CONFIGURING")

        elif self.state == State.OPEN:
            if opcode == DT:
                if frame.length < 2:  # opcode + >=1 byte data
                    raise Anomaly("Data too short")
                self.bytes_seen += frame.length - 1
                resp = self._resp(DT, b"\x00")    # ack
            elif opcode == DC:
                self.state = State.CLOSING
                resp = self._resp(DC, b"\x00")
            else:
                raise Anomaly("Only Data or Disconnect allowed when OPEN")

        elif self.state == State.CLOSING:
            if opcode == DC:
                self.state = State.DISCONNECTED
                resp = self._resp(DC, b"\x00")
            else:
                raise Anomaly("Expected Disconnect in CLOSING")

        else:
            raise Anomaly("Unknown state")

        self.transitions.add((s0.name, self.state.name))
        return resp
