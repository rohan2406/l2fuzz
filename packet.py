# packet.py
from dataclasses import dataclass

@dataclass
class L2CAPFrame:
    length: int      # payload length (bytes)
    cid: int         # channel id
    payload: bytes   # first byte = opcode

def serialize(frame: L2CAPFrame) -> bytes:
    if frame.length != len(frame.payload):
        raise ValueError("length field must equal len(payload)")
    if frame.length < 0 or frame.length > 65535:
        raise ValueError("invalid length")
    return (
        frame.length.to_bytes(2, "little")
        + frame.cid.to_bytes(2, "little")
        + frame.payload
    )

def parse(data: bytes) -> L2CAPFrame:
    if len(data) < 4:
        raise ValueError("frame too short for header")
    length = int.from_bytes(data[0:2], "little")
    cid = int.from_bytes(data[2:4], "little")
    payload = data[4:4+length]
    if len(payload) != length:
        raise ValueError("declared length does not match payload bytes")
    return L2CAPFrame(length=length, cid=cid, payload=payload)
