import random
# opcodes
CR, CP, FR, FP, DT, DC = 0x01, 0x02, 0x03, 0x04, 0x05, 0x06

def mutate_length_consistent(length: int, payload: bytes) -> int:
    # Keep declared length consistent 98% of the time
    if random.random() < 0.98:
        return len(payload)
    # Tiny mismatch 2% of the time to tickle parser edges
    delta = random.choice([-1, 1])
    return max(0, min(65535, len(payload) + delta))

def mutate_payload_core(payload: bytes) -> bytes:
    if len(payload) <= 1:
        return payload
    # Allow progress more often, but still explore
    if random.random() < 0.15:
        return payload

    opcode = payload[0]
    core = bytearray(payload[1:])

    # CP: keep status OK most runs so we reach CONFIGURING/OPEN
    if opcode == CP:
        if random.random() < 0.70:
            return bytes([opcode]) + bytes(core)
        # 30%: flip exactly one status byte (protocol anomaly chance)
        i = 0 if random.random() < 0.5 else 1
        core[i] = (core[i] + 1) % 256
        return bytes([opcode]) + bytes(core)

    # FR: prefer value flips; mismatch opt_len sometimes
    if opcode == FR and len(core) >= 2:
        opt_type = core[0]
        opt_len  = core[1]
        opt_val  = bytearray(core[2:2+opt_len])
        if len(opt_val) > 0:
            j = random.randrange(len(opt_val))
            opt_val[j] ^= 0x01  # minimal, structured mutation
        keep_len = random.random() < 0.70  # 30%: provoke length mismatch anomaly
        new_len = len(opt_val) if keep_len else (len(opt_val) ^ 1) & 0xFF
        core = bytearray([opt_type, new_len]) + opt_val
        return bytes([opcode]) + bytes(core)

    # OPEN state payloads (DT): ~20% chance to zero out data → "Data too short"
    if opcode == DT and len(core) > 0 and random.random() < 0.20:
        core = bytearray(b"")  # trigger simulator's "Data too short" path

    # default: flip one core byte
    k = random.randrange(len(core)) if len(core) > 0 else 0
    if len(core) > 0:
        core[k] ^= 0x01
    return bytes([opcode]) + bytes(core)
