"""String decoders for the ai.your.tundra payload (EVANGELION family).

Each malware class carries its own base64 + XOR transform. These are faithful
ports of the smali logic, used to recover plaintext IOC and API strings from a
decompiled tree.
"""
import base64

def _s(v: int) -> int:
    v &= 0xFF
    return v - 256 if v > 127 else v


def _make(key, reverse, transform):
    def decode(data: str) -> str:
        raw = bytearray(base64.b64decode(data))
        n = len(key)
        for i in (range(len(raw) - 1, -1, -1) if reverse else range(len(raw))):
            raw[i] ^= transform(_s(key[i % n])) & 0xFF
        return raw.decode("utf-8", "replace")
    return decode


# umnex601.YagraQe29
calar = _make(
    [-127, 4, -58, -77, 117, 22, 18, -34, -121, -38, 94, 45, -22, 120],
    False,
    lambda k: 17 - ((-43) - (37 - (18 - (k ^ 69)))),
)

# g143mu.arcalk2.Calronoa
vexar = _make(
    [-55, -77, 97, -48, -82, -96, -40, 87, -31, -32, 76, -28, -46, 11],
    True,
    lambda k: (-78) - ((-69) - (((-24) - (((k + 99) - 87) - 5)) + 18)),
)

# fatri3.Inmiteho3jqu
inm = _make(
    [47, 45, 121, -51, 0, 110, 80, -95, 43, 31, -23, -71, -1, 78, 67, -56],
    True,
    lambda k: (7 - ((((k ^ -96) ^ -51) ^ -34) - 38)) ^ 54,
)

# xg9r5jt4.PedielpiKQR
ped = _make(
    [-120, -54, 13, 127, 68, -68, -126, 112, 115],
    False,
    lambda k: ((k ^ 121) ^ 26) - 45,
)

# grayaa.kanex.arfaorkae0.GraBer40
gra = _make(
    [-70, -22, -16, 13, 59, -126, 65, -47, 81, 122, -122, 74, 95, 42, 66, 115],
    False,
    lambda k: ((((-41) - ((k ^ -26) + 15)) + 2) ^ 6 ^ 59) - 116,
)

# plolu5.Calarxpexuca
cpx = _make(
    [-82, -102, 16, -127, -23, -119, -86, 6, -36, 7, -121, 72, 34, -59, 75, -98],
    False,
    lambda k: ((((((k ^ 36) ^ -122) + 127) ^ 115) + 120) ^ 7) - 39,
)

DECODERS = {"calar": calar, "vexar": vexar, "inm": inm, "ped": ped, "gra": gra, "cpx": cpx}


if __name__ == "__main__":
    import sys
    fn = DECODERS[sys.argv[2]]
    print(fn(sys.argv[1]))
