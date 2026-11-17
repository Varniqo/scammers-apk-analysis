"""Recover the original second-stage APK from a preserved assets/ylx0 file."""

import argparse
import hashlib
from pathlib import Path

from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

KEY = b"TIwcHVIsbeO13zlm"


def unpack(source: Path, destination: Path) -> None:
    encrypted = source.read_bytes()
    xored = bytes(value ^ KEY[index % len(KEY)] for index, value in enumerate(encrypted))
    plaintext = unpad(AES.new(KEY, AES.MODE_ECB).decrypt(xored), AES.block_size)
    destination.write_bytes(plaintext)
    print(f"Wrote {len(plaintext)} bytes to {destination}")
    print(f"SHA-256: {hashlib.sha256(plaintext).hexdigest()}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path, help="Preserved encrypted ylx0 asset")
    parser.add_argument("destination", type=Path, help="Output APK path")
    args = parser.parse_args()
    unpack(args.source, args.destination)


if __name__ == "__main__":
    main()
