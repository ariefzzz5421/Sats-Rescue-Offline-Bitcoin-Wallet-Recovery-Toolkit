#!/usr/bin/env python3
"""
Offline helper for a single Bitcoin private key.

Run this on your own machine. Do not paste private keys or seed phrases into chat.
The script uses no network and stores nothing.
"""

from __future__ import annotations

import argparse
import getpass
import hashlib
import json
import re
import sys
from typing import Dict, Iterable, List, Optional, Tuple


BASE58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
BECH32 = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
G = (GX, GY)
Point = Optional[Tuple[int, int]]


class KeyErrorValue(Exception):
    pass


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def hash160(data: bytes) -> bytes:
    try:
        ripe = hashlib.new("ripemd160")
    except ValueError as exc:
        raise RuntimeError("Python/OpenSSL ini tidak menyediakan RIPEMD160.") from exc
    ripe.update(sha256(data))
    return ripe.digest()


def b58encode(raw: bytes) -> str:
    n = int.from_bytes(raw, "big")
    out = ""
    while n:
        n, rem = divmod(n, 58)
        out = BASE58[rem] + out
    pad = 0
    for byte in raw:
        if byte == 0:
            pad += 1
        else:
            break
    return "1" * pad + (out or "")


def b58decode(text: str) -> bytes:
    n = 0
    for char in text:
        if char not in BASE58:
            raise KeyErrorValue(f"Karakter '{char}' bukan Base58 valid.")
        n = n * 58 + BASE58.index(char)
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    pad = len(text) - len(text.lstrip("1"))
    return b"\x00" * pad + raw


def b58check_encode(payload: bytes) -> str:
    checksum = sha256(sha256(payload))[:4]
    return b58encode(payload + checksum)


def b58check_decode(text: str) -> bytes:
    raw = b58decode(text)
    if len(raw) < 5:
        raise KeyErrorValue("Base58 terlalu pendek untuk checksum.")
    payload, checksum = raw[:-4], raw[-4:]
    expected = sha256(sha256(payload))[:4]
    if checksum != expected:
        raise KeyErrorValue("Checksum WIF/Base58Check tidak cocok.")
    return payload


def inverse_mod(k: int, p: int = P) -> int:
    return pow(k, -1, p)


def point_add(a: Point, b: Point) -> Point:
    if a is None:
        return b
    if b is None:
        return a

    ax, ay = a
    bx, by = b
    if ax == bx and (ay + by) % P == 0:
        return None

    if a == b:
        slope = (3 * ax * ax) * inverse_mod(2 * ay, P) % P
    else:
        slope = (by - ay) * inverse_mod(bx - ax, P) % P

    x = (slope * slope - ax - bx) % P
    y = (slope * (ax - x) - ay) % P
    return x, y


def point_mul(k: int, point: Point = G) -> Point:
    if k % N == 0 or point is None:
        return None
    result: Point = None
    addend = point
    while k:
        if k & 1:
            result = point_add(result, addend)
        addend = point_add(addend, addend)
        k >>= 1
    return result


def point_neg(point: Tuple[int, int]) -> Tuple[int, int]:
    x, y = point
    return x, (-y) % P


def pubkeys(secret: int) -> Tuple[bytes, bytes, Tuple[int, int]]:
    point = point_mul(secret)
    if point is None:
        raise KeyErrorValue("Private key berada di luar range secp256k1.")
    x, y = point
    xb = x.to_bytes(32, "big")
    yb = y.to_bytes(32, "big")
    compressed = (b"\x02" if y % 2 == 0 else b"\x03") + xb
    uncompressed = b"\x04" + xb + yb
    return compressed, uncompressed, point


def wif_encode(secret: int, network: str, compressed: bool) -> str:
    prefix = b"\x80" if network == "mainnet" else b"\xef"
    payload = prefix + secret.to_bytes(32, "big") + (b"\x01" if compressed else b"")
    return b58check_encode(payload)


def p2pkh(pubkey: bytes, network: str) -> str:
    version = b"\x00" if network == "mainnet" else b"\x6f"
    return b58check_encode(version + hash160(pubkey))


def p2sh_p2wpkh(compressed_pubkey: bytes, network: str) -> str:
    redeem_script = b"\x00\x14" + hash160(compressed_pubkey)
    version = b"\x05" if network == "mainnet" else b"\xc4"
    return b58check_encode(version + hash160(redeem_script))


def bech32_polymod(values: Iterable[int]) -> int:
    generators = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    chk = 1
    for value in values:
        top = chk >> 25
        chk = (chk & 0x1FFFFFF) << 5 ^ value
        for i in range(5):
            if (top >> i) & 1:
                chk ^= generators[i]
    return chk


def bech32_hrp_expand(hrp: str) -> List[int]:
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]


def bech32_checksum(hrp: str, data: List[int], spec: str) -> List[int]:
    const = 1 if spec == "bech32" else 0x2BC830A3
    values = bech32_hrp_expand(hrp) + data
    polymod = bech32_polymod(values + [0, 0, 0, 0, 0, 0]) ^ const
    return [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]


def bech32_encode(hrp: str, data: List[int], spec: str) -> str:
    combined = data + bech32_checksum(hrp, data, spec)
    return hrp + "1" + "".join(BECH32[d] for d in combined)


def convertbits(data: bytes, from_bits: int, to_bits: int, pad: bool = True) -> List[int]:
    acc = 0
    bits = 0
    ret: List[int] = []
    maxv = (1 << to_bits) - 1
    max_acc = (1 << (from_bits + to_bits - 1)) - 1
    for value in data:
        if value < 0 or value >> from_bits:
            raise KeyErrorValue("Nilai data bech32 tidak valid.")
        acc = ((acc << from_bits) | value) & max_acc
        bits += from_bits
        while bits >= to_bits:
            bits -= to_bits
            ret.append((acc >> bits) & maxv)
    if pad:
        if bits:
            ret.append((acc << (to_bits - bits)) & maxv)
    elif bits >= from_bits or ((acc << (to_bits - bits)) & maxv):
        raise KeyErrorValue("Konversi bit bech32 gagal.")
    return ret


def segwit_address(witness_version: int, witness_program: bytes, network: str) -> str:
    hrp = "bc" if network == "mainnet" else "tb"
    spec = "bech32" if witness_version == 0 else "bech32m"
    data = [witness_version] + convertbits(witness_program, 8, 5, True)
    return bech32_encode(hrp, data, spec)


def tagged_hash(tag: str, data: bytes) -> bytes:
    tag_hash = sha256(tag.encode("ascii"))
    return sha256(tag_hash + tag_hash + data)


def taproot_bip86_address(point: Tuple[int, int], network: str) -> str:
    internal = point if point[1] % 2 == 0 else point_neg(point)
    x_only = internal[0].to_bytes(32, "big")
    tweak = int.from_bytes(tagged_hash("TapTweak", x_only), "big") % N
    tweaked = point_add(internal, point_mul(tweak))
    if tweaked is None:
        raise KeyErrorValue("Taproot tweak menghasilkan point invalid.")
    return segwit_address(1, tweaked[0].to_bytes(32, "big"), network)


def clean_input(text: str) -> str:
    cleaned = text.strip()
    if ":" in cleaned:
        prefix, rest = cleaned.split(":", 1)
        if prefix.strip().lower() in {"p2pkh", "p2wpkh", "p2wpkh-p2sh"}:
            cleaned = rest
    cleaned = "".join(cleaned.split())
    if cleaned.lower().startswith("0x"):
        cleaned = cleaned[2:]
    return cleaned


def parse_secret(text: str) -> Dict[str, object]:
    cleaned = clean_input(text)
    if not cleaned:
        raise KeyErrorValue("Input kosong.")

    if re.fullmatch(r"[0-9a-fA-F]{64}", cleaned):
        secret = int(cleaned, 16)
        source = "raw_hex_64"
        network = None
        compressed = None
    elif cleaned.lower().startswith(("xprv", "yprv", "zprv")):
        raise KeyErrorValue("Ini extended private key HD wallet, bukan single private key. Perlu restore sebagai HD wallet dengan derivation path.")
    elif " " in text.strip() and len(text.strip().split()) in {12, 15, 18, 21, 24}:
        raise KeyErrorValue("Ini terlihat seperti seed phrase. Jangan pakai tool ini; restore sebagai BIP39 seed di wallet yang benar.")
    else:
        payload = b58check_decode(cleaned)
        if len(payload) == 33 and payload[0] in {0x80, 0xEF}:
            source = "wif_uncompressed"
            network = "mainnet" if payload[0] == 0x80 else "testnet"
            compressed = False
            secret = int.from_bytes(payload[1:], "big")
        elif len(payload) == 34 and payload[0] in {0x80, 0xEF} and payload[-1] == 0x01:
            source = "wif_compressed"
            network = "mainnet" if payload[0] == 0x80 else "testnet"
            compressed = True
            secret = int.from_bytes(payload[1:-1], "big")
        else:
            raise KeyErrorValue("WIF/Base58Check valid, tapi payload-nya bukan private key BTC standar.")

    if not (1 <= secret < N):
        raise KeyErrorValue("Angka private key tidak berada dalam range valid secp256k1.")

    return {
        "source_format": source,
        "network_from_input": network,
        "compressed_from_input": compressed,
        "secret": secret,
    }


def build_data(secret: int, network: str, show_private: bool) -> Dict[str, object]:
    compressed_pub, uncompressed_pub, point = pubkeys(secret)
    addresses = {
        "legacy_p2pkh_compressed_pubkey": p2pkh(compressed_pub, network),
        "legacy_p2pkh_uncompressed_pubkey": p2pkh(uncompressed_pub, network),
        "nested_segwit_p2sh_p2wpkh": p2sh_p2wpkh(compressed_pub, network),
        "native_segwit_p2wpkh": segwit_address(0, hash160(compressed_pub), network),
        "taproot_bip86_p2tr": taproot_bip86_address(point, network),
    }

    data: Dict[str, object] = {
        "network_for_output": network,
        "public_key_compressed": compressed_pub.hex(),
        "public_key_uncompressed": uncompressed_pub.hex(),
        "addresses": addresses,
    }

    if show_private:
        wif_compressed = wif_encode(secret, network, True)
        wif_uncompressed = wif_encode(secret, network, False)
        data["private_material"] = {
            "raw_hex": secret.to_bytes(32, "big").hex(),
            "wif_compressed": wif_compressed,
            "wif_uncompressed": wif_uncompressed,
            "electrum_sweep_native_segwit": f"p2wpkh:{wif_compressed}",
            "electrum_sweep_nested_segwit": f"p2wpkh-p2sh:{wif_compressed}",
            "electrum_sweep_legacy_compressed": wif_compressed,
            "electrum_sweep_legacy_uncompressed": wif_uncompressed,
        }
    return data


def print_human(parsed: Dict[str, object], data: Dict[str, object], expected: Optional[str]) -> None:
    print("\n=== HASIL CEK KEY BTC OFFLINE ===")
    print(f"Format input        : {parsed['source_format']}")
    print(f"Network dari input  : {parsed['network_from_input'] or 'tidak ada di raw hex'}")
    print(f"Compressed flag     : {parsed['compressed_from_input'] if parsed['compressed_from_input'] is not None else 'tidak ada di raw hex'}")
    print(f"Output network      : {data['network_for_output']}")
    print("\nPublic key:")
    print(f"- compressed   : {data['public_key_compressed']}")
    print(f"- uncompressed : {data['public_key_uncompressed']}")
    print("\nAlamat yang mungkin dari key ini:")
    for name, addr in data["addresses"].items():
        print(f"- {name}: {addr}")

    if "private_material" in data:
        print("\nPRIVATE MATERIAL - jangan screenshot / kirim ke siapa pun:")
        for name, value in data["private_material"].items():
            print(f"- {name}: {value}")
    else:
        print("\nPrivate material tidak ditampilkan. Tambah --show-private jika benar-benar perlu WIF untuk sweep.")

    if expected:
        matches = [name for name, addr in data["addresses"].items() if addr == expected]
        print("\nCocokkan dengan address target:")
        if matches:
            print(f"[MATCH] address cocok dengan {', '.join(matches)}")
        else:
            print("[NO MATCH] Tidak cocok dengan address target.")
            print("Kemungkinan: key salah, network salah, typo, atau address dibuat dari seed/derivation path lain.")


def main() -> int:
    parser = argparse.ArgumentParser(description="Offline BTC private key validator/converter.")
    parser.add_argument("--address", help="Address BTC publik yang ingin dicocokkan.")
    parser.add_argument("--network", choices=["mainnet", "testnet"], default="mainnet", help="Network output untuk raw hex. Default: mainnet.")
    parser.add_argument("--show-private", action="store_true", help="Tampilkan raw hex dan WIF. Gunakan hanya offline.")
    parser.add_argument("--json", action="store_true", help="Cetak output sebagai JSON.")
    args = parser.parse_args()

    if sys.stdin.isatty():
        print("Paste private key di bawah ini. Input disembunyikan.")
        secret_text = getpass.getpass("Private key / WIF / raw hex: ")
    else:
        secret_text = sys.stdin.read().strip()

    try:
        parsed = parse_secret(secret_text)
        network = parsed["network_from_input"] or args.network
        data = build_data(int(parsed["secret"]), str(network), args.show_private)
    except Exception as exc:
        print(f"\nERROR: {exc}", file=sys.stderr)
        return 1

    public_parsed = {k: v for k, v in parsed.items() if k != "secret"}
    if args.json:
        out = dict(public_parsed)
        out.update(data)
        if args.address:
            out["expected_address"] = args.address
            out["matches"] = [name for name, addr in data["addresses"].items() if addr == args.address]
        print(json.dumps(out, indent=2))
    else:
        print_human(public_parsed, data, args.address)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
