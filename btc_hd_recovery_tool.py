#!/usr/bin/env python3
"""
Offline recovery helper for Bitcoin HD extended private keys.

Use this when your secret starts with xprv/yprv/zprv and the funded address is
one of its derived child addresses. The script uses no network and stores
nothing.
"""

from __future__ import annotations

import argparse
import getpass
import hashlib
import hmac
import json
import re
import sys
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from btc_key_recovery_tool import (
    N,
    b58check_decode,
    b58check_encode,
    hash160,
    p2pkh,
    p2sh_p2wpkh,
    pubkeys,
    segwit_address,
    taproot_bip86_address,
    wif_encode,
)


HARDENED = 0x80000000

VERSION_NAMES = {
    0x0488ADE4: ("xprv", "mainnet"),
    0x049D7878: ("yprv", "mainnet"),
    0x04B2430C: ("zprv", "mainnet"),
    0x0295B005: ("Yprv", "mainnet"),
    0x02AA7A99: ("Zprv", "mainnet"),
    0x04358394: ("tprv", "testnet"),
    0x044A4E28: ("uprv", "testnet"),
    0x045F18BC: ("vprv", "testnet"),
}


@dataclass(frozen=True)
class ExtPrivateKey:
    version: int
    depth: int
    parent_fingerprint: bytes
    child_number: int
    chain_code: bytes
    secret: int

    @property
    def prefix(self) -> str:
        return VERSION_NAMES.get(self.version, (f"0x{self.version:08x}", "unknown"))[0]

    @property
    def network(self) -> str:
        return VERSION_NAMES.get(self.version, ("unknown", "mainnet"))[1]


def parse_xprv(text: str) -> ExtPrivateKey:
    cleaned = "".join(text.strip().split())
    raw = b58check_decode(cleaned)
    if len(raw) != 78:
        raise ValueError(f"Extended key payload harus 78 byte, dapat {len(raw)} byte.")

    version = int.from_bytes(raw[0:4], "big")
    if version not in VERSION_NAMES:
        raise ValueError(f"Version extended key tidak dikenal: 0x{version:08x}.")

    depth = raw[4]
    parent_fingerprint = raw[5:9]
    child_number = int.from_bytes(raw[9:13], "big")
    chain_code = raw[13:45]
    key_data = raw[45:78]

    if key_data[0] != 0:
        raise ValueError("Ini extended public key, bukan extended private key. Public key tidak bisa mengambil BTC.")

    secret = int.from_bytes(key_data[1:], "big")
    if not (1 <= secret < N):
        raise ValueError("Private key di dalam extended key tidak valid.")

    return ExtPrivateKey(version, depth, parent_fingerprint, child_number, chain_code, secret)


def fingerprint(secret: int) -> bytes:
    compressed_pub, _, _ = pubkeys(secret)
    return hash160(compressed_pub)[:4]


def child_key(parent: ExtPrivateKey, index: int, compute_parent_fingerprint: bool = False) -> ExtPrivateKey:
    if index < 0 or index > 0xFFFFFFFF:
        raise ValueError("Index child di luar range.")

    if index >= HARDENED:
        data = b"\x00" + parent.secret.to_bytes(32, "big") + index.to_bytes(4, "big")
    else:
        compressed_pub, _, _ = pubkeys(parent.secret)
        data = compressed_pub + index.to_bytes(4, "big")

    digest = hmac.new(parent.chain_code, data, hashlib.sha512).digest()
    il = int.from_bytes(digest[:32], "big")
    ir = digest[32:]
    if il >= N:
        raise ValueError("Child derivation invalid: IL >= curve order.")

    secret = (il + parent.secret) % N
    if secret == 0:
        raise ValueError("Child derivation invalid: zero key.")

    return ExtPrivateKey(
        version=parent.version,
        depth=(parent.depth + 1) & 0xFF,
        parent_fingerprint=fingerprint(parent.secret) if compute_parent_fingerprint else b"\x00\x00\x00\x00",
        child_number=index,
        chain_code=ir,
        secret=secret,
    )


def parse_path(path: str) -> List[int]:
    normalized = path.strip()
    if normalized in {"", "m"}:
        return []
    if normalized.startswith("m/"):
        normalized = normalized[2:]

    indexes: List[int] = []
    for part in normalized.split("/"):
        hardened = part.endswith(("'", "h", "H"))
        number_text = part[:-1] if hardened else part
        if not re.fullmatch(r"\d+", number_text):
            raise ValueError(f"Path tidak valid di bagian: {part}")
        number = int(number_text)
        if number >= HARDENED:
            raise ValueError(f"Index terlalu besar: {part}")
        indexes.append(number + HARDENED if hardened else number)
    return indexes


def format_index(index: int) -> str:
    if index >= HARDENED:
        return f"{index - HARDENED}'"
    return str(index)


def format_path(indexes: Sequence[int]) -> str:
    return "m" if not indexes else "m/" + "/".join(format_index(i) for i in indexes)


def derive_path(root: ExtPrivateKey, indexes: Sequence[int]) -> ExtPrivateKey:
    node = root
    for index in indexes:
        node = child_key(node, index)
    return node


def child_key_quiet(parent: ExtPrivateKey, index: int) -> Optional[ExtPrivateKey]:
    try:
        return child_key(parent, index)
    except Exception:
        return None


def purpose_candidates(address: str) -> List[Tuple[str, List[int]]]:
    if address.startswith("bc1q") or address.startswith("tb1q"):
        return [("native_segwit_p2wpkh", [84 + HARDENED, 0 + HARDENED, 0 + HARDENED])]
    if address.startswith("3") or address.startswith("2"):
        return [("nested_segwit_p2sh_p2wpkh", [49 + HARDENED, 0 + HARDENED, 0 + HARDENED])]
    if address.startswith("1") or address.startswith(("m", "n")):
        return [("legacy_p2pkh_compressed_pubkey", [44 + HARDENED, 0 + HARDENED, 0 + HARDENED])]
    if address.startswith("bc1p") or address.startswith("tb1p"):
        return [("taproot_bip86_p2tr", [86 + HARDENED, 0 + HARDENED, 0 + HARDENED])]
    return [
        ("native_segwit_p2wpkh", [84 + HARDENED, 0 + HARDENED, 0 + HARDENED]),
        ("nested_segwit_p2sh_p2wpkh", [49 + HARDENED, 0 + HARDENED, 0 + HARDENED]),
        ("legacy_p2pkh_compressed_pubkey", [44 + HARDENED, 0 + HARDENED, 0 + HARDENED]),
        ("taproot_bip86_p2tr", [86 + HARDENED, 0 + HARDENED, 0 + HARDENED]),
    ]


def address_for(secret: int, script_type: str, network: str) -> str:
    compressed_pub, uncompressed_pub, point = pubkeys(secret)
    if script_type == "native_segwit_p2wpkh":
        return segwit_address(0, hash160(compressed_pub), network)
    if script_type == "nested_segwit_p2sh_p2wpkh":
        return p2sh_p2wpkh(compressed_pub, network)
    if script_type == "legacy_p2pkh_compressed_pubkey":
        return p2pkh(compressed_pub, network)
    if script_type == "legacy_p2pkh_uncompressed_pubkey":
        return p2pkh(uncompressed_pub, network)
    if script_type == "taproot_bip86_p2tr":
        return taproot_bip86_address(point, network)
    raise ValueError(f"Script type tidak dikenal: {script_type}")


def sweep_prefix(script_type: str) -> str:
    if script_type == "native_segwit_p2wpkh":
        return "p2wpkh:"
    if script_type == "nested_segwit_p2sh_p2wpkh":
        return "p2wpkh-p2sh:"
    return ""


def auto_search(root: ExtPrivateKey, target: str, limit: int) -> List[Dict[str, object]]:
    network = "testnet" if target.startswith(("tb1", "m", "n", "2")) else "mainnet"
    matches: List[Dict[str, object]] = []

    # If the extended key is likely account-level, try /change/index first.
    if root.depth >= 3:
        prefixes: List[List[int]] = [[], [0 + HARDENED], [84 + HARDENED, 0 + HARDENED, 0 + HARDENED]]
    else:
        prefixes = [[]] + [base for _, base in purpose_candidates(target)]

    seen = set()
    script_candidates = [name for name, _ in purpose_candidates(target)]
    if target.startswith("bc1q") or target.startswith("tb1q"):
        script_candidates = ["native_segwit_p2wpkh"]

    for script_type in script_candidates:
        try:
            address = address_for(root.secret, script_type, network)
        except Exception:
            continue
        if address == target:
            matches.append(
                {
                    "path": "m",
                    "script_type": script_type,
                    "network": network,
                    "change": None,
                    "index": None,
                    "secret": root.secret,
                }
            )

    for prefix in prefixes:
        key_prefix = tuple(prefix)
        if key_prefix in seen:
            continue
        seen.add(key_prefix)

        prefix_node = derive_path(root, prefix)
        for change in [0, 1]:
            change_node = child_key_quiet(prefix_node, change)
            if change_node is None:
                continue

            for index in range(limit):
                node = child_key_quiet(change_node, index)
                if node is None:
                    continue

                for script_type in script_candidates:
                    try:
                        address = address_for(node.secret, script_type, network)
                    except Exception:
                        continue
                    if address == target:
                        path_indexes = prefix + [change, index]
                        matches.append(
                            {
                                "path": format_path(path_indexes),
                                "script_type": script_type,
                                "network": network,
                                "change": change,
                                "index": index,
                                "secret": node.secret,
                            }
                        )
    return matches


def result_payload(root: ExtPrivateKey, match: Dict[str, object], show_private: bool) -> Dict[str, object]:
    secret = int(match["secret"])
    compressed_pub, uncompressed_pub, _ = pubkeys(secret)
    network = str(match["network"])
    script_type = str(match["script_type"])
    wif = wif_encode(secret, network, True)
    payload: Dict[str, object] = {
        "extended_key_prefix": root.prefix,
        "extended_key_depth": root.depth,
        "matched_path_relative_to_given_key": match["path"],
        "script_type": script_type,
        "network": network,
        "public_key_compressed": compressed_pub.hex(),
        "public_key_uncompressed": uncompressed_pub.hex(),
        "matched_address": address_for(secret, script_type, network),
    }
    if show_private:
        payload["private_material"] = {
            "child_private_key_wif_compressed": wif,
            "electrum_sweep_line": sweep_prefix(script_type) + wif,
        }
    return payload


def print_result(root: ExtPrivateKey, target: str, matches: List[Dict[str, object]], show_private: bool) -> None:
    print("\n=== HASIL CEK HD KEY BTC OFFLINE ===")
    print(f"Extended key prefix : {root.prefix}")
    print(f"Depth               : {root.depth}")
    print(f"Network key         : {root.network}")
    print(f"Target address      : {target}")

    if not matches:
        print("\n[NO MATCH] Belum menemukan child address yang cocok.")
        print("Coba naikkan limit dengan --limit 1000, atau masukkan path manual jika tahu derivation path dari bot.")
        return

    print(f"\n[MATCH] Ditemukan {len(matches)} child key yang cocok.")
    for i, match in enumerate(matches, start=1):
        payload = result_payload(root, match, show_private)
        print(f"\nMatch #{i}")
        print(f"- path relatif dari key yang kamu paste: {payload['matched_path_relative_to_given_key']}")
        print(f"- script type: {payload['script_type']}")
        print(f"- address: {payload['matched_address']}")
        print(f"- public key compressed: {payload['public_key_compressed']}")
        if show_private:
            material = payload["private_material"]
            print("\nPRIVATE MATERIAL - jangan screenshot / kirim ke siapa pun:")
            print(f"- child WIF compressed: {material['child_private_key_wif_compressed']}")
            print(f"- Electrum sweep line : {material['electrum_sweep_line']}")
        else:
            print("\nPrivate material disembunyikan. Tambah --show-private untuk melihat baris sweep Electrum.")


def main() -> int:
    parser = argparse.ArgumentParser(description="Offline BTC HD extended private key recovery helper.")
    parser.add_argument("--address", required=True, help="Public BTC address yang ada balance-nya.")
    parser.add_argument("--limit", type=int, default=200, help="Jumlah index address yang dicari per change chain. Default 200.")
    parser.add_argument("--path", help="Path manual relatif dari extended key yang dipaste, contoh: m/84'/0'/0'/0/0 atau m/0/0.")
    parser.add_argument("--script-type", choices=[
        "native_segwit_p2wpkh",
        "nested_segwit_p2sh_p2wpkh",
        "legacy_p2pkh_compressed_pubkey",
        "legacy_p2pkh_uncompressed_pubkey",
        "taproot_bip86_p2tr",
    ], help="Script type untuk --path manual.")
    parser.add_argument("--show-private", action="store_true", help="Tampilkan child WIF dan Electrum sweep line.")
    parser.add_argument("--json", action="store_true", help="Cetak output sebagai JSON.")
    args = parser.parse_args()

    if args.limit < 1 or args.limit > 10000:
        print("ERROR: --limit harus 1 sampai 10000.", file=sys.stderr)
        return 1

    if sys.stdin.isatty():
        print("Paste extended private key di bawah ini. Input disembunyikan.")
        secret_text = getpass.getpass("xprv/yprv/zprv: ")
    else:
        secret_text = sys.stdin.read().strip()

    try:
        root = parse_xprv(secret_text)
        if args.path:
            script_type = args.script_type
            if not script_type:
                if args.address.startswith(("bc1q", "tb1q")):
                    script_type = "native_segwit_p2wpkh"
                elif args.address.startswith(("3", "2")):
                    script_type = "nested_segwit_p2sh_p2wpkh"
                elif args.address.startswith(("1", "m", "n")):
                    script_type = "legacy_p2pkh_compressed_pubkey"
                elif args.address.startswith(("bc1p", "tb1p")):
                    script_type = "taproot_bip86_p2tr"
                else:
                    raise ValueError("Tidak bisa menebak script type dari address; isi --script-type.")
            indexes = parse_path(args.path)
            node = derive_path(root, indexes)
            network = "testnet" if args.address.startswith(("tb1", "m", "n", "2")) else "mainnet"
            derived_address = address_for(node.secret, script_type, network)
            matches = []
            if derived_address == args.address:
                matches.append({
                    "path": format_path(indexes),
                    "script_type": script_type,
                    "network": network,
                    "change": None,
                    "index": None,
                    "secret": node.secret,
                })
        else:
            matches = auto_search(root, args.address, args.limit)
    except Exception as exc:
        print(f"\nERROR: {exc}", file=sys.stderr)
        return 1

    public_matches = [result_payload(root, m, args.show_private) for m in matches]
    if args.json:
        print(json.dumps({
            "extended_key_prefix": root.prefix,
            "extended_key_depth": root.depth,
            "target_address": args.address,
            "matches": public_matches,
        }, indent=2))
    else:
        print_result(root, args.address, matches, args.show_private)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
