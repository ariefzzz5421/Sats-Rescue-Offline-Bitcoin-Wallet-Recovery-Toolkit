#!/usr/bin/env python3
"""
Offline Bitcoin BIP39 seed phrase recovery helper.

This tool helps owners of a known seed phrase find which standard derivation
path created a public Bitcoin address. It does not brute-force missing seed
words and it does not use the network.
"""

from __future__ import annotations

import argparse
import getpass
import hashlib
import hmac
import json
import re
import sys
import unicodedata
from typing import Dict, Iterable, List, Optional, Sequence

from btc_hd_recovery_tool import (
    HARDENED,
    ExtPrivateKey,
    address_for,
    derive_path,
    format_path,
    parse_path,
    sweep_prefix,
)
from btc_key_recovery_tool import pubkeys, wif_encode


ACCOUNT_PURPOSES = {
    "legacy_p2pkh_compressed_pubkey": 44,
    "nested_segwit_p2sh_p2wpkh": 49,
    "native_segwit_p2wpkh": 84,
    "taproot_bip86_p2tr": 86,
}


def normalize_mnemonic(text: str) -> str:
    words = re.split(r"\s+", text.strip().lower())
    words = [unicodedata.normalize("NFKD", word) for word in words if word]
    return " ".join(words)


def mnemonic_to_seed(mnemonic: str, passphrase: str = "") -> bytes:
    normalized_mnemonic = unicodedata.normalize("NFKD", normalize_mnemonic(mnemonic))
    normalized_passphrase = unicodedata.normalize("NFKD", passphrase)
    salt = ("mnemonic" + normalized_passphrase).encode("utf-8")
    return hashlib.pbkdf2_hmac("sha512", normalized_mnemonic.encode("utf-8"), salt, 2048, 64)


def master_from_seed(seed: bytes, network: str = "mainnet") -> ExtPrivateKey:
    digest = hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest()
    secret = int.from_bytes(digest[:32], "big")
    chain_code = digest[32:]
    version = 0x0488ADE4 if network == "mainnet" else 0x04358394
    return ExtPrivateKey(version, 0, b"\x00\x00\x00\x00", 0, chain_code, secret)


def network_from_address(address: Optional[str], default: str = "mainnet") -> str:
    if address and address.startswith(("tb1", "m", "n", "2")):
        return "testnet"
    return default


def script_candidates(address: Optional[str]) -> List[str]:
    if not address:
        return [
            "native_segwit_p2wpkh",
            "nested_segwit_p2sh_p2wpkh",
            "legacy_p2pkh_compressed_pubkey",
            "taproot_bip86_p2tr",
        ]
    if address.startswith(("bc1q", "tb1q")):
        return ["native_segwit_p2wpkh"]
    if address.startswith(("bc1p", "tb1p")):
        return ["taproot_bip86_p2tr"]
    if address.startswith(("3", "2")):
        return ["nested_segwit_p2sh_p2wpkh"]
    if address.startswith(("1", "m", "n")):
        return ["legacy_p2pkh_compressed_pubkey"]
    return [
        "native_segwit_p2wpkh",
        "nested_segwit_p2sh_p2wpkh",
        "legacy_p2pkh_compressed_pubkey",
        "taproot_bip86_p2tr",
    ]


def candidate_account_prefixes(script_type: str, accounts: int, network: str) -> Iterable[List[int]]:
    purpose = ACCOUNT_PURPOSES[script_type]
    coin_type = 1 if network == "testnet" else 0
    for account in range(accounts):
        yield [
            purpose + HARDENED,
            coin_type + HARDENED,
            account + HARDENED,
        ]


def find_matches(
    root: ExtPrivateKey,
    target_address: str,
    limit: int,
    accounts: int,
    manual_path: Optional[str],
    manual_script_type: Optional[str],
) -> List[Dict[str, object]]:
    network = network_from_address(target_address)
    candidates = script_candidates(target_address)
    matches: List[Dict[str, object]] = []

    if manual_path:
        script_type = manual_script_type or candidates[0]
        indexes = parse_path(manual_path)
        node = derive_path(root, indexes)
        address = address_for(node.secret, script_type, network)
        if address == target_address:
            matches.append({
                "path": format_path(indexes),
                "script_type": script_type,
                "network": network,
                "address": address,
                "secret": node.secret,
            })
        return matches

    for script_type in candidates:
        for prefix in candidate_account_prefixes(script_type, accounts, network):
            account_node = derive_path(root, prefix)
            for change in [0, 1]:
                change_node = derive_path(account_node, [change])
                for index in range(limit):
                    path = prefix + [change, index]
                    node = derive_path(change_node, [index])
                    address = address_for(node.secret, script_type, network)
                    if address == target_address:
                        matches.append({
                            "path": format_path(path),
                            "script_type": script_type,
                            "network": network,
                            "address": address,
                            "secret": node.secret,
                        })
    return matches


def list_addresses(root: ExtPrivateKey, limit: int, accounts: int, network: str) -> List[Dict[str, object]]:
    rows: List[Dict[str, object]] = []
    for script_type in [
        "native_segwit_p2wpkh",
        "nested_segwit_p2sh_p2wpkh",
        "legacy_p2pkh_compressed_pubkey",
        "taproot_bip86_p2tr",
    ]:
        for prefix in candidate_account_prefixes(script_type, accounts, network):
            account_node = derive_path(root, prefix)
            change_node = derive_path(account_node, [0])
            for index in range(limit):
                path = prefix + [0, index]
                node = derive_path(change_node, [index])
                rows.append({
                    "path": format_path(path),
                    "script_type": script_type,
                    "network": network,
                    "address": address_for(node.secret, script_type, network),
                })
    return rows


def match_payload(match: Dict[str, object], show_private: bool) -> Dict[str, object]:
    secret = int(match["secret"])
    compressed_pub, uncompressed_pub, _ = pubkeys(secret)
    script_type = str(match["script_type"])
    network = str(match["network"])
    payload: Dict[str, object] = {
        "path": match["path"],
        "script_type": script_type,
        "network": network,
        "address": match["address"],
        "public_key_compressed": compressed_pub.hex(),
        "public_key_uncompressed": uncompressed_pub.hex(),
    }
    if show_private:
        wif = wif_encode(secret, network, True)
        payload["private_material"] = {
            "child_private_key_wif_compressed": wif,
            "electrum_sweep_line": sweep_prefix(script_type) + wif,
        }
    return payload


def print_matches(matches: List[Dict[str, object]], target_address: str, show_private: bool) -> None:
    print("\n=== BTC SEED RECOVERY OFFLINE ===")
    print(f"Target address: {target_address}")
    if not matches:
        print("\n[NO MATCH] Tidak menemukan address yang cocok.")
        print("Coba naikkan --limit, naikkan --accounts, isi --passphrase jika seed memakai passphrase, atau masukkan --path manual.")
        return

    print(f"\n[MATCH] Ditemukan {len(matches)} address yang cocok.")
    for i, match in enumerate(matches, start=1):
        payload = match_payload(match, show_private)
        print(f"\nMatch #{i}")
        print(f"- path: {payload['path']}")
        print(f"- script type: {payload['script_type']}")
        print(f"- network: {payload['network']}")
        print(f"- address: {payload['address']}")
        if show_private:
            material = payload["private_material"]
            print("\nPRIVATE MATERIAL - jangan screenshot / upload / kirim ke siapa pun:")
            print(f"- child WIF compressed: {material['child_private_key_wif_compressed']}")
            print(f"- Electrum sweep line : {material['electrum_sweep_line']}")
        else:
            print("\nPrivate material disembunyikan. Tambah --show-private hanya saat offline.")


def read_secret(prompt: str) -> str:
    if sys.stdin.isatty():
        return getpass.getpass(prompt)
    return sys.stdin.read().strip()


def main() -> int:
    parser = argparse.ArgumentParser(description="Offline BIP39 BTC seed phrase address finder.")
    parser.add_argument("--address", help="Public BTC address yang ingin dicocokkan.")
    parser.add_argument("--list", action="store_true", help="Tampilkan address pertama dari seed, tanpa target address.")
    parser.add_argument("--limit", type=int, default=20, help="Jumlah index per change chain. Default 20.")
    parser.add_argument("--accounts", type=int, default=1, help="Jumlah account BIP44/49/84/86 yang dicek. Default 1.")
    parser.add_argument("--network", choices=["mainnet", "testnet"], default="mainnet", help="Network untuk --list. Default mainnet.")
    parser.add_argument("--passphrase", action="store_true", help="Prompt BIP39 passphrase tambahan. Kosongkan jika tidak memakai passphrase.")
    parser.add_argument("--path", help="Path manual, contoh: m/84'/0'/0'/0/0.")
    parser.add_argument("--script-type", choices=list(ACCOUNT_PURPOSES.keys()), help="Script type untuk --path manual.")
    parser.add_argument("--show-private", action="store_true", help="Tampilkan child WIF dan Electrum sweep line. Gunakan hanya offline.")
    parser.add_argument("--json", action="store_true", help="Cetak output sebagai JSON.")
    args = parser.parse_args()

    if not args.address and not args.list:
        parser.error("Isi --address untuk match, atau gunakan --list untuk menampilkan address pertama.")
    if args.limit < 1 or args.limit > 10000:
        parser.error("--limit harus 1 sampai 10000.")
    if args.accounts < 1 or args.accounts > 100:
        parser.error("--accounts harus 1 sampai 100.")

    mnemonic = read_secret("Seed phrase BIP39: ")
    passphrase = getpass.getpass("BIP39 passphrase (Enter jika kosong): ") if args.passphrase else ""

    word_count = len(normalize_mnemonic(mnemonic).split())
    if word_count not in {12, 15, 18, 21, 24}:
        print(f"\nERROR: Seed phrase biasanya 12/15/18/21/24 kata. Input terbaca {word_count} kata.", file=sys.stderr)
        return 1

    try:
        seed = mnemonic_to_seed(mnemonic, passphrase)
        root = master_from_seed(seed, network_from_address(args.address, args.network))
        if args.list:
            rows = list_addresses(root, args.limit, args.accounts, args.network)
            if args.json:
                print(json.dumps({"addresses": rows}, indent=2))
            else:
                print("\n=== FIRST BTC ADDRESSES FROM SEED ===")
                for row in rows:
                    print(f"{row['path']} | {row['script_type']} | {row['address']}")
            return 0

        assert args.address is not None
        matches = find_matches(root, args.address, args.limit, args.accounts, args.path, args.script_type)
    except Exception as exc:
        print(f"\nERROR: {exc}", file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps({
            "target_address": args.address,
            "matches": [match_payload(m, args.show_private) for m in matches],
        }, indent=2))
    else:
        print_matches(matches, args.address, args.show_private)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
