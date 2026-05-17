# BTC Wallet Recovery Steps

Use this guide when you have a single BTC private key from a bot but an external wallet refuses it.

Do not paste your private key, seed phrase, wallet file, or WIF into any chat.

## 1. Prepare public data only

Safe to share:

- Public BTC address, for example starts with `1`, `3`, `bc1q`, or `bc1p`.
- Transaction ID if BTC was already sent to that address.
- Wallet app name and exact error message.
- Key format only, not the key: example `64 hex chars`, `starts with K`, `starts with L`, `starts with 5`, `starts with xprv`.

Do not share:

- The full private key.
- Seed phrase.
- WIF.
- QR code containing the key.
- Screenshot that shows the key.

## 2. Run the offline checker

Open PowerShell in this folder:

```powershell
cd C:\Users\ariefzzz.eth\Documents\Codex\2026-05-16\https-chatgpt-com-share-6a07b303-30d4
python .\btc_key_recovery_tool.py --address YOUR_PUBLIC_BTC_ADDRESS
```

Paste the private key when asked. The input is hidden.

The tool will show:

- Whether the key is valid.
- Public key compressed and uncompressed.
- Possible BTC addresses from that key.
- Whether one of those addresses matches your target address.

## 3. If the address matches

Run this only offline if you need the WIF/sweep data:

```powershell
python .\btc_key_recovery_tool.py --address YOUR_PUBLIC_BTC_ADDRESS --show-private
```

Use the output that matches your address type:

- Address starts with `1`: usually use `wif_compressed` or `wif_uncompressed`.
- Address starts with `3`: try `electrum_sweep_nested_segwit`.
- Address starts with `bc1q`: try `electrum_sweep_native_segwit`.
- Address starts with `bc1p`: this is Taproot. Some wallets need descriptor/Taproot support, not basic WIF import.

After you can spend it, sweep all funds to a new wallet seed that was not created by the bot.

## 4. If your key starts with xprv/yprv/zprv

That is an HD extended private key, not a single private key. Use the HD tool:

```powershell
python .\btc_hd_recovery_tool.py --address YOUR_PUBLIC_BTC_ADDRESS --limit 20
```

When PowerShell shows `xprv/yprv/zprv:`, paste the extended private key and press Enter.
The pasted text is hidden, so the screen may look like nothing happened.

If no match is found, increase gradually:

```powershell
python .\btc_hd_recovery_tool.py --address YOUR_PUBLIC_BTC_ADDRESS --limit 200
```

If it finds a match, run again only offline:

```powershell
python .\btc_hd_recovery_tool.py --address YOUR_PUBLIC_BTC_ADDRESS --limit 200 --show-private
```

For an address that starts with `bc1q`, the useful line is usually:

```text
p2wpkh:...
```

Paste that line into Electrum:

```text
Wallet > Private Keys > Sweep
```

Leave the destination address as your new Electrum wallet address, set fee, then send.

If no match is found, try a wider scan:

```powershell
python .\btc_hd_recovery_tool.py --address YOUR_PUBLIC_BTC_ADDRESS --limit 1000
```

If the bot gave a known derivation path, run:

```powershell
python .\btc_hd_recovery_tool.py --address YOUR_PUBLIC_BTC_ADDRESS --path "m/84'/0'/0'/0/0"
```

## 5. If the address does not match

Likely causes:

- The bot gave the wrong key.
- The key was copied with a typo.
- The wallet address was made from a seed phrase or extended key, not a single private key.
- Wrong network: testnet key cannot spend mainnet BTC.
- Wrong address type or derivation path.

Next safe information to collect:

- Public BTC address.
- TXID where funds were received.
- Exact wallet error message.
- Key format summary only, not the key.

## 6. Security warning

If a bot generated the private key, assume the bot owner can also spend the BTC.
Do not keep funds there. Sweep to a fresh wallet immediately after recovery.
