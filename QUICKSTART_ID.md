# Panduan Cepat Sats Rescue

Tool ini untuk membantu recovery wallet Bitcoin **milik sendiri** saat kamu masih punya seed phrase, `xprv/yprv/zprv`, private key, atau WIF.

Tool ini tidak bisa menebak seed phrase yang benar-benar hilang.

## 1. Clone Repo

```powershell
git clone https://github.com/USERNAME/sats-rescue.git
cd sats-rescue
```

Atau kalau sudah download ZIP, masuk ke folder hasil extract.

## 2. Cek Python

```powershell
python --version
```

Kalau Python belum ada, install Python 3.10+ dari website resmi Python.

## 3. Recovery Dari Seed Phrase

Kalau kamu punya 12/24 kata seed phrase:

```powershell
python .\btc_seed_recovery_tool.py --address ALAMAT_BTC_KAMU --limit 20
```

Saat muncul:

```text
Seed phrase BIP39:
```

paste seed phrase. Teks tidak akan terlihat. Itu normal. Tekan `Enter`.

Kalau seed kamu punya passphrase tambahan:

```powershell
python .\btc_seed_recovery_tool.py --address ALAMAT_BTC_KAMU --limit 20 --passphrase
```

Kalau muncul `[MATCH]`, jalankan lagi:

```powershell
python .\btc_seed_recovery_tool.py --address ALAMAT_BTC_KAMU --limit 20 --show-private
```

Ambil baris:

```text
Electrum sweep line : ...
```

Jangan kirim baris itu ke siapa pun.

## 4. Recovery Dari zprv / xprv / yprv

Kalau secret kamu mulai dengan `zprv`, `xprv`, atau `yprv`:

```powershell
python .\btc_hd_recovery_tool.py --address ALAMAT_BTC_KAMU --limit 20
```

Kalau key sudah depth address seperti `Depth: 5`, coba:

```powershell
python .\btc_hd_recovery_tool.py --address ALAMAT_BTC_KAMU --path m --show-private
```

## 5. Recovery Dari Private Key / WIF

Kalau kamu punya private key biasa:

```powershell
python .\btc_key_recovery_tool.py --address ALAMAT_BTC_KAMU
```

Kalau match:

```powershell
python .\btc_key_recovery_tool.py --address ALAMAT_BTC_KAMU --show-private
```

## 6. Sweep Ke Wallet Baru

Di Electrum:

1. Buat wallet baru dengan seed phrase baru.
2. Buka `Wallet > Private Keys > Sweep`.
3. Paste `Electrum sweep line`.
4. Pastikan destination address adalah wallet baru kamu.
5. Klik `Preview`, cek ulang address dan fee.
6. Kalau benar, klik `Sign/Broadcast`.

## 7. Kirim Ke CEX

Setelah dana masuk dan confirmed di wallet baru:

1. Buka CEX.
2. Pilih `Deposit BTC`.
3. Pilih network `BTC / Bitcoin / Bitcoin Mainnet`.
4. Copy address deposit.
5. Dari Electrum, kirim ke address deposit itu.

Jangan pilih:

- BEP20
- ERC20
- BSC
- TRC20
- Lightning

## Risk

Kalau seed/private key dibuat bot, anggap bot juga bisa mengambil dana. Setelah berhasil recovery, langsung pindahkan semua dana ke wallet baru yang seed phrase-nya dibuat sendiri.
