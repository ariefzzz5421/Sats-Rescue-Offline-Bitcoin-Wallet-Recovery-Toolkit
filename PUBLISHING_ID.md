# Cara Publish Sats Rescue ke GitHub

Ikuti langkah ini dari folder project.

## 1. Cek file yang akan dipublish

```powershell
dir
```

File utama yang harus ada:

- `README.md`
- `QUICKSTART_ID.md`
- `SECURITY.md`
- `LICENSE`
- `requirements.txt`
- `btc_seed_recovery_tool.py`
- `btc_hd_recovery_tool.py`
- `btc_key_recovery_tool.py`
- `tests/test_vectors.py`

Jangan publish:

- Seed phrase asli.
- Private key asli.
- Screenshot yang berisi secret.
- File wallet.
- File `.txt` berisi recovery data pribadi.

## 2. Test sebelum publish

```powershell
python .\tests\test_vectors.py
```

Harus keluar:

```text
All public test vectors passed.
```

## 3. Buat repo GitHub

1. Buka GitHub.
2. Klik `New repository`.
3. Nama repo yang disarankan:

```text
sats-rescue
```

4. Description:

```text
Offline Bitcoin wallet recovery toolkit for seed phrase, xprv/yprv/zprv, and WIF address matching.
```

5. Pilih `Public`.
6. Jangan centang `Add README`, karena README sudah ada di folder ini.

## 4. Push dari PowerShell

Ganti `USERNAME` dengan username GitHub kamu.

```powershell
git init
git add .
git commit -m "Initial release: Sats Rescue offline BTC recovery toolkit"
git branch -M main
git remote add origin https://github.com/USERNAME/sats-rescue.git
git push -u origin main
```

## 5. Tambahkan GitHub Topics

Di halaman repo GitHub, tambahkan topics:

```text
bitcoin
wallet-recovery
electrum
bip39
bip32
segwit
taproot
offline-tool
python
btc
```

## 6. Pesan Penting di Repo

Pastikan README tetap menjelaskan:

- Tool ini offline.
- Tidak ada dependency.
- Tidak bisa menebak seed phrase yang hilang.
- Jangan upload secret ke GitHub issue.
- Gunakan hanya untuk wallet sendiri.

## 7. Kalau Ada Orang Minta Bantuan

Minta mereka kirim hanya data publik:

- Public BTC address.
- TXID.
- Wallet app.
- Error message.
- Format key, misalnya `zprv depth 5`, `12-word seed`, atau `WIF starts with K`.

Jangan pernah minta seed phrase/private key mereka.
