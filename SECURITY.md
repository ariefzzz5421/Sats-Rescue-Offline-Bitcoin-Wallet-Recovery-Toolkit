# Security Policy

## Do Not Share Secrets

Do not open GitHub issues, pull requests, screenshots, or discussions containing:

- Seed phrases.
- Private keys.
- WIF keys.
- Extended private keys such as `xprv`, `yprv`, `zprv`.
- Electrum sweep lines.
- Wallet files.

Anyone with those secrets can spend the funds.

## Safe Support Information

If you need help, share only:

- Public Bitcoin address.
- Transaction ID.
- Wallet name and version.
- Exact error message.
- Key format summary, for example `12-word seed`, `starts with zprv`, or `WIF starts with K`.

## Offline Use

For real recovery work:

1. Read the code first.
2. Disconnect from the internet.
3. Run the tool locally.
4. Sweep funds to a new wallet.
5. Do not reuse the recovered key.

## Vulnerability Reports

If you find a vulnerability in this project, open a public issue only if it does not expose secrets or active funds. For sensitive reports, contact the maintainer privately.
