# BitcoinPIR cashier

The credit issuer for BitcoinPIR paid queries. A browser (or any client)
buys an ARC credential for a `cashuB…` token and spends it one credit at a
time on any PIR server; each server forwards what it was shown to the
cashier, which verifies it, rejects double spends, and settles with that
server in gas.

The contract this service implements is "Issuer API" in
[`docs/CREDITS.md`](https://github.com/Bitcoin-PIR/Bitcoin-PIR/blob/main/docs/CREDITS.md)
in the main repository. Its types (`pir-credit`) are consumed from that
repository by git revision, so cashier and servers can never disagree on
the bytes. The v1 session grants (`/v1/info`, `/v1/grants`) are retired.

## What it does

| Endpoint | Behaviour |
| --- | --- |
| `GET /v2/info` | the credits contract ([`docs/CREDITS.md`](https://github.com/Bitcoin-PIR/Bitcoin-PIR/blob/main/docs/CREDITS.md)): `credit_sat`, `gas_per_credit`, `base_gas_per_frame`, `egress_gas_per_mb`, `mints`, sat-priced `offers`, `rate_card` |
| `POST /v2/credentials` | pay one listed pack (`credits` = the presentation limit, `sat`) with a Cashu token and a blinded `arc::CredentialRequest`; the cashier swaps the token at the mint through a [cdk](https://crates.io/crates/cdk) wallet, blind-issues an ARC credential under the current epoch's key, and answers `CredentialResponseV2` (idempotent per token and request) |
| `POST /v2/redeem` | a PIR server forwards what a client presented (`RedeemRequestV1`, signed by the server's identity key and carrying its operator-signed certificate); the cashier verifies each item — a Cashu token is swapped at the mint (`gas_added = sats × gas_per_credit / credit_sat`), ARC presentations are verified under their epoch's key with a global tag set per epoch (`gas_per_credit` each, `402 double_spend` on reuse, `402 expired_epoch` outside the epoch or its grace) — books the value to that server, and answers `RedeemResponseV1` signed by the same key servers pin |
| `GET /healthz` | `ok` |

Rules that matter:

- **Never credit without money.** A credential is issued and a redemption
  booked only after the mint accepted the swap; a token the mint refuses
  gets `402 token_rejected`, a mint that cannot be reached gets
  `503 mint_unavailable` and the token stays spendable.
- **Idempotent per token.** The idempotency key is derived from the token's
  proof secrets; a token is spent at most once across all paths, and a
  repeated credential request for the same token and blinded request
  returns the same answer without consulting the mint.
- **Honest about the unknown.** If the process dies (or the mint times out)
  after the swap request was sent, the token is left in a `pending` state
  and logged at error level for manual reconciliation.
- **No secrets on the PIR hosts.** The cashier is the only component that
  holds the issuer signing seed, the ARC master seed, and the wallet seed.
  Servers pin the issuer public key with `--credit-issuer-pubkey`.
- **Redeem is authenticated and replay-safe.** Only servers certified by an
  operator key in `operator_pubkeys` may redeem; `server_id` must match the
  certificate; a repeated `(server_id, nonce)` returns the stored signed
  answer without touching the mint; a token that already bought something
  (a credential, or a v1 grant before the retirement) or was redeemed once
  answers `402 already_redeemed`. Every redemption is
  appended to `redeem.jsonl`, the per-server settlement ledger
  (`bpir-cashier settlement --config …`).

## Build

```sh
cargo build --release          # rust-toolchain.toml pins the compiler
cargo test
```

`cdk` is built with `default-features = false, features = ["wallet"]`; no
mint, nostr, or Lightning code is compiled in.

## Operate

```sh
# once: keys
bpir-cashier keygen --out /etc/bitcoinpir/cashier/grant.key      # issuer seed; prints the pubkey to pin
bpir-cashier wallet-seed --out /etc/bitcoinpir/cashier/wallet.seed

# config
cp config.example.toml /etc/bitcoinpir/cashier/config.toml       # edit mints, CORS, operator keys, [arc] packs

# run
bpir-cashier serve --config /etc/bitcoinpir/cashier/config.toml
bpir-cashier balance --config /etc/bitcoinpir/cashier/config.toml   # ecash held per (mint, unit)
bpir-cashier settlement --config /etc/bitcoinpir/cashier/config.toml # gas and sat redeemed per PIR server
bpir-cashier arc-seed --out /etc/bitcoinpir/cashier/arc.seed        # ARC master seed (per-epoch issuer keys)
bpir-cashier pubkey --key /etc/bitcoinpir/cashier/grant.key
bpir-cashier mnemonic --out /etc/bitcoinpir/mint/seed         # BIP39 phrase for a cdk-mintd --seed-file (mode 0400)
```

`deploy/bpir-cashier.service` is a hardened systemd unit; put a reverse
proxy or a Cloudflare tunnel in front (the browser pins
`https://cashier.bitcoinpir.org`). The service speaks plain HTTP and sends
the CORS headers the browser needs.

On every PIR server:

```sh
unified_server … --credit-issuer-url https://cashier.bitcoinpir.org \
                 --credit-issuer-pubkey /etc/bitcoinpir/cashier/grant.pub   # 64 hex chars from keygen
# what each backend charges: --require-credits and --access (docs/CREDITS.md "Access policy")
```

The cashier's `operator_pubkeys` must list the operator key that signed the
servers' identity certificates, or `POST /v2/redeem` refuses them.

### Files the operator owns

| File | Contents | Backup |
| --- | --- | --- |
| `grant.key` | 32-byte Ed25519 issuer seed (signs redeem answers) | yes — rotating it means re-pinning every server |
| `arc.seed` | 32-byte ARC master seed | yes — it is the credentials |
| `wallet.seed` | 64-byte Cashu wallet seed | yes — with the mint, it recovers the ecash |
| `wallet.sqlite` | proofs the cashier holds (cdk wallet store) | yes |
| `grants.jsonl` | append-only log: every token seen, what it bought, every failure (the name predates credits) | yes — it is the idempotency store and the reconciliation record |
| `redeem.jsonl` | every redemption per server | yes — it is the settlement ledger |

Money accumulates in the wallet as ecash. Melt it to Lightning with any cdk
wallet (for example `cdk-cli` with the same seed) or extend the `balance`
command; the cashier itself never pays out.

### Fees

A mint may deduct input fees on the swap, so the amount credited can be
below the token's face value. The cashier validates the **face value**
against the pack and absorbs the fee; the credited amount is recorded in
`grants.jsonl`.

## Layout

```
src/config.rs   TOML config and validation, seed-file reader
src/cashu.rs    token summary, idempotency key, Swapper trait, cdk implementation
src/issuer_key.rs  the Ed25519 key that signs redeem answers
src/arc.rs      ARC credential issuance and presentation verification
src/redeem.rs   POST /v2/redeem verification, replay index, settlement ledger
src/store.rs    JSON-lines idempotency/audit store
src/api.rs      axum router, handlers, contract error codes
src/main.rs     CLI
tests/api.rs    contract tests with a scripted fake mint
```

License: MIT OR Apache-2.0.
