# PCC Scout Collector — Code Signing Learning Path

A start-to-finish path for signing the per-prospect Collector EXE so it stops
tripping SmartScreen and "Unknown Publisher" warnings on prospect machines.

> **The 60-second answer.** Scout ships a *uniquely-named, unique-hash EXE to
> each prospect, downloaded once.* SmartScreen's cheap tier builds trust **per
> file**, and your files never repeat — so a standard **OV certificate would
> leave every prospect staring at the blue "Windows protected your PC" wall,
> forever.** Only **publisher-level instant trust** clears that:
>
> 1. **Azure Trusted Signing** — ~$10/mo, no hardware, immediate trust.
>    **Start here** if Precision Computers & Consulting is a registered business
>    3+ years old.
> 2. **EV certificate on a USB token** — ~$300–500/yr, instant trust, works
>    regardless of company age; you sign from a machine with the token plugged in.

## 1. The mental model — three separate trust systems

| # | System | What it looks like | Fixed by |
|---|--------|--------------------|----------|
| 1 | **Unknown Publisher** | UAC dialog naming the maker, or "Unknown Publisher" in yellow | **Any** valid signature |
| 2 | **SmartScreen reputation** | Full-screen blue "Windows protected your PC" | **EV / Trusted Signing** instantly; OV only via slow per-file reputation |
| 3 | **EDR / antivirus** | SentinelOne / CrowdStrike / Defender heuristics | Signing helps a lot — not a guarantee |

Signing matters **double** for Scout: dropping bundled nmap was half the
EDR-trust story; a trusted-publisher signature is the other half — it's what
lets a guarded prospect network run the collector in a sales meeting.

## 2. Choosing a certificate (2026)

Since June 2023, OV/EV signing keys must live on certified hardware — no more
downloadable `.pfx`. Three realistic paths (prices approximate; confirm at purchase):

| Option | Cost | Clears SmartScreen? | Hardware | Best for |
|--------|------|---------------------|----------|----------|
| **Azure Trusted Signing** ⭐ | ~$9.99/mo | Yes, instantly | None (cloud) | Registered business 3+ yrs old wanting cheapest/lowest-friction |
| **EV certificate** (Sectigo/DigiCert/SSL.com) | ~$300–500/yr | Yes, instantly | USB token / cloud HSM | Not eligible for Trusted Signing, or want a physical token |
| **OV certificate** | ~$200–400/yr | **No** — reputation only | USB token / cloud HSM | General apps with steady download volume. **A trap for Scout.** |

### The reputation trap (read twice)
SmartScreen's cheap tier is **per-file reputation** — a specific EXE hash must be
"seen" enough times to be trusted. Your pipeline emits
`pcc-scout-collector-<slug>.exe`: a different file/hash per prospect, downloaded
**once**. It never accumulates reputation. OV would fix the small dialog and
leave the scary blue wall on every prospect machine. **EV and Trusted Signing
carry publisher-level reputation — trust attaches to *you*, so the first build
and every uniquely-named prospect EXE after it are trusted from day one.**

## 3. The path, in five stages

- **Stage 0 — Understand the three trust systems.** (~15 min, reading.) Exit
  check: you can say which system OV fixes and which it doesn't.
- **Stage 1 — Decide: Trusted Signing or EV.** One question — is PCC a
  verifiable registered business 3+ years old? Yes → Trusted Signing. No / want
  a token → EV.
- **Stage 2 — Enroll & pass identity validation.** (~1–3 hrs of your time, then
  1–5 business days waiting.) Have legal name, address, and a publicly-listed
  phone ready.
  - *Trusted Signing:* Azure portal → Trusted Signing account → Identity
    Validation (Public Trust) → Certificate Profile.
  - *EV:* order from a CA, complete vetting + verification call, receive USB token.
  - Exit check: sign a throwaway `hello.exe` and it reports your name as publisher.
- **Stage 3 — Wire into electron-builder.** (~1–2 hrs, one config change.) See §4.
- **Stage 4 — Verify, timestamp, operate.** (~1 hr setup + ongoing habit.) See §5.

## 4. Wiring it into the build

Signing plugs into the existing `electron-builder.collector.json` so **every**
per-prospect build gets signed automatically.

### Path A — Azure Trusted Signing
Add inside `"win"`:
```json
"azureSignOptions": {
  "endpoint": "https://eus.codesigning.azure.net",
  "codeSigningAccountName": "pcc-scout-signing",
  "certificateProfileName": "pcc-collector",
  "timestampRfc3161": "http://timestamp.acs.microsoft.com",
  "timestampDigest": "SHA256"
}
```
Credentials go in the shell/CI as a service principal — never in the file:
```bash
export AZURE_TENANT_ID="…"
export AZURE_CLIENT_ID="…"
export AZURE_CLIENT_SECRET="…"
PROSPECT_SLUG=acme-corp npm run build:collector
```

### Path B — EV certificate on a token
The key is on hardware, so reference the cert by subject name (no `.pfx`):
```json
"win": {
  "target": "portable",
  "certificateSubjectName": "Precision Computers & Consulting",
  "signingHashAlgorithms": ["sha256"],
  "rfc3161TimeStampServer": "http://timestamp.sectigo.com"
}
```
The token must be plugged in at build time; electron-builder calls `signtool`.
EV tokens prompt for a PIN per session — batch prospect builds so you enter it once.

> **Always include a timestamp server** (both snippets do). It records *when* you
> signed, so signatures stay valid after the certificate expires. Without it,
> every EXE you ever shipped goes untrusted the day the cert lapses.

## 5. Verify & operate

- **Confirm the signature:** `signtool verify /pa /v collector.exe` — expect your
  publisher name and a valid timestamp countersignature.
- **Test on a clean machine:** download a fresh prospect EXE onto a Windows VM
  that's never seen it. No blue wall = publisher trust works.
- **Right-click → Properties → Digital Signatures:** the human-visible proof a
  prospect can check themselves.
- **EDR is separate:** signing cuts false positives sharply, but keep a short
  "submit our publisher/hash to allow-list" note for prospects on managed
  SentinelOne/CrowdStrike.
- **Renew on a calendar:** Trusted Signing auto-renews; an EV cert is yours to
  renew yearly — calendar the expiry the day you get it.
- **Keep credentials out of git:** service-principal secrets and token PINs live
  in the shell / CI secrets.

## Glossary
- **Authenticode** — Microsoft's format for signing Windows executables.
- **OV / EV** — Organization / Extended Validation. EV grants *immediate*
  SmartScreen publisher trust; OV earns it only via per-file reputation.
- **SmartScreen** — Windows' download-reputation gate (the blue wall).
- **Trusted Signing** — Azure's managed cloud signing (EV-grade instant trust,
  ~$10/mo, no hardware; formerly "Azure Code Signing").
- **HSM** — Hardware Security Module; a USB signing token is a small one.
- **Timestamp** — countersignature recording when you signed, so signatures
  survive cert expiry.
- **signtool** — Microsoft's CLI signing/verify tool; electron-builder calls it.

---
*Figures approximate for 2026 — verify pricing and current Trusted Signing
eligibility rules at purchase.*
