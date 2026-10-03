# Admin encrypted Watchtower report — design

Sub-project 4 of the reporting roadmap. Status: implemented on feat/admin-encrypted-report for PR review. The separate
extension work is committed locally and is not included in this reporting branch.

## Goal and scope

An explicitly selected administrator can view encrypted, voluntarily submitted
security counts for users' **personal vaults**, plus reporting coverage and freshness.
The server stores ciphertext and routing metadata. It never receives passwords,
password hashes, matching tokens, entry titles, UUIDs, URLs or finding details.

User-selected scope (2026-10-03): counts and coverage first. Cross-user password reuse detection
is excluded pending explicit product requirements and a separate protocol review.
The individual Watchtower remains the detailed remediation view for each user.
No password-age rule is added. Extension/KyAuth publishing, shared-vault reporting,
automatic submission, exports, report history and a scheduled server scanner are
outside this first version. A locked or never-opened vault cannot be scanned here.

## Why password fingerprints are excluded

If a recipient can decrypt a deterministic token and calculate that token for a
candidate password, they can test guesses offline. Encrypting the token to that
recipient does not remove the test. A public salt does not remove it. A secret HMAC
key held by the administrator does not remove it. A key shared with all reporting
clients exposes the same test to any enrolled client. Slow hashing only raises cost;
it does not meet the requirement that weak passwords cannot be tested this way.
Per-user random salts prevent useful cross-user equality, defeating that feature.
These are deductions from the proposed equality interface, not properties promised
by the encryption library.

[RFC 9497](https://www.rfc-editor.org/rfc/rfc9497.html) defines an oblivious PRF in
which the evaluator does not learn the client's input. That primitive alone is not
an authorization or abuse-control protocol: a client that can evaluate arbitrary
guesses and see comparable outputs can still build a dictionary. A later reuse
protocol must define a separate trust boundary, authorized inputs, query limits,
collusion and malicious-client attacks, and the leakage from equality itself.
Do not implement a home-grown OPRF or claim that it resolves this requirement.

## Existing machinery and recipient custody

Reuse `frontend/src/lib/watchtower.ts` for computation and
`frontend/src/lib/userKey.ts` for X-Wing HPKE with HKDF-SHA256/AES-256-GCM. Reuse
the selected administrator's published user key; its seed is already wrapped under
their personal vault key. No reporting private key is generated or held server-side.

Version 1 has **one designated recipient**, an active local administrator with a
published X-Wing key. Other administrators can manage reporting configuration and
view submission coverage, but cannot decrypt reports for that recipient. The UI
must state this explicitly. Adding several independent recipients is a later
product requirement, not a shared private-key export.

Enabling reporting requires a fresh KySignOn browser admin session, CSRF, an
explicit recipient selection and confirmation of their username and fingerprint.
Configuration captures user ID and the exact current public-key bytes. Use full
SHA-256 hex (64 lower-case characters) for protocol key identity; the existing
short display fingerprint is only for human comparison. Device sessions cannot
configure, submit, list or download reports in this version.

The publisher sees the recipient's identity/fingerprint and confirms **each** share.
Reuse Known keys to compare/pin that exact public key; on an existing pin mismatch,
refuse sharing until the user resolves the key change through the existing flow.
An unpinned recipient requires an explicit compare-out-of-band disclosure before
first-use pinning. Never silently replace a pin. A server supplying public keys is
still a trusted directory; first-use pinning cannot defeat initial substitution.
A malicious server serving altered JavaScript can read an unlocked vault: this
feature cannot remove that existing web-client trust boundary.

## Report payload

Construct a new allowlisted summary. Never serialize `WatchtowerReport` itself.
Only live personal entries count. Use the current score weights and no finding
strings. `reused` counts entries reused **within that personal vault**; it is not a
count of passwords or a comparison across users.

```ts
type AdminSummary = {
  schema: "kyvault/admin-summary/1";
  algorithm: "watchtower/1";
  computedAt: string;                    // UTC RFC3339, client-claimed
  liveEntries: number;
  score: number | null;
  breachStatus: "not-run" | "complete";
  counts: {
    breached: number | null;              // null if not-run, including zero entries
    reused: number;
    weak: number;
    insecureUrl: number;
    missing2fa: number;
    expired: number;
    expiring: number;
  };
};
```

Counts are safe integers in 0..liveEntries. Empty vault: liveEntries=0, score=null.
Otherwise score must equal the existing formula calculated from the counts.
A breach result is complete only after a successful full check for the exact saved
vault revision being shared; aborted, failed or edited-after-check results are not
complete. `breached=null` and the existing not-checked score apply in that case.
Do not start HIBP requests just to submit: reuse the existing independent consent.
No new external network destination or CSP relaxation is required.

Projection must use an immutable captured saved revision. Sharing is disabled for
shared selections, unapplied editor drafts, unsaved or saving states. Use the save
queue's existing serializer/exclusive operation to capture the revision and export
an independent KDBX snapshot, then compute outside the live mutable object. Record
the unlock generation and version; refuse to submit if either changes during work.
A server version already changed at admission is rejected rather than relabelled.
A save ordered after that check can make the accepted report stale immediately;
the coverage read compares current version again. Do not promise an atomic scan
of client and server or silently retry against a newer version.

## Encryption and encoding

Each share uses a random 128-bit reportId (32 lower-case hex characters) and a fresh
HPKE single-shot sender context. No reused deterministic ciphertext or context.

HPKE `info` is the UTF-8 encoding of `JSON.stringify` on this exact array of strings:

```
["kyvault/admin-report/1", instanceId, configGeneration, sourceUserId,
 "personal", decimalVaultVersion, reportId, recipientUserId, recipientKeySha256]
```

instanceId and configGeneration are random 128-bit values encoded as 32 lower-case
hex characters. Version is a positive safe integer rendered in base 10 without
leading zeros. User IDs come from the authenticated directory; lengths are bounded
to 128 UTF-8 bytes. IDs and the key digest are echoed in the outer record; the
recipient constructs info from that record and checks the current config.
Changing any field must cause decrypt failure. The version/generation bind context,
but cannot authenticate who originally composed it.

Plaintext is exactly 2048 bytes: two-byte big-endian JSON byte length, strict UTF-8
JSON summary, then zero padding. Require canonical JSON with the exact field order shown above. Reject JSON above 2046 bytes, nonzero padding,
unknown/duplicate keys, invalid dates, extra fields and invalid counts on decode.
A fixed payload size prevents length revealing category counts. With this existing
X-Wing suite, `enc || ciphertext` is 1120 + 2048 + 16 = **3184 bytes**, base64-encoded
canonically. No additional AES envelope or shared symmetric report key is needed.

[HPKE RFC 9180](https://www.rfc-editor.org/rfc/rfc9180.html#section-9.7) does not
provide application replay protection or hide plaintext length, and recipient-key
compromise exposes past ciphertexts. Context, padding and store rules address the
first two; downloaded reports cannot be cryptographically recalled. Base-mode HPKE
does not authenticate the sender. Attribution relies on the server's authenticated
write and audit trail; a malicious server can fabricate a report. Label counts
**client-reported**, never verified compliance or proof that a vault is safe.

Deliberate disclosure: the recipient learns per-user category counts and can infer
some behavior from small vaults or successive submissions. There is no differential
privacy or protection against deductions from those disclosed counts. Manual
consent explains that disclosure. A server observes source, recipient, version,
submission timing and coverage even though the summary is encrypted. Context and
version checks stop mixups under an honest server, not malicious-server rollback.

## Server contract

New `internal/reporting` store owns `DATA_DIR/reporting/` with 0700 directories and
0600 atomic files. It stores one current config and at most one current record per
user in one atomic state.json; user IDs are map keys, never filesystem paths.
Configuration and record writes share its mutex. Failed persistence is an error,
never a success. Config generation and record deletion are one atomic replacement. A failure
changes neither disk nor memory; invalid recipients are still refused on each
access while invalidation persistence is retried. No decrypted count or seed appears
in a log or audit detail.

| Route | Access and result |
| --- | --- |
| GET /api/reporting/config | Authenticated browser; disabled flag, or instanceId/generation and recipient ID, username, public key and full digest. Validate current recipient role, active state and exact published key before returning enabled. |
| PUT /api/admin/reporting/config | Fresh browser admin + CSRF; conditional current generation. Enable with recipient ID/key digest, replace recipient or disable. Server derives public key from directory, generates a new generation and purges old records on every effective change. Unchanged effective settings keep the generation; stale generation is 409. A lost response is resolved with a GET and explicit confirmation, not an automatic mutation retry. |
| PUT /api/reporting/report | Authenticated browser + CSRF; source derived from session, personal scope only. Exact config generation/recipient key, report ID, If-Match personal version, and one 3184-byte sealed payload. Reject version/config mismatch 409 without retaining rejected ciphertext. Atomic replacement; retries of the exact stored reportId/body return 200 without resetting receivedAt. Same ID/different bytes is 409. |
| DELETE /api/reporting/report | Authenticated browser + CSRF; deletes only caller's report, idempotent. No claim that recipient downloads are revoked. |
| GET /api/admin/reporting | Browser admin; bounded cursor pagination of active users' coverage and routing metadata. Designated current recipient may obtain the sealed payload; other admins receive coverage only. No counts returned in plaintext by server. |

Limit a PUT body to 8 KiB using MaxBytesReader before any mutation; reject unknown
JSON fields, duplicate fields, invalid IDs, noncanonical base64 and wrong lengths.
The server cannot validate encrypted summary contents; the admin browser must.
Report ID, source and receivedAt are fixed server metadata; computedAt stays
client-claimed inside ciphertext. GET responses are no-store. Emit fixed audit
actions reporting.config_changed, reporting.submitted, reporting.withdrawn,
reporting.viewed; details contain IDs/generation only. Use the existing per-source
budget to bound rejected-request audit growth.

Before every enabled-config read, report admission and admin payload read, compare
the recipient against the authoritative active/admin/key record. If the recipient
is deactivated, demoted or replaces their public key, invalidate the config with a
new generation and purge records. Never auto-follow their replacement key. An
admin must explicitly re-enable; each user must explicitly share again. A role
promotion grants no private key or past report access. Directory role changes are
authoritative just as elsewhere in KyVault.

Before returning a source's record, compare source active state and current vault
version. Inactive sources are hidden and their cached records removed on the next
reporting access. A read admitted before a concurrent revocation may finish; a
request starting after revocation must fail. Lock-order tests must prove config
changes cannot race record admission into the wrong generation. Personal saves
need no synchronous reporting write: a version-mismatched row becomes stale at the
next list/read. Do not claim cross-store transactional snapshots or verified client
scan times. Recipient/source eligibility is revalidated on every access, including
after restart, and without waiting for a periodic cleanup job.

## Coverage, aggregation and lifetime

Show every active user's personal-vault status: no vault, not submitted, current,
stale version, stale time, unreadable, or unsupported schema. Current requires exact
vault version/config/key and server receivedAt within 24 hours. computedAt is shown
as client-claimed, not used to prove freshness. Purge expired ciphertext after seven
days on load and reporting access; the UI treats expired rows as not submitted.

The recipient unlocks their personal vault, adopts their current user seed through
existing userKeyState, opens eligible blobs in bounded batches and validates them.
Failures affect one row. Lock, logout, unauthorized event, recipient-key change or
config change aborts work and drops every plaintext summary/aggregate. Keep reports
and seeds out of localStorage, IndexedDB, service workers, device caches and URLs.
Zero mutable decrypted byte buffers; JS strings/objects cannot promise secure erasure.

Sum category counts and live entries over valid current rows only; present submitted
and missing/stale counts next to totals. Category totals overlap, so do not sum them
as a count of unique vulnerable entries. Do not average scores or present a healthy
server-wide score when coverage is partial. Separate breach coverage; unchecked
reports contribute no breached count and never imply zero breaches. Shared vaults
are excluded and the heading says "Personal vault reports". A future shared report
needs a per-vault ownership/epoch/contributor rule to prevent member double counting.

This is a disposable reporting cache. Exclude the entire reporting directory from
sealed capsules and restore. A restored installation starts reporting disabled,
with no cached reports or consent; explicit setup generates a new instanceId.
Document this in RESTORE.md and backup tests at implementation time. Restart of the
same installation preserves config/cache and revalidates eligibility. No recovery
seed export is introduced. Recipient key loss requires reconfiguration/resubmission.

## Minimal implementation order and acceptance

1. Summary allowlist/codec/context + tests using existing HPKE. Require rejection of
   bad padding, unknown/duplicate fields, malformed counts and wrong context, with
   no passwords, titles, UUIDs, URLs, reason strings or matching tokens after decryption.
2. Store/API: bounds, browser-only/CSRF/fresh-admin gates, restart/persistence failures,
   conditional config, idempotent retry, expiry, version mismatch, wrong-source spoof,
   recipient key/role/deactivation invalidation and concurrent config/admission.
3. Manual share from personal Watchtower; recipient config and counts/coverage in
   Admin. Real X-Wing end-to-end mock plus real Go handler transport tests. Exercise
   lock during build/decrypt, saves during scan, key pin mismatch and revoked session.
4. Full existing gates, owning DOX/restore updates, UI evidence and adversarial review.

Runnable feasibility check:
`cd frontend && npx --no-install tsx scripts/check-admin-report-design.ts`.
It proves real KDBX → Watchtower counts → fixed-size X-Wing encryption → recipient
round-trip, randomized ciphertext, wrong-recipient/context/tamper refusal and an
allowlisted plaintext. It is a design experiment, not production codec validation,
an offline-guessing security proof, or sender authenticity. Implement the complete
boundary tests above before calling this feature ready.
