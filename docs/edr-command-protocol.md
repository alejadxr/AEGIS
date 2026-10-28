# AEGIS EDR Command Protocol (v1) — DESIGN PROPOSAL, NOT IMPLEMENTED

> **Status: proposal. Nothing in this document exists yet.**
>
> - The endpoints `GET /api/v1/nodes/commands`, `POST /api/v1/nodes/commands/{id}/ack`,
>   `POST /api/v1/response/endpoint-actions` and
>   `GET /api/v1/response/endpoint-actions/{action_id}` are **not in the backend**
>   and not in the OpenAPI schema.
> - There is **no** `command_pubkey` in the node-status response, no Ed25519
>   command-signing key (`AEGIS_COMMAND_KEY_PATH`, `AEGIS_COMMAND_SIGNING_KEY`),
>   and the agent (`node-tauri`) does not verify or execute signed commands.
> - `AEGIS_ENROLLMENT_MODE` and the `node_approver` role in section 7 are not
>   implemented either.
> - The three response actions that would depend on this channel —
>   `isolate_host`, `kill_process` and `quarantine_file` in
>   `backend/app/modules/response/responder.py` — are **stubs**. They return
>   `{"success": false, "status": "not_implemented"}` and change nothing on any
>   host. AEGIS cannot isolate, kill or quarantine on an endpoint today.
>
> What follows is the intended design, kept so the work can start from a
> reviewed contract. Written in the present tense for readability; read every
> "is" and "does" as "would".

How the AEGIS server would tell an endpoint agent to act (kill a process,
isolate the host, quarantine a file) and how the agent would report back. If
built, the server, the agent (`node-tauri`) and this document would all live in
this repository. Any other system that wants to trigger an action would call
the public API in section 5; a second transport may relay the signed envelope
unchanged (section 6), but AEGIS would never depend on one.

## 1. Trust model

- Every deployment has one **Ed25519 command-signing key pair**.
  - The private key is generated on first start and stored outside the database
    at `AEGIS_COMMAND_KEY_PATH` (default `~/.aegis/command_signing_key`, file
    mode `0600`), or supplied via `AEGIS_COMMAND_SIGNING_KEY` (base64 raw 32-byte
    seed). It is never logged and never returned by any API.
  - The public key is raw 32 bytes, transmitted as standard base64.
- An agent learns the public key **at enrollment**: the first `active`
  `GET /api/v1/nodes/status/{code}` response carries `command_pubkey` alongside
  the node token. The agent persists it with its node config and pins it; it
  never accepts a key from any other source.
- Agents authenticate to the server with the per-node token
  (`X-AEGIS-Node-Token` + `X-AEGIS-Node-Id`). The server authenticates commands
  to the agent with the signature. Both directions are required.

## 2. Envelope

The server never asks the agent to re-serialize anything. It signs the exact
bytes it sends:

```json
{
  "payload": "<base64url, no padding, of the UTF-8 JSON bytes of the command>",
  "sig":     "<base64url, no padding, of the 64-byte Ed25519 signature over those bytes>"
}
```

The agent MUST: base64url-decode `payload` → verify `sig` over those exact bytes
with the pinned public key → only then parse the bytes as JSON. A command whose
signature does not verify is discarded and reported as `rejected_signature` if
it carries a parseable id; it is never executed.

## 3. Command (decoded payload)

```json
{
  "v": 1,
  "id": "cmd_…",                 // unique, server-assigned
  "node_id": "…",                // the target node; agent rejects any other value
  "action": "kill_process",      // see section 4
  "params": { … },
  "issued_at": "2026-09-29T21:00:00Z",   // RFC 3339 UTC
  "expires_at": "2026-09-29T21:05:00Z",  // agent rejects if now > expires_at
  "nonce": "<base64url 16 random bytes>"
}
```

Agent checks, in order, all mandatory: signature → `v == 1` → `node_id` equals
its own → `now <= expires_at` (allow 60 s clock skew) → `nonce` not seen before.
The agent keeps seen nonces at least until their `expires_at` has passed, so the
same command delivered twice (by retry or by two transports) executes once.

## 4. Actions

| action | params | agent behaviour |
|---|---|---|
| `kill_process` | `pid` (int), `expected_image` (full path) | Kill only if `pid` is still running **and** its image path equals `expected_image` (case-insensitive on Windows). A recycled PID is refused (`rejected_mismatch`). Kills the process tree. |
| `isolate_host` | `allow` (list of IPs/CIDRs) | Block all inbound and outbound traffic except to the AEGIS server and the listed addresses. The AEGIS channel must stay open or isolation could never be lifted. Windows: Windows Filtering Platform / `netsh advfirewall` rules in a dedicated, removable rule group. |
| `release_host` | — | Remove exactly the rules `isolate_host` added. |
| `quarantine_file` | `path`, `sha256` | Only if the file's current SHA-256 equals `sha256`: move it to the agent's quarantine directory, stripped of execute permission, recording the original path. |
| `restore_file` | `quarantine_id` | Move a quarantined file back to its original path. |

Unknown actions are rejected (`rejected_unknown_action`), never guessed at.

## 5. Server APIs

### Enqueue (called by operators, ServerForge, or AEGIS's own response engine)
`POST /api/v1/response/endpoint-actions` — tenant `X-API-Key` (role analyst or
admin) or user JWT.

```json
{ "node_id": "…", "action": "kill_process", "params": { … },
  "reason": "…", "incident_id": "optional" }
```

The request passes through `core/guardrails.py` before anything is queued.
Response: `{ "action_id", "status": "queued" | "pending_approval" | "refused", "reason" }`.

`GET /api/v1/response/endpoint-actions/{action_id}` →
`status`: `pending_approval | queued | delivered | executed | failed | rejected | expired`, plus the ack.

### Delivery (called by the agent)
`GET /api/v1/nodes/commands?wait=25` — node token. Long-poll: returns as soon as
a command is queued for this node, or an empty list after `wait` seconds.
Response: `{ "commands": [ <envelope>, … ] }`. A command is marked `delivered`
when returned; delivered-but-unacked commands are re-offered until they expire.

### Acknowledge (called by the agent)
`POST /api/v1/nodes/commands/{id}/ack` — node token.

```json
{ "result": "executed" | "failed" | "rejected_signature" | "rejected_mismatch"
            | "rejected_expired" | "rejected_replay" | "rejected_unknown_action",
  "detail": "…", "executed_at": "RFC 3339" }
```

The server records the ack against the action and in the audit log. An ack for a
command addressed to a different node is refused.

## 6. Relaying through another transport

A second channel may carry the **same envelope, byte for byte**. The agent
verifies it identically and the nonce prevents double execution. The ack still
goes to the AEGIS ack endpoint.

## 7. Enrollment modes

- `AEGIS_ENROLLMENT_MODE=dashboard` (default, public): an operator approves the
  enrollment code in the AEGIS dashboard.
- `AEGIS_ENROLLMENT_MODE=external`: AEGIS issues no node token until an external
  approver holding a service credential with role `node_approver` calls
  `POST /api/v1/nodes/enroll` with `{code, hostname, approved_by, approval_ref}`.
  The AEGIS dashboard cannot approve in this mode. `approved_by` and
  `approval_ref` are written to the audit log.
