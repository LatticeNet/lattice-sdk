# lattice-sdk

Shared Go models for the Lattice ecosystem.

This package is intentionally small. It currently contains domain structures
shared between `lattice-server` and `lattice-node-agent`, plus protocol
contracts under `proto/lattice/v1`.

## Module

```txt
github.com/LatticeNet/lattice-sdk
```

## Packages

- `model` - users, tokens, nodes, metrics, HostFacts, MachineProfile inventory
  metadata, NFTInputs, NetPolicy/NodeGeo intent state, tasks, task results,
  audit events, KV entries, static objects, Worker scripts, and approvals.

## Proto Contracts

`proto/lattice/v1` is the source of truth for the next API boundary:

- `common.proto` - redacted views, metrics, HostFacts, MachineView,
  NFTInputsView, NetPolicyView, NetPolicyGraph, paging, audit metadata.
- `control_plane.proto` - dashboard/operator APIs.
- `agent.proto` - node-agent polling, reporting, task leasing, monitor reporting.
- `plugin.proto` - plugin manifests, capability risk, publisher identity,
  artifact digest/signature fields, and stdio/gRPC payloads.

Errors are part of the contract. HTTP JSON APIs return the `model.APIError`
shape and proto APIs reserve `ApiError` with `code`, `message`, and
`request_id`; clients must branch on `code` rather than scraping message text.
Every HTTP response also carries `X-Lattice-Request-ID`, matching
`ApiError.request_id` on failures and `AuditEvent.correlation_id` on correlated
authorization denial, authenticated allow, login, and agent task/event audit
records across node, task, token, KV/static, Worker, notification, monitor,
DDNS, tunnel, and network approval changes.
Audit listing is a paged contract: filter by node, actor, token, action,
decision, scope, or `correlation_id`, and page results instead of assuming
unbounded history can be fetched in one call. The current JSON server keeps
`/api/audit` array-compatible when called without query parameters, while
filtered calls return `{events,total,limit,offset}`.
The `model.APIError*` constants are the canonical JSON/proto code strings.
`message` is public and may be deliberately generic for server-side failures.
Security-sensitive codes include `capability_denied`, `invalid_node_token`,
`invalid_task_lease`, and `task_output_limit_exceeded`; clients should treat
them as stable automation signals.

Agent authentication is transport metadata: node tokens belong in the
`Authorization: Bearer` header and are intentionally absent from proto request
messages.

Plugin integrity is also part of the contract. High-risk system plugins should
publish `publisher`, `digest_sha256`, and `signature_ed25519`; loaders verify
the digest against the artifact bytes and the Ed25519 signature against an
operator-managed trusted publisher key.

These files are intentionally checked in before generated code. The current MVP
still serves JSON, but new API work should first update the proto contract and
then generate Go/TypeScript bindings in a later Buf/protoc step.

The contract test rejects secret storage fields such as token/password hashes,
provider credentials, MachineProfile console/detail links, full task script
bodies in control-plane responses, and control-plane metadata in agent
leased-task payloads.

## Development

```sh
go test ./...
```
