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
  metadata, NFTInputs, NetPolicy/NodeGeo intent state, proxy-core
  inbound/user/node-profile/usage intent state, approval-linked tasks, task
  results, audit events, KV entries, static objects, Worker scripts, and
  approvals.

## Proto Contracts

`proto/lattice/v1` is the source of truth for the next API boundary:

- `common.proto` - redacted views, live metrics, HostFacts, NodeView runtime
  metadata, redacted NodeIPConfigView, MachineView, NFTInputsView,
  DNSDeploymentView, NetPolicyView, NetPolicyGraph, ProxyInboundView,
  ProxyUserView, ProxyNodeProfileView, ProxyUsageSnapshot, paging, audit
  metadata.
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
`invalid_task_lease`, and `task_output_limit_exceeded`; approval workflow codes
include `approval_stale` and `agent_update_noop`. Clients should treat these
codes as stable automation signals and avoid branching on localized messages.
Rendered approvals also expose machine-readable stale metadata: use
`Approval.Stale` and `Approval.StaleCode` instead of parsing the operator-facing
`Reason`. The agent-update stale code is
`model.ApprovalStaleAgentUpdatePolicyChanged`.

Agent authentication is transport metadata: node tokens belong in the
`Authorization: Bearer` header and are intentionally absent from proto request
messages.

`DNSDeploymentView` intentionally separates CoreDNS/nft service apply status
(`last_applied_at` / `last_error`) from Cloudflare hostname publication status
(`last_published_at` / `last_publish_error`). Clients must not overload service
status fields to infer DDNS publication health.

Proxy-core contracts are also deliberately redacted. `ProxyInboundView` exposes
only `has_reality_private_key`; `ProxyUserView` exposes only `has_uuid`,
`has_password`, and `has_sub_token`. Clients must never require raw
Reality/private user credentials from list/read APIs; one-time create/rotate
responses should be modeled explicitly when those APIs land.

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
leased-task payloads. Node IP discovery overrides are represented by a
redacted `NodeIPConfigView`: clients can confirm `mode`, static IPs, resolvers,
and `script_sha256`, but never receive the script body from a read-facing node
view.

## Development

```sh
go test ./...
```
