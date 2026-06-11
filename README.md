# lattice-sdk

Shared Go models for the Lattice ecosystem.

This package is intentionally small. It currently contains domain structures
shared between `lattice-server` and `lattice-node-agent`; future releases should
move generated protobuf/ConnectRPC definitions here.

## Module

```txt
github.com/LatticeNet/lattice-sdk
```

## Packages

- `model` - users, tokens, nodes, metrics, tasks, task results, audit events,
  KV entries, static objects, Worker scripts, and approvals.

## Development

```sh
go test ./...
```

