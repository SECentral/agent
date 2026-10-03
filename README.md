# SECentral Agent

The SECentral agent is a Go collector for SELinux audit events.

## What it does

- Assembles related audit records into events and preserves their raw evidence.
- Spools events locally and delivers them to the server, retaining them across
  temporary network outages.
- Sends host and SELinux state separately as heartbeat checkpoints.
- Uploads the loaded SELinux policy artifact when requested by the server.

## Requirements

- Go version specified in `go.mod`.
- Linux with audit event access for normal collection. Most unit tests do not
  require SELinux to be enabled.

## Test and format

```sh
gofmt -w $(git ls-files '*.go')
go test ./...
```

See [TEST.md](TEST.md) for contributor testing guidance. See the
SECentral server repository for the ingestion API and self-hosted deployment
instructions.

An [example hardened systemd service unit](contrib/systemd/secentral-agent.service)
is available for Linux deployments; review its permissions and paths for your
host before using it. It runs as root for audit access and SELinux policy
inspection; running the agent unprivileged is not currently supported. Keep its
environment file and spool restricted to the service, even if you use a
dedicated account to own them.
