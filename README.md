# SECentral Agent

The SECentral agent is a Go collector for SELinux audit events.

See [Contributing](CONTRIBUTING.md) for feedback and contribution guidelines.

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

## Install from COPR

RPM packages are available from
[mikelo2/secentral-agent](https://copr.fedorainfracloud.org/coprs/mikelo2/secentral-agent/).
On a COPR-supported Fedora or RHEL-family system, enable the repository and
install the agent:

```sh
sudo dnf copr enable mikelo2/secentral-agent
sudo dnf install secentral-agent
```

The standalone catalog-generation tool is packaged separately:

```sh
sudo dnf install secentral-agent-catalog-collector
```

The catalog collector is a development/reference-data tool, not part of normal
agent operation. See its [usage instructions](cmd/secentral-catalog-collector/README.md).
The agent requires configuration with a server endpoint and ingestion key before
it can deliver events. Review the package-provided service and configuration
files for your distribution before enabling the service.

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
