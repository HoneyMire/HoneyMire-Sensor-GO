# HoneyMire Sensor GO

A Docker-runnable HoneyMire software sensor for VPS, lab, and container-based
deployments. It exposes Telnet and SSH honeypot listeners, captures attacker
sessions, serves an optional live dashboard, and reports attacks to a HoneyMire
Hub.

Reports are emitted using the canonical
[`honeymire.attack/v1` protocol](https://github.com/HoneyMire/HoneyMire-Protocol).
That protocol repository is the source of truth for the ingest payload, Hub
compatibility rules, and first-party client libraries.

## Run With Docker Compose

Set the Hub endpoint and honeypot bearer token, then start the sensor:

```sh
export HONEYMIRE_HUB_URL=https://hub.example/api/v1/ingest
export HONEYMIRE_TOKEN=hop_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
./start.sh
```

The compose setup exposes Telnet, SSH, HTTP/HTTPS dashboard support, and the
local dashboard port. See `docker-compose.yml` for the full environment surface.

## Published Image

Images are published to GitHub Container Registry:

```sh
docker pull ghcr.io/honeymire/honeymire-sensor-go:latest
```

The workflow also publishes branch, tag, and commit-SHA tags. Public GHCR
packages are free according to GitHub Packages billing, and GitHub currently
lists Container Registry storage and bandwidth as free.

## Build Locally

```sh
cd honeypot
go test ./...
go build .
```

The produced `honeypot` binary is a local build artifact and should not be
committed.
