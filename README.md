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

## Run The Published Image

```sh
docker run -d \
  --name honeymire-sensor-go \
  --restart unless-stopped \
  -e HONEYMIRE_HUB_URL=https://hub.example/api/v1/ingest \
  -e HONEYMIRE_TOKEN=hop_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx \
  -e HONEYMIRE_DEVICE_ID=hp-vps-1 \
  -e HONEYMIRE_BOARD=docker-edge \
  -e HONEYMIRE_DISPLAY=none \
  -e HONEYMIRE_TELNET_LISTEN=:23 \
  -e HONEYMIRE_SSH_LISTEN=:22 \
  -e HONEYMIRE_DASHBOARD=:8080 \
  -e HONEYMIRE_DASHBOARD_AUTH=change-this-dashboard-token \
  -e HONEYMIRE_IP_COOLDOWN=3m \
  -e HONEYMIRE_LOGIN_ATTEMPTS_BEFORE_ACCEPT=3 \
  -p 23:23 \
  -p 22:22 \
  -p 8080:8080 \
  -v honeymire_sensor_state:/data \
  ghcr.io/honeymire/honeymire-sensor-go:latest
```

For HTTPS dashboard support with Let's Encrypt, also publish ports 80 and 443
and set `HONEYMIRE_DASHBOARD_URL` or `DASHBOARD_URL` to a DNS name pointing at
the host.

## Published Image

Images are published to GitHub Container Registry:

```sh
docker pull ghcr.io/honeymire/honeymire-sensor-go:latest
```

The workflow also publishes branch, tag, and commit-SHA tags. Public GHCR
packages are free according to GitHub Packages billing, and GitHub currently
lists Container Registry storage and bandwidth as free.

If `docker pull` returns `unauthorized`, the package is still private or has not
been published yet. After the first successful workflow run, open the package on
GitHub, go to **Package settings**, and change its visibility to **Public**.
Private pulls require a GitHub token with `read:packages`:

```sh
echo "$GITHUB_TOKEN" | docker login ghcr.io -u YOUR_GITHUB_USER --password-stdin
docker pull ghcr.io/honeymire/honeymire-sensor-go:latest
```

## Build Locally

```sh
cd honeypot
go test ./...
go build .
```

The produced `honeypot` binary is a local build artifact and should not be
committed.
