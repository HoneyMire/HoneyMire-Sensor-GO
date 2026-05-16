#!/bin/sh
set -eu

# Required:
#   HONEYMIRE_HUB_URL  Hub ingest endpoint, including /api/v1/ingest
#   HONEYMIRE_TOKEN    Honeypot bearer token from the Hub
#
# Recommended for public dashboard HTTPS:
#   DASHBOARD_URL      DNS name pointed at this VPS, e.g. honeypot.example.com
#   DASHBOARD_AUTH     Token/password required to open the dashboard
#
# Optional:
#   HONEYMIRE_DEVICE_ID        Defaults to hp-$(hostname)
#   HONEYMIRE_TELNET_LISTEN    Defaults to :23
#   HONEYMIRE_SSH_LISTEN       Defaults to :22
#   HONEYMIRE_IP_COOLDOWN      Defaults to 3m; suppresses repeat reports per IP
#   HONEYMIRE_LOGIN_ATTEMPTS_BEFORE_ACCEPT Defaults to 3

if [ -z "${HONEYMIRE_HUB_URL:-}" ]; then
  echo "Missing HONEYMIRE_HUB_URL, e.g. https://hub.example.com/api/v1/ingest" >&2
  exit 2
fi

if [ -z "${HONEYMIRE_TOKEN:-}" ]; then
  echo "Missing HONEYMIRE_TOKEN, e.g. hop_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" >&2
  exit 2
fi

export HONEYMIRE_DEVICE_ID="${HONEYMIRE_DEVICE_ID:-hp-$(hostname | tr '[:upper:]' '[:lower:]' | tr -cd 'a-z0-9-')}"
export HONEYMIRE_TELNET_LISTEN="${HONEYMIRE_TELNET_LISTEN:-:23}"
export HONEYMIRE_SSH_LISTEN="${HONEYMIRE_SSH_LISTEN:-:22}"
export HONEYMIRE_DASHBOARD="${HONEYMIRE_DASHBOARD:-:8080}"
export HONEYMIRE_IP_COOLDOWN="${HONEYMIRE_IP_COOLDOWN:-3m}"
export HONEYMIRE_LOGIN_ATTEMPTS_BEFORE_ACCEPT="${HONEYMIRE_LOGIN_ATTEMPTS_BEFORE_ACCEPT:-3}"

if [ -n "${DASHBOARD_URL:-}" ] || [ -n "${HONEYMIRE_DASHBOARD_URL:-}" ]; then
  echo "Dashboard HTTPS enabled for ${DASHBOARD_URL:-$HONEYMIRE_DASHBOARD_URL}"
  echo "Make sure ports 80 and 443 are open and DNS points to this VPS."
else
  echo "DASHBOARD_URL not set; dashboard will use plain HTTP on ${HONEYMIRE_DASHBOARD}."
fi

if [ -z "${DASHBOARD_AUTH:-}" ] && [ -z "${HONEYMIRE_DASHBOARD_AUTH:-}" ]; then
  echo "Warning: DASHBOARD_AUTH is not set; dashboard will be unauthenticated." >&2
fi

docker compose up -d --build
