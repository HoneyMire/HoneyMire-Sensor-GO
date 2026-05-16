# Dockerfile for the HoneyMire Go honeypot.

FROM golang:1.25-alpine AS builder
WORKDIR /src

COPY honeypot/go.mod honeypot/go.sum honeypot/main.go ./
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/honeypot .

FROM alpine:3.20
WORKDIR /data

COPY --from=builder /out/honeypot /app/honeypot
RUN apk add --no-cache ca-certificates libcap \
    && addgroup -S honeymire \
    && adduser -S -G honeymire honeymire \
    && mkdir -p /data/certs \
    && chown -R honeymire:honeymire /data \
    && setcap 'cap_net_bind_service=+ep' /app/honeypot

USER honeymire
ENV HONEYMIRE_TELNET_LISTEN=:23 \
    HONEYMIRE_SSH_LISTEN=:22 \
    HONEYMIRE_DASHBOARD=:8080 \
    HONEYMIRE_CERT_CACHE=/data/certs
EXPOSE 80 443 2323 2222 8080
ENTRYPOINT ["/app/honeypot"]
