# syntax=docker/dockerfile:1.7
#
# The registry serves plain HTTP on PORT; put a TLS-terminating proxy in front
# of it. Its database and service identity live in BRR_DATA_DIR (/data), so
# mount a persistent volume there: losing it loses the service's identity.

FROM golang:1.26-alpine AS build
RUN apk add --no-cache git ca-certificates
WORKDIR /src
ENV CGO_ENABLED=0 GOOS=linux GOTOOLCHAIN=auto
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go build -trimpath -ldflags="-s -w" -o /out/brr ./cmd/brr

FROM alpine:3.21 AS runtime
RUN apk add --no-cache ca-certificates su-exec && adduser -D -u 10001 brr
COPY --from=build /out/brr /usr/local/bin/brr
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
# A platform volume is usually owned by root, so the entrypoint starts as root,
# hands the data directory to the brr user, and drops to that user before the
# registry runs.
ENV BRR_DATA_DIR=/data PORT=8093
EXPOSE 8093
ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
