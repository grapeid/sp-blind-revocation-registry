FROM golang:1.24-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /brr ./cmd/brr

FROM alpine:3.21
RUN apk add --no-cache ca-certificates
COPY --from=build /brr /usr/local/bin/brr
ENV BRR_DATA_DIR=/data PORT=8093
EXPOSE 8093
ENTRYPOINT ["brr"]