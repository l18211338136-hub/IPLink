FROM golang:1.26-alpine AS builder
WORKDIR /src
COPY go.mod ./
COPY cmd ./cmd
COPY internal ./internal
COPY pkg ./pkg
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /out/iplink-server ./cmd/server

FROM alpine:3.20
RUN apk add --no-cache ca-certificates
WORKDIR /app
COPY --from=builder /out/iplink-server /usr/local/bin/iplink-server
COPY configs/server.json.example /etc/iplink/server.json
EXPOSE 29000/tcp 29001/udp 29002/udp 28080/tcp
ENTRYPOINT ["iplink-server", "start", "--config", "/etc/iplink/server.json"]
