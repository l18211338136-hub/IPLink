.PHONY: all build test test-race vet fmt clean

BIN_DIR := bin

all: fmt vet test build

fmt:
	gofmt -w cmd internal pkg test

vet:
	go vet ./...

test:
	go test -v ./...

test-race:
	go test -race ./...

build:
	go build -o $(BIN_DIR)/iplink-server ./cmd/server
	go build -o $(BIN_DIR)/iplink-client ./cmd/client

build-all:
	GOOS=linux GOARCH=amd64 go build -o $(BIN_DIR)/iplink-server-linux-amd64 ./cmd/server
	GOOS=linux GOARCH=amd64 go build -o $(BIN_DIR)/iplink-client-linux-amd64 ./cmd/client
	GOOS=linux GOARCH=arm64 go build -o $(BIN_DIR)/iplink-server-linux-arm64 ./cmd/server
	GOOS=linux GOARCH=arm64 go build -o $(BIN_DIR)/iplink-client-linux-arm64 ./cmd/client
	GOOS=windows GOARCH=amd64 go build -o $(BIN_DIR)/iplink-server-windows-amd64.exe ./cmd/server
	GOOS=windows GOARCH=amd64 go build -o $(BIN_DIR)/iplink-client-windows-amd64.exe ./cmd/client

clean:
	rm -rf $(BIN_DIR)
