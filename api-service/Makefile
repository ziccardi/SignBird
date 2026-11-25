.PHONY: run build test check generate

run:
	go run ./cmd/api-service

build:
	go build -o api-service ./cmd/api-service

test:
	go test ./...

check: test
	go vet ./...
	go build ./...

generate:
	go generate ./...
