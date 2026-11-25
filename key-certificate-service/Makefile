.PHONY: run build test test-integration check generate migrate

run:
	go run ./cmd/key-certificate-service

build:
	go build -o key-certificate-service ./cmd/key-certificate-service

test:
	go test ./...

test-integration:
	@test -n "$$SIGNBIRD_TEST_DATABASE_URL" || { echo "Set SIGNBIRD_TEST_DATABASE_URL"; exit 1; }
	go test -count=1 -v ./...

check: test
	go vet ./...
	go build ./...

generate:
	sqlc generate

migrate:
	go run ./cmd/key-certificate-service migrate
