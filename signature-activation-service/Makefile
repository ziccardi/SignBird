.PHONY: run build test test-integration check

run:
	go run ./cmd/signature-activation-service

build:
	go build ./cmd/signature-activation-service

test:
	go test ./...

test-integration:
	@test -n "$$SIGNBIRD_TEST_DATABASE_URL" || { echo "Set SIGNBIRD_TEST_DATABASE_URL"; exit 1; }
	go test -count=1 -v ./...

check: test
	go vet ./...
	go build ./...
