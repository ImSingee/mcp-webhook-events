# mcp-webhook-events: make build | dev | test | test-ui | lint

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X github.com/ImSingee/mcp-webhook-events/internal/version.Version=$(VERSION)
BIN := bin

.PHONY: build dev test test-ui lint fmt clean docker

## build: both binaries into ./bin, static (CGO_ENABLED=0)
build:
	CGO_ENABLED=0 go build -trimpath -ldflags '$(LDFLAGS)' -o $(BIN)/mwe-server ./cmd/mwe-server
	CGO_ENABLED=0 go build -trimpath -ldflags '$(LDFLAGS)' -o $(BIN)/mwe ./cmd/mwe

## dev: run the server with the UI read from disk (-tags dev); set MWE_PASSWORD
dev:
	MWE_PUBLIC_URL=$${MWE_PUBLIC_URL:-http://localhost:8080} MWE_PASSWORD=$${MWE_PASSWORD:-dev} \
	MWE_DATA_DIR=$${MWE_DATA_DIR:-./data} MWE_ALLOW_PRIVATE_CALLBACKS=$${MWE_ALLOW_PRIVATE_CALLBACKS:-true} \
	MWE_LOG_LEVEL=$${MWE_LOG_LEVEL:-debug} go run -tags dev ./cmd/mwe-server

## test: vet and the race-enabled test suite
test:
	go vet ./...
	go test -race ./...

## test-ui: the UI's Playwright tests (tests/ui), when there are any
test-ui:
	@if [ -d tests/ui ]; then cd tests/ui && npx playwright test; else echo "no UI tests in tests/ui"; fi

## lint: formatting and vet, including the Linux build
lint:
	@out=$$(gofmt -l .); if [ -n "$$out" ]; then echo "gofmt needed:"; echo "$$out"; exit 1; fi
	go vet ./...
	GOOS=linux go vet ./...

fmt:
	gofmt -w .

docker:
	docker build --build-arg VERSION=$(VERSION) -t mcp-webhook-events:$(VERSION) .

clean:
	rm -rf $(BIN)
