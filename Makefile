.PHONY: build build-all build-ui test race test-integration bench lint vet fmt fmt-check verify vulncheck check-pgproto clean run ci-local

BINARY_NAME=agentiam
CMD_PATH=./cmd/agentiam

build-ui:
	@echo "==> Building Observability Dashboard..."
	cd web && npm install && npm run build

build: build-ui
	@echo "==> Building AgentIAM Proxy..."
	go build -o bin/$(BINARY_NAME) $(CMD_PATH)

build-all:
	@echo "==> Building all AgentIAM binaries..."
	go build -v ./cmd/...

test:
	@echo "==> Running unit and regression tests..."
	go test -count=1 -v ./...

race:
	@echo "==> Running race detection tests..."
	go test -race -count=1 ./...

test-integration:
	@echo "==> Running PostgreSQL integration tests..."
	go test -v -tags=integration -run "TestViewMaskingIntegration|TestProxyIntegration|TestTLSUpgradeAndEnforcement" ./internal/proxy

bench:
	@echo "==> Running benchmarks..."
	go test -bench . ./...

lint:
	@echo "==> Running golangci-lint..."
	golangci-lint run ./...

vet:
	@echo "==> Running go vet..."
	go vet ./...

fmt:
	@echo "==> Formatting Go files with gofmt..."
	gofmt -w .

fmt-check:
	@echo "==> Checking Go formatting..."
	@unformatted=$$(gofmt -l .); \
	if [ -n "$$unformatted" ]; then \
		echo "Unformatted Go source files detected:"; \
		echo "$$unformatted"; \
		exit 1; \
	fi

verify:
	@echo "==> Verifying Go module dependencies..."
	go mod verify

check-pgproto:
	@echo "==> Verifying absence of retired pgproto3/v2 dependency..."
	@if grep -q "github.com/jackc/pgproto3" go.mod go.sum 2>/dev/null; then \
		echo "CRITICAL: Retired dependency github.com/jackc/pgproto3 detected in dependency graph!"; \
		exit 1; \
	fi; \
	echo "Verified: pgproto3/v2 is absent."

vulncheck:
	@echo "==> Running govulncheck..."
	govulncheck ./...

clean:
	@echo "==> Cleaning up..."
	go clean
	rm -rf bin/

run: build
	@echo "==> Running AgentIAM Proxy..."
	./bin/$(BINARY_NAME)

ci-local: fmt-check verify check-pgproto vet lint test build-all
	@echo "==> Local CI quality gates passed successfully."
