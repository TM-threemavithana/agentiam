.PHONY: build test test-integration bench lint clean run

BINARY_NAME=agentiam
CMD_PATH=./cmd/agentiam

build-ui:
	@echo "==> Building Observability Dashboard..."
	cd web && npm install && npm run build

build: build-ui
	@echo "==> Building AgentIAM Proxy..."
	go build -o bin/$(BINARY_NAME) $(CMD_PATH)

test:
	@echo "==> Running tests..."
	go test -v ./...

test-integration:
	@echo "==> Running database integration tests..."
	go test -v -tags integration -count=1 -timeout 10m ./internal/proxy

bench:
	@echo "==> Running benchmarks..."
	go test -bench . ./...

lint:
	@echo "==> Running golangci-lint..."
	golangci-lint run ./...

clean:
	@echo "==> Cleaning up..."
	go clean
	rm -rf bin/

run: build
	@echo "==> Running AgentIAM Proxy..."
	./bin/$(BINARY_NAME)
