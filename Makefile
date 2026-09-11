GOLANGCI_LINT ?= go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.13.2

.PHONY: build test integration vet lint check clean

build:
	go build -o bin/infra-box ./cmd/infra-box

test:
	go test -race ./...

integration:
	go test -race -tags=integration ./...

vet:
	go vet ./...

lint:
	$(GOLANGCI_LINT) run ./...
	$(GOLANGCI_LINT) fmt --diff

check: test integration vet lint

clean:
	rm -f bin/infra-box
