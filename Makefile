GOLANGCI_LINT ?= go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.13.2

.PHONY: build boot test integration e2e-qemu vet lint check clean

build:
	go build -o bin/infra-box ./cmd/infra-box

boot: build
	sudo ./bin/infra-box -config config.example.json

test:
	go test -race ./...

integration:
	go test -race -tags=integration ./...

e2e-qemu:
	bash tests/e2e-qemu/prepare.sh
	sudo -- python3 -B tests/e2e-qemu/run.py

vet:
	go vet ./...

lint:
	$(GOLANGCI_LINT) run ./...
	$(GOLANGCI_LINT) fmt --diff

check: test integration vet lint

clean:
	rm -f bin/infra-box
