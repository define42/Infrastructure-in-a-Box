.PHONY: build test integration vet check clean

build:
	go build -o bin/infra-box ./cmd/infra-box

test:
	go test -race ./...

integration:
	go test -race -tags=integration ./...

vet:
	go vet ./...

check: test integration vet

clean:
	rm -f bin/infra-box
