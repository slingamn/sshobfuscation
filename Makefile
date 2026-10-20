GIT_COMMIT := $(shell git rev-parse HEAD 2> /dev/null)
GIT_TAG := $(shell git tag --points-at HEAD 2> /dev/null | head -n 1)

# disable linking against native libc / libpthread by default;
# this can be overridden by passing CGO_ENABLED=1 to make
export CGO_ENABLED ?= 0

.PHONY: all
all: build

.PHONY: build
build:
	mkdir -p ./bin
	go build -v -o ./bin ./cmd/...

test:
	go vet ./...
	go test ./...
