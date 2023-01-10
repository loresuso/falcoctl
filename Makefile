SHELL=/bin/bash -o pipefail
# Get the currently used golang install path (in GOPATH/bin, unless GOBIN is set)
ifeq (,$(shell go env GOBIN))
GOBIN=$(shell go env GOPATH)/bin
else
GOBIN=$(shell go env GOBIN)
endif

GO ?= go
DOCKER ?= docker

# version settings
RELEASE?=$(shell git rev-parse --short HEAD)
COMMIT?=$(shell git rev-parse --short HEAD)
BUILD_DATE?=$(shell date -u '+%Y-%m-%d_%H:%M:%S')
PROJECT?=github.com/falcosecurity/falcoctl

# todo(leogr): re-enable race when CLI tests can run with race enabled
TEST_FLAGS ?= -v -cover# -race 

.PHONY: falcoctl
falcoctl:
	$(GO) build -ldflags \
    "-X ${PROJECT}/pkg/version.semVersion=${RELEASE} \
    -X ${PROJECT}/pkg/version.gitCommit=${COMMIT} \
    -X ${PROJECT}/pkg/version.buildDate=${BUILD_DATE}" \
    -o ./bin/falcoctl .

.PHONY: test
test:
	$(GO) vet ./...
	$(GO) test ${TEST_FLAGS} ./...

.PHONY: daemon
daemon:
	$(GO) build -o ./bin/falcoctld ./cmd/falcoctld/*.go 

# Install gci if not available
gci:
ifeq (, $(shell which gci))
	@go install github.com/daixiang0/gci@v0.9.0
GCI=$(GOBIN)/gci
else
GCI=$(shell which gci)
endif

# Install addlicense if not available
addlicense:
ifeq (, $(shell which addlicense))
	@go install github.com/google/addlicense@v1.0.0
ADDLICENSE=$(GOBIN)/addlicense
else
ADDLICENSE=$(shell which addlicense)
endif

# Run go fmt against code and add the licence header
fmt: gci addlicense
	go mod tidy
	go fmt ./...
	find . -type f -name '*.go' -a -exec $(GCI) write -s standard -s default -s "prefix(github.com/falcosecurity/falcoctl)" {} \;
	find . -type f -name '*.go' -exec $(ADDLICENSE) -l apache -c "The Falco Authors" -y "$(shell date +%Y)" {} \;

# Install golangci-lint if not available
golangci-lint:
ifeq (, $(shell which golangci-lint))
	@go install github.com/golangci/golangci-lint/cmd/golangci-lint@v1.48
GOLANGCILINT=$(GOBIN)/golangci-lint
else
GOLANGCILINT=$(shell which golangci-lint)
endif

# It works when called in a branch different than main.
# "--new-from-rev REV Show only new issues created after git revision REV"
lint: golangci-lint
	$(GOLANGCILINT) run --new-from-rev main

docker:
	$(DOCKER) build -f ./build/Dockerfile .
