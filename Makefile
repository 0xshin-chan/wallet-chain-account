GITCOMMIT := $(shell git rev-parse HEAD)
GITDATE := $(shell git show -s --format='%ct')

LDFLAGSSTRING +=-X main.GitCommit=$(GITCOMMIT)
LDFLAGSSTRING +=-X main.GitDate=$(GITDATE)
LDFLAGS := -ldflags "$(LDFLAGSSTRING)"

wallet-chain-account:
	env GO111MODULE=on go build -v $(LDFLAGS) ./cmd/wallet-chain-account

clean:
	rm wallet-chain-account

test:
	go test -v ./..

lint:
	golangci-lint run ./...


.PHONY: \
	wallet-chain-account \
	clean \
	test \
	lint