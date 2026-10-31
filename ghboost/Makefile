BINARY=ghboost
BINDIR=bin

STAGEDIR=../files/usr/bin

GOOS ?= linux
GOARCH ?= arm64
CGO_ENABLED ?= 0
VERSION ?= dev
LDFLAGS=-s -w -trimpath -buildvcs=false -extldflags="-static" -X main.version=$(VERSION) -X main.statusVersion=$(VERSION)

.PHONY: build stage clean release

build:
	mkdir -p $(BINDIR)
	GOOS=$(GOOS) GOARCH=$(GOARCH) CGO_ENABLED=$(CGO_ENABLED) \
		go build -ldflags="$(LDFLAGS)" -o $(BINDIR)/$(BINARY)-$(GOOS)-$(GOARCH) .
	@echo "Built $(BINDIR)/$(BINARY)-$(GOOS)-$(GOARCH)"

stage: build
	mkdir -p $(STAGEDIR)
	install -m0755 $(BINDIR)/$(BINARY)-$(GOOS)-$(GOARCH) $(STAGEDIR)/$(BINARY)
	@file $(STAGEDIR)/$(BINARY) 2>/dev/null || true

clean:
	rm -rf $(BINDIR)

release:
	@$(MAKE) build GOOS=linux GOARCH=arm64
	@$(MAKE) build GOOS=linux GOARCH=amd64
