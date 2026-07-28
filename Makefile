BIN     := kiro-secops
VERSION ?= 1.1.0
LDFLAGS := -s -w -X kiro-secops/internal/app.version=$(VERSION)
DIST    := dist
PLATFORMS := darwin/amd64 darwin/arm64 linux/amd64 linux/arm64 windows/amd64
MAIN    := ./cmd/kiro-secops

.PHONY: build vet fmt test dist checksums release-check release-snapshot install-local clean

build: ## compile the binary for the current OS
	go build -trimpath -ldflags '$(LDFLAGS)' -o $(BIN) $(MAIN)

vet: ## go vet + formatting check
	go vet ./...
	@test -z "$$(gofmt -l cmd internal)" || { echo 'gofmt: unformatted files:'; gofmt -l cmd internal; exit 1; }

fmt: ## format the code
	gofmt -w cmd internal

test: ## run the tests
	go test ./...

dist: ## cross-compile for all targets (darwin/linux/windows)
	@mkdir -p $(DIST)
	@for p in $(PLATFORMS); do \
	  os=$${p%/*}; arch=$${p#*/}; ext=; [ "$$os" = windows ] && ext=.exe; \
	  out=$(DIST)/$(BIN)-$$os-$$arch$$ext; \
	  echo "-> $$out"; \
	  GOOS=$$os GOARCH=$$arch CGO_ENABLED=0 go build -trimpath -ldflags '$(LDFLAGS)' -o $$out $(MAIN) || exit 1; \
	done

checksums: dist ## generate SHA256SUMS of the binaries (basis for signing/SLSA)
	cd $(DIST) && shasum -a 256 * > SHA256SUMS && cat SHA256SUMS

install-local: build ## install the global config using the freshly compiled binary
	./$(BIN) install

release-check: ## validate .goreleaser.yaml (requires goreleaser)
	goreleaser check

release-snapshot: ## build a local release in dist/ (does not publish)
	goreleaser release --snapshot --clean

clean:
	rm -f $(BIN); rm -rf $(DIST)
