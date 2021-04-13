# Thank you Influxdata for the foundation of this file!

PROG := able

SHELL := bash

GIT ?= git
GO ?= go
PROTOC ?= protoc
FPM ?= fpm

DOCKER ?= docker
DOCKER_REGISTRY ?= hub.docker.com

GOPATH := $(shell $(GO) env GOPATH)
GOFILES := $(shell $(GIT) ls-files '*.go' | grep -v ^protos)

VET_SPEC  := $(shell $(GO) list ./...)
TEST_SPEC := $(shell $(GO) list ./...)
FMT_SPEC := $(shell $(GIT) ls-files '*.go')

GIT_BRANCH := $(shell $(GIT) rev-parse --abbrev-ref HEAD)
GIT_COMMIT := $(shell $(GIT) rev-parse --short=8 HEAD)
GIT_TAG := $(shell $(GIT) describe --exact-match --tags 2>/dev/null)

DATE := $(shell date +%Y%m%d-%H%M%S)

ifeq ($(GIT_TAG),)
	version := $(GIT_BRANCH)~$(GIT_COMMIT)
	rpm_version := $(version)-0
	rpm_iteration := 0
	deb_version := $(version)-0
	deb_iteration := 0
	tar_version := $(version)
else
	version := $(GIT_TAG:v%=%)
	rpm_version := $(version)-1
	rpm_iteration := 1
	deb_version := $(version)-1
	deb_iteration := 1
	tar_version := $(version)
endif

LDFLAGS := $(LDFLAGS) -X main.branch=$(GIT_BRANCH) -X main.commit=$(GIT_COMMIT)
ifneq ($(GIT_TAG),)
	LDFLAGS += -X main.version=$(version)
endif

prefix ?= /usr/local
bindir ?= $(prefix)/bin
pkgdir ?= build/dist

.PHONY: help
help:
	@echo ''
	@echo 'Targets:'
	@echo '  all        - download modules, fmt, lint, and build binary'
	@echo '  pre        - download modules, fmt, lint, and vet'
	@echo '  mods       - download modules'
	@echo '  fmt        - check formatting'
	@echo '  lint       - check linting'
	@echo '  vet        - check vetting'
	@echo '  test       - run short unit tests'
	@echo '  clean      - delete build artifacts'
	@echo '  packages   - build all package targets'
	@echo '  docker     - build docker image'
	@echo ''
	@echo 'Package Targets:'
	@$(foreach dist,$(dists),echo "  $(dist)";)
	@echo ''

.PHONY: all
all: mods fmt lint build

.PHONY: pre
pre: mods fmt lint vet test

.PHONY: deps
deps:
	@cd $(GOPATH) && $(GO) get golang.org/x/tools/cmd/goimports
	@cd $(GOPATH) && $(GO) get golang.org/x/lint/golint

.PHONY: mods
mods:
	$(GO) mod download
	$(GO) mod verify
	$(GO) mod tidy
	@if ! git diff --quiet go.mod go.sum; then \
		echo "ERR: go mod tidy caused updates"; \
		exit 1; \
	fi

.PHONY: fmt
fmt: deps
	@echo "$(GOPATH)/bin/goimports -d \`$(GIT) ls-files '*.go'\`"
	@OUT=`$(GOPATH)/bin/goimports -d $(GOFILES) 2>&1`; \
	if [ "$$OUT" != "" ]; then \
		echo "ERR: goimports found issues"; \
		exit 1; \
	fi

.PHONY: lint
lint: deps
	$(GOPATH)/bin/golint -set_exit_status ./...

.PHONY: vet
vet:
	$(GO) vet $(VET_SPEC)

.PHONY: build
build:
	$(PROTOC) --go_out=. \
		--go_opt=paths=source_relative \
		--go-grpc_out=. \
		--go-grpc_opt=paths=source_relative \
		protos/echo/echo.proto
	$(GO) build -ldflags "$(LDFLAGS)" $(PROG)

.PHONY: test
test:
	$(GO) test -short -race $(TEST_SPEC)

.PHONY: clean
clean:
	rm -f $(PROG)
	rm -Rf build

.PHONY: install
install: $(buildbin)
	@mkdir -p $(DESTDIR)$(bindir)
	cp -f $(buildbin) $(DESTDIR)$(bindir)/

# Build per platform. This improves package performance by sharing the
# bin between deb/rpm/tar packages over building directly into the
# package directory.
$(buildbin):
	@mkdir -pv $(dir $@)
	go build -o $(dir $@) -ldflags "$(LDFLAGS)" $(PROG)

# all the archs we build debs for
debs := $(PROG)_$(deb_version)_amd64.deb

# all the archs we build rpms for
rpms := $(PROG)-$(rpm_version).x86_64.rpm

# all the archs we build tars for
tars := $(PROG)-$(tar_version)_linux_amd64.tar.gz
tars += $(PROG)-$(tar_version)_darwin_amd64.tar.gz

# all of the pks we will end up building
dists := $(debs) $(rpms) $(tars)

.PHONY: packages
packages: $(dists)

#
# rpm pkgs
#
rpm_amd64 := amd64
rpm_arch = $(rpm_$(GOARCH))

.PHONY: $(rpms)
$(rpms):
	@$(MAKE) install
	@mkdir -p $(pkgdir)
	$(FPM) --force \
		--log info \
		--architecture $(rpm_arch) \
		--input-type dir \
		--output-type rpm \
		--url https://github.com/tokenrain/$(PROG) \
		--license Apache-2.0 \
		--maintainer mselby@tokenrain.net \
		--description "binary for container orchestration proving" \
		--name $(PROG) \
		--version $(version) \
		--iteration $(rpm_iteration) \
        --chdir $(DESTDIR) \
		--package $(pkgdir)/$@

#
# deb pkgs
#
deb_amd64 := amd64
deb_arch = $(deb_$(GOARCH))

.PHONY: $(debs)
$(debs):
	@$(MAKE) install
	@mkdir -pv $(pkgdir)
	$(FPM) --force \
		--log info \
		--architecture $(deb_arch) \
		--input-type dir \
		--output-type deb \
		--url https://github.com/tokenrain/$(PROG) \
		--license Apache-2.0 \
		--maintainer mselby@tokenrain.net \
		--description "binary for container orchestration proving" \
		--name $(PROG) \
		--version $(version) \
		--iteration $(deb_iteration) \
		--chdir $(DESTDIR) \
		--package $(pkgdir)/$@

#
# tar pkgs
#
.PHONY: $(tars)
$(tars):
	@$(MAKE) install
	@mkdir -p $(pkgdir)
	tar --owner 0 --group 0 -czvf $(pkgdir)/$@ -C $(DESTDIR)$(bindir) .

#
# docker build
#
.PHONY: docker
docker: all
	@$(DOCKER) build \
		--tag $(DOCKER_REGISTRY)/$(PROG):$(version) \
		--build-arg VERSION=$(version) \
		--build-arg VCS_REF=$(GIT_COMMIT) \
		--build-arg BUILD_DATE=$(DATE) \
		.

#
# dynamic vars based on arch and pkg type
#
%amd64.deb %x86_64.rpm %linux_amd64.tar.gz: export GOOS := linux
%amd64.deb %x86_64.rpm %linux_amd64.tar.gz: export GOARCH := amd64

%darwin_amd64.tar.gz: export GOOS := darwin
%darwin_amd64.tar.gz: export GOARCH := amd64

%.deb: export pkg := deb

%.rpm: export pkg := rpm

%.tar.gz: export pkg := tar

%.deb %.rpm %.tar.gz: export DESTDIR = build/$(GOOS)-$(GOARCH)-$(pkg)/$(PROG)-$(version)
%.deb %.rpm %.tar.gz: export buildbin = build/$(GOOS)-$(GOARCH)/$(PROG)
%.deb %.rpm %.tar.gz: export LDFLAGS = -w -s
