# Builds rt2wg and bundles it with the systemd unit and the install script:
#
#   make                          # for this machine's architecture
#   make GOARCH=arm64             # 64-bit Raspberry Pi OS
#   make GOARCH=arm GOARM=7       # 32-bit Raspberry Pi OS on Pi 2, 3, 4, Zero 2 W
#   make GOARCH=arm GOARM=6       # Pi 1 and Zero / Zero W
#
# The tarball lands in dist/; on the target, unpack it and run
# ./install.sh as root in the unpacked directory.

GOARCH ?= $(shell go env GOARCH)
GOARM ?=

# A tag on HEAD (v1.2.3) is the version; otherwise the commit time.
VERSION := $(shell git describe --tags --exact-match 2>/dev/null | sed 's/^v//')
ifeq ($(VERSION),)
VERSION := 0.0.0_git$(shell git log -1 --format=%cd --date=format:%Y%m%d%H%M%S)
endif

# Named after the Go target (amd64, arm64, armv7, ...), as the OpenWrt apk is.
TARGET := $(GOARCH)$(if $(GOARM),v$(GOARM))
NAME := rt2wg-$(VERSION)-linux-$(TARGET)
STAGE := dist/$(NAME)
TARBALL := dist/$(NAME).tar.gz

.PHONY: all build test clean

all: $(TARBALL)

# Always rerun go build; its cache makes an up-to-date build cheap.
build:
	mkdir -p $(STAGE)
	CGO_ENABLED=0 GOOS=linux GOARCH=$(GOARCH) GOARM=$(GOARM) \
		go build -trimpath -ldflags='-s -w' -o $(STAGE)/rt2wg ./cmd/rt2wg

$(TARBALL): build deploy/rt2wg@.service deploy/install.sh
	install -m 0644 deploy/rt2wg@.service $(STAGE)/
	install -m 0755 deploy/install.sh $(STAGE)/
	tar -czf $@ -C dist --owner=0 --group=0 $(NAME)
	@echo $@

test:
	go test ./...

clean:
	rm -rf dist/rt2wg-*-linux-*
