# go source files, ignore vendor directory
GO_SRC = $(shell find ${MKFILE_PATH} -type f -name '*.go' -not -path "./vendor/*")
# CURRENT_DIR=$(shell pwd)

# ifeq ($(OS),Windows_NT)
#     detected_OS := Windows
# else
#     detected_OS := $(shell uname -s)
# endif

.DEFAULT_GOAL := build

vendor: Gopkg.toml Gopkg.lock
	dep ensure

.PHONY: build
build: oauth-proxy oauth-proxy.exe

oauth-proxy: ${GO_SRC} vendor
	go build -o oauth-proxy ./cmd

oauth-proxy.exe: ${GO_SRC} vendor
	GOOS=windows go build -o oauth-proxy.exe ./cmd

.PHONY: test
test:
	go test ./...

.PHONY: clean
clean:
	rm -f oauth-proxy
	rm -f oauth-proxy.exe

# vim: syntax=make ts=4 sw=4 sts=4 sr noet
