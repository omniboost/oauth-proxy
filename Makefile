# go source files, ignore vendor directory
GO_SRC = $(shell find ${MKFILE_PATH} -type f -name '*.go' -not -path "./vendor/*")
CURRENT_DIR=$(shell pwd)

.DEFAULT_GOAL := build

vendor: Gopkg.toml Gopkg.lock
	dep ensure

.PHONY: build
build: sms sms.exe

oauth-proxy: ${CURRENT_DIR} vendor ${CURRENT_DIR}
	go build -o oauth-proxy ./cmd

oauth-proxy.exe: ${CURRENT_DIR} vendor ${CURRENT_DIR}
	GOOS=windows go build -o oauth-proxy.exe ./cmd

.PHONY: test
test:
	go test ./...

.PHONY: clean
clean:
	rm -f oauth-proxy
	rm -f oauth-proxy.exe

# vim: syntax=make ts=4 sw=4 sts=4 sr noet
