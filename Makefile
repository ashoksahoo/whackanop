VERSION := $(shell cat VERSION)
SHELL := /bin/bash
PKG := github.com/Clever/whackanop
SUBPKGS :=
PKGS := $(PKG) $(SUBPKGS)
EXECUTABLE := whackanop
BUILDS := \
	build/$(EXECUTABLE)-v$(VERSION)-darwin-amd64 \
	build/$(EXECUTABLE)-v$(VERSION)-linux-amd64
COMPRESSED_BUILDS := $(BUILDS:%=%.tar.gz)
RELEASE_ARTIFACTS := $(COMPRESSED_BUILDS:build/%=release/%)

test: $(PKG)

$(PKG):
	go get github.com/golang/lint/golint
	$(GOPATH)/bin/golint $(GOPATH)/src/$@*/**.go
	go get -d -t $@
	go test -cover -coverprofile=$(GOPATH)/src/$@/c.out $@ -test.v
ifeq ($(HTMLCOV),1)
	go tool cover -html=$(GOPATH)/src/$@/c.out
endif

build/$(EXECUTABLE)-v$(VERSION)-darwin-amd64:
	GOARCH=amd64 GOOS=darwin go build -o "$@/$(EXECUTABLE)"
build/$(EXECUTABLE)-v$(VERSION)-linux-amd64:
	GOARCH=amd64 GOOS=linux go build -o "$@/$(EXECUTABLE)"

%.tar.gz: %
	tar -C `dirname $<` -zcvf "$<.tar.gz" `basename $<`

$(RELEASE_ARTIFACTS): release/% : build/%
	mkdir -p release
	cp $< $@

release: $(RELEASE_ARTIFACTS)

clean:
	rm -rf build release

.PHONY: test $(PKGS) clean github-release
