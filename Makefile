LINTER ?= ${GOPATH}/bin/golangci-lint

.PHONY: all
all: lint test cover

.PHONY: lint
lint:
		@echo "--> Linting"
		@${LINTER} run -D structcheck -E interfacer -E maligned -E prealloc -E depguard -E gocyclo -E gosec -E dupl -E nakedret -E typecheck -e "field.* is unused" --deadline 180s ./...

.PHONY: test
test:
		@echo "--> Running tests"
		@mkdir -p .cover
		@rm -rf .cover/*
		@go test ./...

.PHONY: cover
cover:
		@go test -v -covermode=count -coverprofile=coverage.out
		@${GOPATH}/bin/goveralls -coverprofile=coverage.out -service=travis-ci -repotoken $COVERALLS_TOKEN

.PHONY: cover-html
cover-html:
		@go test -coverprofile .cover/cover.out
		@go tool cover -html=.cover/cover.out -o .cover/cover.html