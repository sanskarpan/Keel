.PHONY: test vet fmt check

test:
	GOTOOLCHAIN=local go test ./...

vet:
	GOTOOLCHAIN=local go vet ./...

fmt:
	gofmt -w cmd internal

check: test vet
