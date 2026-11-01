.PHONY: build test vet image

build:
	CGO_ENABLED=0 go build -trimpath -o bin/cluster-update-fr ./cmd/cluster-update-fr

test:
	go test ./... -race

vet:
	go vet ./...

image:
	docker build -t cluster-update-fr:dev .
