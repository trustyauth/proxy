default:
	go build -o dist/picket ./cmd/picket

clean:
	rm -rf dist

test:
	go test ./...
