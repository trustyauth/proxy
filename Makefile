default:
	go build -o dist/picket ./cmd/picket

clean:
	rm -rf dist

test:
	go test ./...

up:
	docker-compose -f ./etc/docker-compose.yml up -d --build

down:
	docker-compose -f ./etc/docker-compose.yml down
