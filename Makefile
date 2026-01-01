default:
	go build -o dist/ta-proxy ./cmd/ta-proxy

clean:
	rm -rf dist

test:
	go test ./...

fmt:
	go fmt ./...

up:
	docker-compose -f ./etc/docker-compose.yml up -d --build

down:
	docker-compose -f ./etc/docker-compose.yml down

devlogs:
	docker logs -f ta-proxy

bins:
	go build -o dist/generate-cookie ./tools/cookie
	go build -o dist/generate-jwt ./tools/jwt

cookie: bins
	./dist/generate-cookie

jwt: bins
	./dist/generate-jwt
