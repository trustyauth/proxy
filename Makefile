default:
	go build -o dist/ta-proxy ./cmd/ta-proxy

clean:
	rm -rf dist

test:
	go test ./...

fmt:
	go fmt ./...

up:
	docker-compose -f ./etc/docker-compose.yml -f ./etc/docker-compose.off.yml up -d --build

up-tls:
	docker-compose -f ./etc/docker-compose.yml -f ./etc/docker-compose.manual.yml up -d --build

down:
	docker-compose -f ./etc/docker-compose.yml -f ./etc/docker-compose.off.yml down 2>/dev/null; \
	docker-compose -f ./etc/docker-compose.yml -f ./etc/docker-compose.manual.yml down 2>/dev/null; \
	true

devlogs:
	docker logs -f ta-proxy

certs:
	mkdir -p etc/certs
	mkcert -cert-file etc/certs/cert.pem -key-file etc/certs/key.pem \
		localhost app.localhost 127.0.0.1 ::1

bins:
	go build -o dist/generate-cookie ./tools/cookie
	go build -o dist/generate-jwt ./tools/jwt

cookie: bins
	./dist/generate-cookie

cookie-tls: bins
	./dist/generate-cookie -tls

jwt: bins
	./dist/generate-jwt

jwt-tls: bins
	./dist/generate-jwt -tls
