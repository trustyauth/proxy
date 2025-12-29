FROM golang:1.25-alpine AS builder

WORKDIR /src/ta-proxy

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o /usr/local/bin/ta-proxy ./cmd/ta-proxy

FROM alpine:latest

COPY --from=builder /usr/local/bin/ta-proxy /usr/local/bin/ta-proxy

ENTRYPOINT ["/usr/local/bin/ta-proxy"]
CMD []
