FROM golang:1.25-alpine AS builder

WORKDIR /src/picket

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o /usr/local/bin/picket ./cmd/picket

FROM alpine:latest

COPY --from=builder /usr/local/bin/picket /usr/local/bin/picket

ENTRYPOINT ["/usr/local/bin/picket"]
CMD []
