FROM golang:1.23-alpine AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /license-server ./cmd/server

FROM alpine:3.20
RUN apk add --no-cache ca-certificates
WORKDIR /app
COPY --from=builder /license-server .
COPY config.json .
COPY keys/ keys/
COPY certs/ certs/
EXPOSE 8443
ENTRYPOINT ["./license-server"]
CMD ["-config", "config.json"]
