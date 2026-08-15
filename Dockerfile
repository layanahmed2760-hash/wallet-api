# Stage 1: Build the Go binary
FROM golang:1.26-alpine AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN go build -o wallet-api .

# Stage 2: Create a small final image with just the binary
FROM alpine:latest

WORKDIR /app

COPY --from=builder /app/wallet-api .
COPY --from=builder /app/docs ./docs

EXPOSE 8080

CMD ["./wallet-api"]