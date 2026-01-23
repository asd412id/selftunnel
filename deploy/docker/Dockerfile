# Build stage
FROM golang:1.24-alpine AS builder

WORKDIR /app

# Copy go mod files
COPY go.mod go.sum ./
RUN go mod download

# Copy source
COPY . .

# Build signaling server
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o signaling-server ./cmd/signaling-server

# Runtime stage
FROM alpine:3.19

RUN apk --no-cache add ca-certificates tzdata

WORKDIR /app

COPY --from=builder /app/signaling-server /app/signaling-server

EXPOSE 8080

ENTRYPOINT ["/app/signaling-server"]
CMD ["-port", "8080"]
