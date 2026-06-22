FROM golang:1.25-alpine AS builder

# Install gcc and musl-dev for CGO (required by pg_query_go)
RUN apk add --no-cache gcc musl-dev

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

COPY . .
# Build the binary with CGO enabled
RUN CGO_ENABLED=1 GOOS=linux go build -o agentiam ./cmd/agentiam

FROM alpine:latest
WORKDIR /app
COPY --from=builder /app/agentiam .
# Ensure sqlite db can be created
RUN mkdir -p /app/data

EXPOSE 5433
CMD ["./agentiam"]
