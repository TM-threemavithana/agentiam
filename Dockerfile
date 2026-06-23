FROM golang:1.25-alpine AS builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

COPY . .
# Build the binary
RUN CGO_ENABLED=0 GOOS=linux go build -o agentiam ./cmd/agentiam

FROM alpine:latest
WORKDIR /app
COPY --from=builder /app/agentiam .
# Ensure sqlite db can be created
RUN mkdir -p /app/data

EXPOSE 5433
CMD ["./agentiam"]
