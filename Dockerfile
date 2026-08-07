FROM golang:1.25-alpine AS builder

WORKDIR /app
COPY go.mod go.sum ./
ENV GOTOOLCHAIN=auto
RUN go mod download

COPY . .
# Build the binary (CGO disabled for a fully static binary)
RUN CGO_ENABLED=0 GOOS=linux go build -o agentiam ./cmd/agentiam

FROM alpine:latest
WORKDIR /app
COPY --from=builder /app/agentiam .
# Create data directory for policy file storage
RUN mkdir -p /app/data

EXPOSE 5433
CMD ["./agentiam"]
