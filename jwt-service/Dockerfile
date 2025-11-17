# Build stage
FROM golang:1.21-alpine AS builder

# Set working directory
WORKDIR /app

# Copy go mod files
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build the CLI
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o jwt-cli cmd/cli/main.go

# Build the server
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o jwt-server cmd/server/main.go

# Final stage
FROM alpine:latest

# Set timezone
RUN apk --no-cache add tzdata
ENV TZ=Asia/Kolkata
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone

WORKDIR /root/

# Copy the binaries from builder stage
COPY --from=builder /app/jwt-cli .
COPY --from=builder /app/jwt-server .

# Expose port for the server
EXPOSE 8080

# Default command is to run the server
CMD ["./jwt-server"]