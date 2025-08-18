# syntax=docker/dockerfile:1.4

# Stage 1: Build the Go application
FROM golang:1.22-alpine AS builder

WORKDIR /app

# Copy go.mod and go.sum first to leverage Docker cache
COPY go.mod go.sum ./ 
RUN go mod download

# Copy the rest of the application source code
COPY . .

# Build the application
# CGO_ENABLED=0 disables CGO, making the binary statically linked
# -a forces rebuilding of packages that are already up-to-date
# -installsuffix nocgo prevents issues with CGO-enabled and CGO-disabled builds
# -ldflags "-s -w" removes debug information and symbol table, reducing binary size
RUN CGO_ENABLED=0 go build -o /lucid-vigil ./cmd/lucid-vigil

# Stage 2: Create the final distroless image
FROM gcr.io/distroless/static-debian12

WORKDIR /

# Copy the statically linked binary from the builder stage
COPY --from=builder /lucid-vigil /lucid-vigil

# Expose the API port (default 8080)
EXPOSE 8080

# Run the sentinel application
ENTRYPOINT ["/lucid-vigil"]
