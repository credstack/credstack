# To build this with secrets: (sudo) docker build --secret id=sshkey,src=/path/to/id_rsa -t credstack-api:latest .
# To build normally: (sudo) docker build . -t credstack-api:latest

FROM golang:1.25.1-alpine AS builder

RUN apk --no-cache add ca-certificates git

# Describes the OS/Architecture we want to build for and instructs the conmpiler to build static binaries
ENV CGO_ENABLED=0 \
    GOOS=linux \
    GOARCH=amd64

WORKDIR /app

# Add nonroot user and group so that we can create our /app/log directory with proper permissions
RUN addgroup -S nonroot -g 1000 && adduser -S nonroot -u 1000 -G nonroot
RUN mkdir -p /log && chown -R nonroot:nonroot /log && chmod -R 755 /log

# Copy source files
COPY . .

RUN go mod download

# Strip symbols and debugging information
RUN go build -o app -ldflags="-s -w" ./cmd/api

FROM gcr.io/distroless/static-debian12

COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /app/app /app/app
COPY --from=builder /log /log

ENV CREDSTACK_LOG_PATH="/log"

USER 1000:1000

WORKDIR /app

ENTRYPOINT ["/app/app"]
