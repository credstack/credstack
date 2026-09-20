FROM golang:1.26.1-alpine AS builder

RUN apk --no-cache add ca-certificates

# Describes the OS/Architecture we want to build for and instructs the conmpiler to build static binaries
ENV CGO_ENABLED=0 \
    GOOS=linux \
    GOARCH=amd64 \
    LDFLAGS="-s -w" \
    BUILDFLAGS="-v"

WORKDIR /build

COPY . .

RUN go build -o app $BUILDFLAGS -ldflags="$LDFLAGS" ./cmd/credstack-api/main.go

FROM gcr.io/distroless/static-debian13

COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /build/app /app/app

USER 1000:1000

WORKDIR /app

ENTRYPOINT ["/app/app"]
