# syntax=docker/dockerfile:1
FROM golang:1.26-alpine AS builder
WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY main.go ./
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/vc-webhook .

# ---- distroless runtime: no shell, non-root by default ----
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=builder /out/vc-webhook /vc-webhook
USER nonroot:nonroot
EXPOSE 8443
ENTRYPOINT ["/vc-webhook"]
