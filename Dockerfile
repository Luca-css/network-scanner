# syntax=docker/dockerfile:1

# ---- build stage ----
FROM golang:1.25-alpine AS build
WORKDIR /src
COPY go.mod ./
RUN go mod download
COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/netscan ./cmd/netscan

# ---- runtime stage ----
# Static binary + CA certs/tzdata only, no shell, runs as non-root (uid 65532).
# A TCP connect scan needs no extra capabilities.
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/netscan /netscan
ENTRYPOINT ["/netscan"]
