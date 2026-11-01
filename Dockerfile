# syntax=docker/dockerfile:1@sha256:4edf897a3ffa55b89f906fc8cc78afdb3f1834cc9c7083565e611a8a7d5fe99e

# Static Go binary on distroless-static, numeric non-root user so a
# runAsNonRoot pod verifies without a manifest-side runAsUser override.
# Every base (and the frontend above) is pinned by digest (c1s-r7); the tag
# stays for Renovate's digest updates.
FROM golang:1.23-alpine@sha256:383395b794dffa5b53012a212365d40c8e37109a626ca30d6151c8348d380b5f AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" \
    -o /out/cluster-update-fr ./cmd/cluster-update-fr

FROM gcr.io/distroless/static:nonroot@sha256:25ac8f0c3b2334a9eb05452266bd4697864a8c8ef0ef71e5e6480d7f92868329
COPY --from=build /out/cluster-update-fr /cluster-update-fr
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/cluster-update-fr"]
