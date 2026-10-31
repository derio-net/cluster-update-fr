# syntax=docker/dockerfile:1

# Static Go binary on distroless-static, numeric non-root user so a
# runAsNonRoot pod verifies without a manifest-side runAsUser override.
FROM golang:1.23-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" \
    -o /out/cluster-update-fr ./cmd/cluster-update-fr

FROM gcr.io/distroless/static:nonroot
COPY --from=build /out/cluster-update-fr /cluster-update-fr
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/cluster-update-fr"]
