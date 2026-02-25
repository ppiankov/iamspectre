# syntax=docker/dockerfile:1
FROM golang:1.25-alpine AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .

ARG VERSION=dev
ARG COMMIT=none
ARG DATE=unknown

RUN CGO_ENABLED=0 go build \
    -ldflags="-s -w -X main.version=${VERSION} -X main.commit=${COMMIT} -X main.date=${DATE}" \
    -o /iamspectre ./cmd/iamspectre/

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=builder /iamspectre /usr/local/bin/iamspectre
USER nonroot:nonroot
ENTRYPOINT ["iamspectre"]
