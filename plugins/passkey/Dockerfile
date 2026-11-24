# PocketBase + passkey plugin (examples/base) as a small container.
#
#   docker run -p 8090:8090 -v pb_data:/pb/pb_data \
#     -e PB_PASSKEY_RP_ID=pb.example.com -e PB_PASSKEY_ORIGINS=https://pb.example.com \
#     ghcr.io/nat-build-with-oracle/pocketbase-passkey
#
# Passkeys need https at PB_PASSKEY_ORIGINS (put a reverse proxy in front). Without the two
# variables PocketBase works as usual and the passkey routes answer 503.
FROM --platform=$BUILDPLATFORM golang:1.27-alpine AS build
ARG TARGETOS TARGETARCH VERSION=dev
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN PBV="$(go list -m -f '{{.Version}}' github.com/pocketbase/pocketbase)" && \
    CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath \
      -ldflags "-s -w -X github.com/pocketbase/pocketbase.Version=${PBV#v}+passkey.${VERSION#v}" \
      -o /out/pocketbase ./examples/base

FROM alpine:3
RUN apk add --no-cache ca-certificates tzdata
COPY --from=build /out/pocketbase /pb/pocketbase
WORKDIR /pb
EXPOSE 8090
VOLUME /pb/pb_data
ENTRYPOINT ["/pb/pocketbase"]
CMD ["serve", "--http=0.0.0.0:8090", "--dir=/pb/pb_data"]
