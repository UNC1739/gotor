FROM golang:1.23-alpine AS build
WORKDIR /src
COPY . .
RUN go mod tidy
RUN go test -count=1 -timeout 120s ./...
RUN mkdir -p /out \
 && CGO_ENABLED=0 go build -o /out/gotor ./cmd/gotor \
 && CGO_ENABLED=0 go build -o /out/gotor-net ./cmd/gotor-net \
 && CGO_ENABLED=0 go build -o /out/origin ./cmd/origin \
 && CGO_ENABLED=0 go build -o /out/gotor-check ./cmd/gotor-check

FROM alpine:3.21
RUN apk add --no-cache ca-certificates wget
COPY --from=build /out/gotor /out/gotor-net /out/origin /out/gotor-check /usr/local/bin/
WORKDIR /run
ENTRYPOINT []
