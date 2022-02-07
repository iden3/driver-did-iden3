##
## Build did driver
##
FROM golang:1.16-alpine as base

WORKDIR /build

RUN apk add --no-cache --update git

#COPY . .
COPY ./cmd ./cmd
COPY ./pkg ./pkg
COPY go.mod ./
COPY go.sum ./
RUN go mod download

RUN CGO_ENABLED=0 go build -o ./driver ./cmd/driver/main.go

# Build an driver image
FROM scratch

COPY --from=base /build/driver       /app/driver
COPY ./configs    /app/configs
COPY --from=base  /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

WORKDIR /app

# Command to run
ENTRYPOINT ["/app/driver"]
