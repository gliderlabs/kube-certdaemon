FROM golang:1.8-alpine
WORKDIR /go/src/github.com/gliderlabs/kube-certdaemon
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o certdaemon .

FROM alpine:3.6
RUN apk --no-cache add ca-certificates
COPY --from=0 /go/src/github.com/gliderlabs/kube-certdaemon/certdaemon /
ENTRYPOINT ["/certdaemon"]
