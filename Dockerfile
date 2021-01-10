FROM alpine:3.12
RUN apk add tzdata && rm -rf /var/cache/apk/
COPY go-jwt-cracker /go-jwt-cracker
ENTRYPOINT ["/go-jwt-cracker"]