FROM alpine:3.8

RUN apk add --update --no-cache ca-certificates

RUN addgroup -g 1000 -S test && \
adduser -u 1000 -S test -G test

USER test

ENTRYPOINT ["/bin/sh"]
CMD ["-c", "echo $TEST_SECRET && echo going to sleep... && sleep 10000"]