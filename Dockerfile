FROM golang:1.13.5 as builder
WORKDIR /workspace
COPY . .
RUN CGO_ENABLED=0 GO111MODULE=on go build -a -o ./bin/ks-alerting-migration ./

FROM alpine:3.9
WORKDIR /
COPY --from=builder /workspace/bin/ks-alerting-migration /usr/local/bin/ks-alerting-migration

RUN adduser -D -g migrator -u 1002 migrator && \
    chown -R migrator:migrator /usr/local/bin/ks-alerting-migration
USER migrator

ENTRYPOINT ["ks-alerting-migration"]