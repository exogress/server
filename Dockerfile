FROM rust:1.51 as dirs

RUN rustup component add clippy rustfmt
RUN apt-get update && apt-get install -y libssl-dev libsasl2-dev llvm-dev llvm libclang1-7 \
    build-essential clang cmake build-essential lmdb-utils liblmdb-dev liblmdb0

COPY . /code
WORKDIR /code/crates

FROM dirs as builder

RUN cargo update -p exogress-common
RUN cargo build --release

FROM debian:buster as base

RUN apt-get update && apt-get install -y libssl1.1 libsasl2-dev ca-certificates

FROM base as signaler
COPY --from=builder /code/crates/target/release/exogress-signaler /usr/local/bin/
RUN exogress-signaler autocompletion bash > /etc/profile.d/exogress-signaler.sh && \
    echo "source /etc/profile.d/exogress-signaler.sh" >> ~/.bashrc
ENTRYPOINT ["/usr/local/bin/exogress-signaler"]

FROM base as assistant
COPY --from=builder /code/crates/target/release/exogress-assistant /usr/local/bin/
RUN exogress-assistant autocompletion bash > /etc/profile.d/exogress-assistant.sh && \
    echo "source /etc/profile.d/exogress-assistant.sh" >> ~/.bashrc
ENTRYPOINT ["/usr/local/bin/exogress-assistant"]

FROM base as director
COPY --from=builder /code/crates/target/release/exogress-director /usr/local/bin/
RUN exogress-director autocompletion bash > /etc/profile.d/exogress-director.sh && \
    echo "source /etc/profile.d/exogress-director.sh" >> ~/.bashrc
ENTRYPOINT ["/usr/local/bin/exogress-director"]

FROM dpokidov/imagemagick:7.0.11-2-buster as transformer
RUN apt-get update && apt-get install -y libssl1.1 libsasl2-dev ca-certificates
COPY --from=builder /code/crates/target/release/exogress-transformer /usr/local/bin/
RUN exogress-transformer autocompletion bash > /etc/profile.d/exogress-transformer.sh && \
    echo "source /etc/profile.d/exogress-transformer.sh" >> ~/.bashrc
ENTRYPOINT ["/usr/local/bin/exogress-transformer"]

FROM base as api
COPY --from=builder /code/crates/target/release/exogress-api /usr/local/bin/
RUN exogress-api autocompletion bash > /etc/profile.d/exogress-api.sh && \
    echo "source /etc/profile.d/exogress-api.sh" >> ~/.bashrc
ENTRYPOINT ["/usr/local/bin/exogress-api"]

FROM base as gateway
COPY --from=builder /code/crates/target/release/exogress-gateway /usr/local/bin/
COPY --from=quay.io/exogress/dbip-db:latest /dbip.mmdb /
RUN apt install -y lmdb-utils liblmdb-dev liblmdb0
RUN exogress-gateway autocompletion bash > /etc/profile.d/exogress-gateway.sh && \
    echo "source /etc/profile.d/exogress-gateway.sh" >> ~/.bashrc
ENTRYPOINT ["/usr/local/bin/exogress-gateway"]
