FROM rust:1.45.1 as builder

RUN rustup component add clippy rustfmt
RUN apt-get update && apt-get install -y libssl-dev libsasl2-dev llvm-dev llvm libclang1-7 \
    build-essential clang cmake build-essential

ADD ci/gcs.json /gcs.json
ADD ci/sccache /usr/local/bin/sccache

ENV SCCACHE_GCS_BUCKET=sccache-exogress-jenkinsn
ENV SCCACHE_GCS_RW_MODE=READ_WRITE
ENV RUSTC_WRAPPER=/usr/local/bin/sccache
ENV SCCACHE_GCS_KEY_PATH=/gcs.json

COPY . /code
WORKDIR /code/crates

RUN cargo test && sccache --show-stats

RUN cargo build --release && sccache --show-stats

FROM debian:buster as signaler
RUN apt-get update && apt-get install -y libssl1.1 libsasl2-dev ca-certificates
COPY --from=builder /code/crates/target/release/exogress-signaler /usr/local/bin/
RUN exogress-signaler autocompletion bash > /etc/profile.d/exogress-signaler.sh && \
    echo "source /etc/profile.d/exogress-signaler.sh" >> ~/.bashrc
ENTRYPOINT ["/usr/local/bin/exogress-signaler"]

FROM debian:buster as gateway
RUN apt-get update && apt-get install -y libssl1.1 libsasl2-dev ca-certificates
COPY --from=builder /code/crates/target/release/exogress-gateway /usr/local/bin/
RUN exogress-gateway autocompletion bash > /etc/profile.d/exogress-gateway.sh && \
    echo "source /etc/profile.d/exogress-gateway.sh" >> ~/.bashrc
ENTRYPOINT ["/usr/local/bin/exogress-gateway"]
