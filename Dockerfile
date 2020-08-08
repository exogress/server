FROM rust:1.45.1

RUN rustup component add clippy rustfmt
RUN apt-get update && apt-get install -y libssl-dev libsasl2-dev libzmq3-dev libzmq5 llvm-dev llvm libclang1-7 \
    build-essential clang cmake build-essential

ADD ci/gcs.json /gcs.json
ADD ci/sccache /usr/local/bin/sccache

ENV SCCACHE_GCS_BUCKET=sccache-exogress-jenkinsn
ENV SCCACHE_GCS_RW_MODE=READ_WRITE
ENV RUSTC_WRAPPER=/usr/local/bin/sccache
ENV SCCACHE_GCS_KEY_PATH=/gcs.json

COPY . /code
WORKDIR /code/crates
RUN cargo build --release && sccache --show-stats && \
    cp /code/crates/target/release/exogress-gateway /usr/local/bin/ && \
    cp /code/crates/target/release/exogress-signaler /usr/local/bin/ && \
    rm -rf ../target

ENTRYPOINT ["/usr/local/bin/exogress-gateway"]
