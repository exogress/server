FROM rust:1.48-alpine3.12 as dirs

RUN rustup component add clippy rustfmt
RUN apk --update add build-base imagemagick imagemagick-dev \
    libffi-dev openssl-dev libsasl clang cmake \
    ca-certificates pkgconfig llvm-dev libgcc clang-libs

COPY . /code
WORKDIR /code/crates

ENV RUSTFLAGS="-Ctarget-feature=-crt-static"

FROM dirs as builder
#ADD ci/gcs.json /gcs.json
#ADD ci/sccache /usr/local/bin/sccache

#ENV SCCACHE_GCS_BUCKET=sccache-exogress-jenkinsn
#ENV SCCACHE_GCS_RW_MODE=READ_WRITE
#ENV RUSTC_WRAPPER=/usr/local/bin/sccache
#ENV SCCACHE_GCS_KEY_PATH=/gcs.json

RUN cargo build --release
#&& sccache --show-stats

FROM alpine:3.12 as base

RUN apk --update add libffi-dev openssl-dev libsasl ca-certificates pkgconfig libgcc clang-libs sqlite-dev sqlite

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

FROM base as gateway
COPY --from=builder /code/crates/target/release/exogress-gateway /usr/local/bin/
COPY --from=quay.io/exogress/dbip-db:latest /dbip.mmdb /
RUN apk --update add imagemagick imagemagick-dev pkgconfig sqlite-dev sqlite
RUN exogress-gateway autocompletion bash > /etc/profile.d/exogress-gateway.sh && \
    echo "source /etc/profile.d/exogress-gateway.sh" >> ~/.bashrc
ENTRYPOINT ["/usr/local/bin/exogress-gateway"]
