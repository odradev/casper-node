FROM rust:1.77.2

RUN apt-get update && \
    apt-get install --no-install-recommends -y \
    ca-certificates curl file \
    build-essential \
    autoconf automake autotools-dev libtool xutils-dev \
    cmake libssl-dev pkg-config gcc g++ gettext-base && \
    rm -rf /var/lib/apt/lists/*

RUN rustup --version
