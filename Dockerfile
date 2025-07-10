FROM rust:latest

WORKDIR /zkp-server

COPY . .

RUN apt update
RUN apt install -y protobuf-compiler

RUN cargo build --release --bin server --bin client

# Keep container running - start server by default
CMD ["./target/release/server"]