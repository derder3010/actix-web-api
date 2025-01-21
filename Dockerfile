FROM rust:latest as builder

WORKDIR /usr/src/app
COPY . .

# Build dependencies separately to cache them
RUN cargo build --release

FROM debian:bookworm-slim

RUN apt-get update && \
    apt-get install -y libssl-dev ca-certificates && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=builder /usr/src/app/target/release/backend .
COPY .env .

EXPOSE 8080
CMD ["./backend"]
