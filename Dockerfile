FROM rust:latest AS builder

WORKDIR /app
COPY src src
COPY Cargo.toml Cargo.lock ./
COPY .cargo .cargo
COPY prisma prisma
COPY prisma-cli prisma-cli

RUN --mount=type=cache,target=/root/.rustup \
  --mount=type=cache,target=/root/.cargo/registry \
  --mount=type=cache,target=/root/.cargo/git \
  --mount=type=cache,target=/root/.cache \
  cargo prisma generate;

RUN --mount=type=cache,target=/root/.rustup \
  --mount=type=cache,target=/root/.cargo/registry \
  --mount=type=cache,target=/root/.cargo/git \
  --mount=type=cache,target=/app/target \
  set -eux; \
  cargo build --release;\
  cp target/release/emp_logger .

FROM ubuntu:latest

WORKDIR /app

COPY --from=builder /app/emp_logger ./

CMD ["/app/emp_logger"]
