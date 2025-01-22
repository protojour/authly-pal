dev-image:
    docker build . -t protojour/authly-pal:dev --platform linux/amd64 --build-arg RUST_PROFILE=debug --build-arg CARGO_FLAGS=
