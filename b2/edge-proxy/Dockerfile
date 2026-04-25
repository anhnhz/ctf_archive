FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*
COPY edge-proxy /usr/local/bin/edge-proxy
EXPOSE 8080
ENTRYPOINT ["edge-proxy"]
