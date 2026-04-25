FROM golang:1.25.7-bookworm AS builder
WORKDIR /app
COPY go.mod ./
RUN go mod download
COPY *.go ./
RUN CGO_ENABLED=0 go build -o /build-runner .

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=builder /build-runner /build-runner
EXPOSE 9000
ENTRYPOINT ["/build-runner"]
