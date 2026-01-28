FROM alpine:latest AS builder

RUN apk update && apk upgrade --no-cache && apk add --quiet --no-cache gcc musl-dev openssl-dev make

COPY ./*.h /opt/src/
COPY ./*.c /opt/src/
COPY Makefile /opt/src/

WORKDIR /opt/src
# Build with native CPU optimizations (Intel Xeon w5-2445 / Sapphire Rapids / x86-64-v4)
RUN make CFLAGS="-I /usr/include/openssl -g -std=gnu99 -O3 -march=native -mtune=native"

FROM alpine:3.23.3

# CPU Requirements: x86-64-v4 (AVX-512 capable)
# Optimized for: Intel Xeon w5-2445 (Sapphire Rapids)
# Compatible with: Intel Xeon Scalable 4th Gen+, Intel Core 11th Gen+ with AVX-512
LABEL org.opencontainers.image.title="c-jwt-cracker"
LABEL org.opencontainers.image.description="Multi-threaded JWT brute-force cracker"
LABEL org.opencontainers.image.source="https://github.com/maximmasiutin/c-jwt-cracker"
LABEL org.opencontainers.image.authors="Maxim Masiutin"
LABEL cpu.architecture="x86-64-v4"
LABEL cpu.features="AVX-512"
LABEL cpu.optimized-for="Intel Xeon w5-2445 (Sapphire Rapids)"

RUN apk update && apk upgrade --no-cache && apk add --quiet --no-cache libssl3 libcrypto3

# Create non-root user and group
RUN addgroup -S appgroup && adduser -S appuser -G appgroup

COPY --from=builder /opt/src/jwtcrack /opt/src/jwtcrack
COPY entrypoint.sh /

RUN chmod +x /entrypoint.sh /opt/src/jwtcrack
RUN chown -R appuser:appgroup /opt/src /entrypoint.sh

USER appuser

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 CMD ["/opt/src/jwtcrack", "--version"] || exit 1

ENTRYPOINT ["/entrypoint.sh"]
