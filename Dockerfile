FROM frolvlad/alpine-gcc:latest
# Update packages to get latest security fixes for OpenSSL (CVE-2025-9230, CVE-2025-9231, CVE-2025-9232)
RUN apk update && apk upgrade --no-cache && apk add --quiet --no-cache libressl-dev make

# Create non-root user and group
RUN addgroup -S appgroup && adduser -S appuser -G appgroup

COPY ./*.h /opt/src/
COPY ./*.c /opt/src/
COPY Makefile /opt/src/
COPY entrypoint.sh /

WORKDIR /opt/src
# Note: Only need one make command on Alpine Linux (macOS paths removed)
RUN make
RUN ["chmod", "+x", "/entrypoint.sh"]
RUN ["chmod", "+x", "/opt/src/jwtcrack"]

# Change ownership to non-root user
RUN chown -R appuser:appgroup /opt/src /entrypoint.sh

USER appuser

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 CMD ["/opt/src/jwtcrack", "--version"] || exit 1

ENTRYPOINT ["/entrypoint.sh"]
