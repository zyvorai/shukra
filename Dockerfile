# Runtime image for a controlled environment. systemd on the hypervisor is still
# the supported install: this image does not load eBPF by itself unless the
# binary inside it was built with -tags shukrabpf and the container is granted
# the capabilities in deploy/shukra.service.
#
# The default command listens on loopback. That is unreachable through
# `docker run -p 30970:30970`. Override the command. Put TLS in front, or pass
# -allow-insecure-http and keep the container behind a TLS proxy.
#
#   docker run --rm -p 30970:30970 \
#     -v /path/certs:/certs:ro shukra:local \
#     -listen 0.0.0.0:30970 -tls-cert /certs/tls.crt -tls-key /certs/tls.key \
#     -web /usr/share/shukra/web
#
#   docker run --rm -p 30970:30970 shukra:local \
#     -listen 0.0.0.0:30970 -allow-insecure-http -web /usr/share/shukra/web
#
# Build after scripts/package.sh, which leaves bin/shukrad and web/dist:
#   docker build -t shukra:local .
FROM debian:12-slim
COPY bin/shukrad bin/shukractl /usr/local/bin/
COPY web/dist /usr/share/shukra/web
EXPOSE 30970
USER 65534:65534
ENTRYPOINT ["/usr/local/bin/shukrad"]
CMD ["-listen", "127.0.0.1:30970", "-web", "/usr/share/shukra/web"]
