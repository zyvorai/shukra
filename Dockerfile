# Runtime image for a controlled environment. systemd on the hypervisor is still
# the supported install: this image does not load eBPF by itself unless the
# binary inside it was built with -tags shukrabpf and the container is granted
# the capabilities in deploy/shukra.service.
#
# Build after scripts/package.sh, which leaves bin/shukrad and web/dist:
#   docker build -t shukra:local .
FROM debian:12-slim
COPY bin/shukrad bin/shukractl /usr/local/bin/
COPY web/dist /usr/share/shukra/web
EXPOSE 30970
USER 65534:65534
ENTRYPOINT ["/usr/local/bin/shukrad", "-listen", "127.0.0.1:30970", "-web", "/usr/share/shukra/web"]
