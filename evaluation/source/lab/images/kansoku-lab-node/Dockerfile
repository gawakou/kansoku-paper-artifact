FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

RUN printf '#!/bin/sh\nexit 101\n' > /usr/sbin/policy-rc.d \
    && chmod +x /usr/sbin/policy-rc.d \
    && apt-get update \
    && apt-get install -y --no-install-recommends \
       bash ca-certificates curl ethtool iperf3 iproute2 iputils-ping jq \
       netcat-openbsd nftables openvswitch-switch procps python3 tcpdump \
    && rm -f /usr/sbin/policy-rc.d \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /opt/kansoku /srv/kansoku /var/log/openvswitch /var/run/openvswitch /usr/local/libexec \
    && cp /usr/bin/tcpdump /usr/local/libexec/kansoku-tcpdump \
    && chmod 0755 /usr/local/libexec/kansoku-tcpdump

COPY entrypoint.sh /usr/local/bin/kansoku-lab-entrypoint
RUN chmod 0755 /usr/local/bin/kansoku-lab-entrypoint \
    && printf 'KANSOKU v0.10.0 virtual lab\n' > /srv/kansoku/index.html

ENTRYPOINT ["/usr/local/bin/kansoku-lab-entrypoint"]
CMD ["sleep", "infinity"]
