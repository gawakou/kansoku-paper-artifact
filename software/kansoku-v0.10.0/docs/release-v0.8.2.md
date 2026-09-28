# KANSOKU v0.8.2

KANSOKU v0.8.2 is a virtual-lab reliability patch discovered during the first full Ubuntu/containerlab execution.

## Fixes

- starts the HTTP and iperf3 services with detached `docker exec` processes after all container links are created
- waits for TCP/443 and TCP/5201 listeners before declaring the lab ready
- validates HTTP and iperf3 end to end during `make lab-up`
- restarts missing application services during lab reset
- prints interface, route, listener, process, and HTTP log diagnostics when readiness fails
- removes fragile background service startup from the containerlab bootstrap exec session
