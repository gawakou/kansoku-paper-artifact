# Virtual-lab requirements

## Supported host

- Ubuntu Server 24.04 LTS is the reference environment.
- Ubuntu 22.04 LTS is expected to work but is not the release reference.
- AMD64 and ARM64 are supported by the selected Ubuntu and FRRouting images.
- macOS and Windows users run the lab inside an Ubuntu VM.

## VM sizing

| Profile | vCPU | RAM | Disk | Purpose |
|---|---:|---:|---:|---|
| Minimum | 4 | 8 GiB | 40 GiB | Functional tests |
| Recommended | 6 | 12 GiB | 80 GiB | Full suite and captures |
| Extended | 8 | 16 GiB | 120 GiB | v0.9+ experiments |

## Required software

- Docker Engine with non-root access for the test user
- containerlab
- Python 3.10 or later
- Open vSwitch kernel module
- 802.1Q VLAN kernel module
- Git, curl, jq, tcpdump

`lab/vm/bootstrap-ubuntu.sh` installs and verifies these dependencies on Ubuntu.
