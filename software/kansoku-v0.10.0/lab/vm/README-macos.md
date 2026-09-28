# macOS host preparation

The data-plane lab must run in Linux because containerlab creates Linux network namespaces and veth links. Keep KANSOKU source on the Ubuntu VM while running the integration suite.

## Recommended VM

- Guest: Ubuntu Server 24.04 LTS
- Architecture: ARM64 on Apple Silicon, AMD64 on Intel Mac
- CPU: 6 vCPU
- Memory: 12 GiB
- Disk: 80 GiB dynamically allocated
- Network adapter 1: NAT/shared networking
- Optional adapter 2: host-only networking for stable SSH access

UTM, VMware Fusion, Parallels, or an OrbStack Linux VM can provide the guest. The lab itself does not depend on a particular macOS hypervisor.

## Procedure

1. Install Ubuntu Server and enable SSH.
2. Copy or clone the KANSOKU repository into the VM.
3. Run:

   ```bash
   cd ~/kansoku
   ./lab/vm/bootstrap-ubuntu.sh
   ```

4. Log out and back in when the installer adds the account to the `docker` group.
5. Deploy and test:

   ```bash
   make lab-up
   make lab-test
   make lab-down
   ```

## Minimum resource profile

A reduced lab generally runs with 4 vCPU, 8 GiB RAM, and 40 GiB disk. The recommended profile leaves enough capacity for packet capture, image builds, and future v0.9 configuration-validation services.
