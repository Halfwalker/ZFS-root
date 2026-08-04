# Packer Builds

The ZFS-root system can generate `.qcow2` KVM disk images via [Packer](https://developer.hashicorp.com/packer).  Two helper scripts handle the heavy lifting:

* `run-packer.sh` — Build a system using packer (direct or via Docker)
* `run-kvm.sh` — Boot a packer-built system with KVM

The default credentials for packer-built images are `packer/packer`.

## Quick Start

```
# Single disk, no encryption
./run-packer.sh --ubuntu-version 24.04.2 --discenc NOENC --disk-size 5G

# Two-disk mirror with SecureBoot
./run-packer.sh --ubuntu-version 24.04.2 --discenc NOENC --disk-size 5G \
    --disks 2 --raidlevel mirror --secureboot

# Three-disk raidz1 with ZFS encryption and custom hostname
./run-packer.sh --ubuntu-version 24.04.2 --discenc ZFSENC --disk-size 10G \
    --disks 3 --raidlevel raidz1 --set MYHOSTNAME=securebox

# Run the resulting image
./run-kvm.sh /qemu/builds/packer-noble-NOENC-2026-02-08-1234
```

## Build Options

| Option | Description |
|--------|-------------|
| `--docker` | Run packer in a Docker container |
| `--ubuntu-version` | Ubuntu version (e.g. 24.04.2, 26.04) |
| `--discenc` | Encryption: NOENC, ZFSENC, or LUKS |
| `--disk-size` | Disk size (e.g. 5G, 10G) |
| `--disks N` | Total number of disks |
| `--raidlevel` | mirror or raidz1 (for multi-disk) |
| `--secureboot` | Enable UEFI SecureBoot (uses SecureBoot OVMF and configures signing) |
| `--iso-src` | ISO location (e.g. file:///qemu/ISOs) |
| `--config` | Config file (default: ZFS-root.conf.packerci) |
| `--set KEY=VALUE` | Override config variables |

The `--set SSHPUBKEY=...` option injects an SSH public key into the build for
CI/CD access. A dedicated CI key pair is available at `packer-validation/CICD_ed25519{,.pub}`.

## Config Overrides

The `--set` option lets you override any `ZFS-root.conf` variable:

```
./run-packer.sh --ubuntu-version 24.04.2 --discenc NOENC --disk-size 5G \
    --set MYHOSTNAME=testbox --set POOLNAME=testpool
```

Multiple `--set` options can be combined.  These override values from both the base config file and packer's automatic defaults.

The `--set SSHPUBKEY=...` option is commonly used for CI/CD — an example CI key pair lives at `packer-validation/CICD_ed25519{,.pub}`.  This injects the pubkey into the build's `~/.ssh/authorized_keys` and into Dropbear's ACL for remote unlocking.

## ISO Location

ISOs are downloaded automatically from releases.ubuntu.com, or you can point to a local cache.  For local ISOs, place them in release-named subdirectories:

```
/qemu/ISOs/resolute/ubuntu-26.04-live-server-amd64.iso
/qemu/ISOs/questing/ubuntu-25.10-live-server-amd64.iso
/qemu/ISOs/plucky/ubuntu-25.04-live-server-amd64.iso
/qemu/ISOs/noble/ubuntu-24.04.2-live-server-amd64.iso
```

Then use `--iso-src file:///qemu/ISOs`.

## Docker Builds

For isolated builds without installing packer/qemu locally:

```
./run-packer.sh --docker --ubuntu-version 24.04.2 --discenc NOENC --disk-size 5G
```

The script handles plugin initialization, bind mounts, and container setup automatically.  Note that Docker builds always run headless.

## Packer Configuration Files

> <dl>
>   <dt>ZFS-root_local.pkr.hcl
>   <dd>Main packer template.  Defines QEMU VM settings, provisioners, and post-processors.
>   <dt>ZFS-root_local.vars.hcl
>   <dd>Default variable overrides.  Edit this to change output paths, ISO sources, or disk defaults.
>   <dt>ZFS-root.conf.packerci
>   <dd>Pre-seed config for ZFS-root.sh.  Sets up packer-friendly defaults (user, encryption, ZFSBootMenu options).
> </dl>

The `--set KEY=VALUE` option creates runtime overrides that take precedence over both the vars file and the packerci config.

## Running Images

The `run-kvm.sh` script auto-detects SecureBoot from the build metadata and/or the `efivars.fd` :

```
./run-kvm.sh /qemu/builds/packer-noble-NOENC-2026-02-08-1234
```

Options:

| Option | Description |
|--------|-------------|
| `--bios` | Force legacy BIOS mode (no UEFI) |
| `--secureboot` | Force SecureBoot (overrides auto-detect) |
| `--ram SIZE` | RAM in MB (default: 2048) |
| `--ssh PORT` | SSH forwarding port - default: 3222 (NAT'd to 22) |
| `--dropbear PORT` | SSH forwarding port for Dropbear - default: 1222 (NAT'd to 222)<br>NOTE: **requires** an ssh key defined |

SSH into an encrypted booting VM with:

```
# Use your default ssh keys or specify which key to use
ssh -p 1222 [-i path/to/key] root@localhost
```

SSH into the running VM with:

```
ssh -p 3222 packer@localhost -o PubkeyAuthentication=no
```

## Build Output

Each build creates a timestamped directory under the output prefix (default `/qemu/builds/`):

```
packer-noble-NOENC-2026-02-08-1234/
├── packer-noble-NOENC-2026-02-08-1234.qcow2    # Primary disk
├── packer-noble-NOENC-2026-02-08-1234.qcow2-1  # Additional disk (if multi-disk)
├── efivars.fd                                   # UEFI variables
├── build-metadata.txt                           # Build settings for run-kvm.sh
├── build.log                                    # ZFS-root.sh installation log
├── packer-output.log                            # Full log from `packer build ...` command
├── manifest.json                                # Packer manifest
├── ZFS-root_final.conf                          # Final ZFS-root.conf used for build
└── *.sha256.checksum                            # Disk checksums
```
