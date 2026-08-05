
packer {
  required_plugins {
    qemu = {
      version = ">= 1.1.1"
      source  = "github.com/hashicorp/qemu"
    }
  }
}

# Show the VM console gui ?
# Set to true when running under CI/CD pipelines or from docker
# Set to false when running manually/locally
variable "headless" {
  description = "Whether to show the VM console gui"
  type    = bool
  default = true
}

variable "display" {
  description = "Display backend when headless=false: sdl (default), gtk, none, curses"
  type    = string
  default = "sdl"
}

# Output dir prefix
# Set to "" for running in CI/CD pipelines
# Set to some location for running locally
# Be SURE to include trailing slash
# NOTE: If running under docker this location must be bind-mounted into the container
variable "output_prefix" {
  description = "Prefix for output directory location"
  type    = string
  default = ""
}

variable "ubuntu_version" {
  description = "Which version of Ubuntu to boot for the build"
  type = string
  default = "26.04"
}

# Optional - will be auto-derived from ubuntu_version if not provided
variable "ubuntu_version_name" {
  description = "Which release name of Ubuntu to boot for the build (auto-derived if empty)"
  type = string
  default = ""
}

variable "discenc" {
  description = "Encryption mode: NOENC, ZFSENC, LUKS"
  type        = string
  default     = "NOENC"
}

# Full path/source for ubuntu live iso image
# Can be downloaded from Ubuntu, or reference a local copy in some local dir
# For example  file:///home/myuser/ISOs
# For local ISOs, each ISO should be in the appropriate release-named dir
#              ⬇⬇⬇⬇⬇
#   /qemu/ISOs/focal/ubuntu-20.04.5-live-server-amd64.iso
#   /qemu/ISOs/jammy/ubuntu-22.04.5-live-server-amd64.iso
#              ⬆️⬆️⬆️⬆️⬆️
variable "ubuntu_live_iso_src" {
  description = "URI for the live ISO - can be a URL or local file:/// location"
  type = string
  default = "https://releases.ubuntu.com"
}

variable "disk_size" {
  type    = string
  default = "8G"
}

variable "additional_disks" {
  type    = list(string)
  default = []
}

variable "raidlevel" {
  type    = string
  default = ""
  description = "RAID level for multiple disks: mirror or raidz1"
}

variable "secureboot" {
  type    = bool
  default = false
  description = "Enable SecureBoot (requires SecureBoot-enabled OVMF firmware)"
}

variable "sshpubkey" {
  type    = string
  default = ""
  description = "Any additional ssh pubkey to add - used for CI/CD for packer"
}

variable "config_file" {
  description = "Config preseed file for ZFS-root.sh - defaults to ZFS-root.conf.packerci"
  type    = string
  default = "ZFS-root.conf.packerci"
}

variable "config_overrides" {
  description = "Map of config variables to override in overlay.conf (e.g., {MYHOSTNAME='myhost', POOLNAME='zroot'})"
  type    = map(string)
  default = {}
}

# OVMF firmware paths — allow override for systems without the _4M variant
# Ubuntu 24.04+: OVMF_CODE_4M.fd / OVMF_VARS_4M.fd
# Ubuntu 18.04:  OVMF_CODE.fd / OVMF_VARS.fd
variable "ovmf_code" {
  type    = string
  default = ""
  description = "Path to OVMF_CODE firmware file (empty=auto, see locals)"
}

variable "ovmf_vars" {
  type    = string
  default = ""
  description = "Path to OVMF_VARS firmware template (empty=auto, see locals)"
}

locals {
  # Auto-derive ubuntu_version_name from ubuntu_version if not explicitly set
  derived_version_name = (
    var.ubuntu_version_name != "" ? var.ubuntu_version_name :
    # Auto-derive based on version number
    length(regexall("^26\\.04", var.ubuntu_version)) > 0 ? "resolute" :
    length(regexall("^25\\.10", var.ubuntu_version)) > 0 ? "questing" :
    length(regexall("^25\\.04", var.ubuntu_version)) > 0 ? "plucky" :
    length(regexall("^24\\.04", var.ubuntu_version)) > 0 ? "noble" :
    length(regexall("^22\\.04", var.ubuntu_version)) > 0 ? "jammy" :
    length(regexall("^20\\.04", var.ubuntu_version)) > 0 ? "focal" :
    length(regexall("^18\\.04", var.ubuntu_version)) > 0 ? "bionic" :
    # If no match, this will cause an error which is better than silently failing
    "UNKNOWN_VERSION_${var.ubuntu_version}"
  )

  # OVMF firmware paths
  # Default to 4M variant (Ubuntu 24.04+); override via -var ovmf_code / ovmf_vars
  # for older systems (e.g. 18.04: OVMF_CODE.fd / OVMF_VARS.fd)
  ovmf_code = var.ovmf_code != "" ? var.ovmf_code : (
    var.secureboot ? "/usr/share/OVMF/OVMF_CODE_4M.secboot.fd" : "/usr/share/OVMF/OVMF_CODE_4M.fd"
  )
  ovmf_vars = var.ovmf_vars != "" ? var.ovmf_vars : "/usr/share/OVMF/OVMF_VARS_4M.fd"
  machine_type = var.secureboot ? "q35,smm=on" : "pc"

  # Include variant in output directory to allow parallel builds
  output_dir = "packer-${local.variant}-${local.timestamp}"
  timestamp  = formatdate("YYYY-MM-DD-hhmm", timestamp())
  ubuntu_live_iso = "${var.ubuntu_live_iso_src}/${local.derived_version_name}/ubuntu-${var.ubuntu_version}-live-server-amd64.iso"
  variant = "${local.derived_version_name}-${var.discenc}"

  # Calculate total number of disks (1 primary + additional)
  total_disks = 1 + length(var.additional_disks)

  # Validate and constrain raidlevel based on disk count
  # NOTE: Does not *enforce* a raidlevel - if you don't set mirror/raidz1
  #       then no raidlevel is set, so each disk is a vdev alone, with no
  #       redundancy at all
  actual_raidlevel = (
    local.total_disks == 1 ? "" :
    local.total_disks == 2 ? (var.raidlevel == "mirror" ? "mirror" : "") :
    # 3 or more disks
    (var.raidlevel == "mirror" || var.raidlevel == "raidz1" ? var.raidlevel : "")
  )

  # Generate the list of all disk files
  # Primary disk (index 0)
  primary_disk = "${var.output_prefix}${local.output_dir}/packer-${local.variant}-${local.timestamp}.qcow2"

  # Additional disks (indices 1, 2, 3, ...)
  # QEMU names them: base.qcow2-1, base.qcow2-2, etc.
  additional_disk_files = [
    for idx in range(length(var.additional_disks)) :
    "${var.output_prefix}${local.output_dir}/packer-${local.variant}-${local.timestamp}.qcow2-${idx + 1}"
  ]

  # All disks combined
  all_disk_files = concat([local.primary_disk], local.additional_disk_files)

  # Build the default config overrides (these are set automatically)
  default_overrides = {
    DISCENC      = var.discenc
    MYHOSTNAME   = "${local.derived_version_name}-${var.discenc}"
    POOLNAME     = local.derived_version_name
    SUITE        = local.derived_version_name
    RAIDLEVEL    = local.actual_raidlevel
    SSHPUBKEY    = var.sshpubkey
  }

  # Merge defaults with user overrides (user overrides win)
  final_overrides = merge(local.default_overrides, var.config_overrides)

  # Generate the overlay.conf content as a single shell script
  # We build it as one command that creates the entire file
  overlay_commands = [
    # Create file with all variables in one command using here-doc
    # Be SURE to use hard-TABs as first chars for indented heredoc
    <<-EOT
		cat > /tmp/overlay.conf <<-'OVERLAY_EOF'
		%{for key, value in local.final_overrides~}
		${key}="${value}"
		%{endfor~}
		OVERLAY_EOF
		EOT
    ,
    # Display the file
    "cat /tmp/overlay.conf"
  ]
}

source "qemu" "ubuntu" {
  vm_name           = "packer-${local.variant}-${local.timestamp}.qcow2"

  iso_url           = "${local.ubuntu_live_iso}"
  iso_checksum      = "file:https://releases.ubuntu.com/${var.ubuntu_version}/SHA256SUMS"
  # iso_checksum      = "10f19c5b2b8d6db711582e0e27f5116296c34fe4b313ba45f9b201a5007056cb" # 22.04.1

  cpus              = 2
  memory            = 4096
  accelerator       = "kvm"
  # Machine type: q35 required for SecureBoot, pc for standard boot
  # See machine_type in https://developer.hashicorp.com/packer/integrations/hashicorp/qemu/latest/components/builder/qemu
  # Can add -serial for extra logging - ensure /qemu/logs dir exists first
  # Also uncomment "mkdir /qemu/logs" in run-packer.sh
  # ["-serial", "file:/qemu/logs/packer-${local.variant}-${local.timestamp}-serial.log"]
  qemuargs = [
    ["-enable-kvm"],
    ["-machine", local.machine_type],
    ["-cpu", "host,+nx,+pae"]
  ]

  efi_firmware_code = local.ovmf_code
  efi_firmware_vars = local.ovmf_vars
  efi_boot          = true

  # NOTE: output_prefix MUST have trailing slash in var definition
  output_directory  = "${var.output_prefix}${local.output_dir}"

  # virtio-scsi needed to populate /dev/disk/by-id
  # virtio alone does not populate that
  disk_interface    = "virtio-scsi"
  disk_size         = var.disk_size
  format            = "qcow2"

  # For additional disks, use disk_additional_size(s) - see ZFS-root_local.vars.hcl
  # additional_disks  = ["5G"]  # for two total disks (one primary + one additional etc.)
  # For 3x disks total via cmdline  you can call packer with   packer build -var 'additional_disks=["5G","5G"]' ...
  disk_additional_size  = var.additional_disks

  http_directory    = "./"
  net_device        = "virtio-net-pci"

  ssh_username      = "ubuntu-server"
  ssh_password      = "packer"
  ssh_wait_timeout  = "30m"
  shutdown_command  = "sudo poweroff -f"  # force to avoid "remove installation media" msg
  headless          = "${var.headless}"   # NOTE: set this to true when using in CI Pipelines or docker
  display           = "${var.display}"    # sdl is most compatible, gtk is faster but may have issues with older systems

  boot_wait         = "150s"
  # Wait for live CD to fully boot and reach the "Try Ubuntu" prompt,
  # then trigger "Try Ubuntu" right away. Wait for the installer to
  # appear, then ctrl-z it into background to get a shell so we can
  # set a password for packer to ssh in and provision.
  # The 2m+ pre-Ctrl-Z window handles slower hardware (e.g. Xeon E5).
  boot_command = [
    "<wait><enter><wait10><wait10>",
    "<leftCtrlOn>z<leftCtrlOff>",
    "<wait10><enter><wait>",
    "ls -la /dev/vd* /dev/disk/by-id<enter><wait>",
    "echo ubuntu-server:packer | chpasswd<enter>"
  ]
}

build {
  sources = ["source.qemu.ubuntu"]

  # Get the ZFS-root.sh script and packer config into place
  provisioner "file" {
    source      = "ZFS-root.sh"
    destination = "/tmp/ZFS-root.sh"
  }

  provisioner "file" {
    source      = "${var.config_file}"
    destination = "/tmp/base.conf"
  }

  provisioner "file" {
    source      = "packer-validation"
    destination = "/tmp/"
  }

  provisioner "file" {
    source      = "./95zfs-rootflags-fix"
    destination = "/tmp/"
  }

  provisioner "file" {
    sources = ["logo.jpg", "logo_sm.jpg", "os_linux.png"]
    destination = "/tmp/"
  }

  # This writes the config overrides to overlay.conf
  # Combines automatic defaults (DISCENC, SUITE, etc.) with user --set overrides
  provisioner "shell" {
    inline = local.overlay_commands
  }

  # Actually run the ZFS-root.sh script to build the system as root
  # Put the debug output somewhere that ubuntu-server user can reach
  provisioner "shell" {
    execute_command = "echo 'packer' | sudo -S sh -c '{{ .Vars }} {{ .Path }}'"
    inline = [
      "cd /tmp",
      # Merge base and overlay (overlay wins if sourced last, or just cat them)
      "cat base.conf overlay.conf > final.conf",
      "chmod +x ZFS-root.sh",
      # Run with explicit config and packer mode
      "./ZFS-root.sh -p -c final.conf",
      # Rename log to include variant for host-side clarity
      "mv /root/ZFS-setup.log /tmp/ZFS-setup-${local.variant}.log"
    ]
  }

  # Push the config file used back to host machine
  provisioner "file" {
    source      = "/tmp/final.conf"
    destination = "${var.output_prefix}${local.output_dir}/ZFS-root_final.conf"
    direction   = "download"
  }

  # Push the debug output back to host machine
  provisioner "file" {
    source      = "/tmp/ZFS-setup-${local.variant}.log"
    destination = "${var.output_prefix}${local.output_dir}/build.log"
    direction   = "download"
  }

  # Create a metadata file with build settings for easy detection
  provisioner "shell-local" {
    # Be SURE to use hard-TABs as first chars for indented heredoc
    inline = [
      "cat > ${var.output_prefix}${local.output_dir}/build-metadata.txt <<-'METADATA_EOF'",
				"BUILD_DATE=${local.timestamp}",
				"UBUNTU_VERSION=${var.ubuntu_version}",
				"UBUNTU_NAME=${local.derived_version_name}",
				"DISCENC=${var.discenc}",
				"SECUREBOOT=${var.secureboot}",
				"RAIDLEVEL=${local.actual_raidlevel}",
				"TOTAL_DISKS=${local.total_disks}",
			"METADATA_EOF"
    ]
  }

  post-processor "manifest" {
    output     = "${var.output_prefix}${local.output_dir}/manifest.json"
    strip_path = true
  }

  post-processor "artifice" {
    files = concat(
      [
        "${var.output_prefix}${local.output_dir}/build.log",
        "${var.output_prefix}${local.output_dir}/manifest.json",
        "${var.output_prefix}${local.output_dir}/ZFS-root_final.conf",
        "${var.output_prefix}${local.output_dir}/packer-output.log"
      ],
      local.all_disk_files
    )
  }

  # Generate checksums for all disk files
  # Note: The checksum post-processor processes each file from artifice
  # and creates a checksum for each one
  post-processor "checksum" {
      checksum_types      = [ "sha256" ]
      output              = "${var.output_prefix}${local.output_dir}/packer-${local.variant}-${local.timestamp}.{{.ChecksumType}}.checksum"
      keep_input_artifact = true
  }
}
