
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
  default = "24.04.2"
}

# Full path/source for ubuntu live iso image
# Can be pulled from Ubuntu, or reference a local copy in some local dir
# For example  file:///home/myuser/ISOs
variable "ubuntu_live_iso_src" {
  description = "URI for the live ISO - can be a URL or local file:/// location"
  type = string
  default = "https://releases.ubuntu.com/24.04.2"
}

variable "disk_size" {
  type    = string
  default = "10G"
}

variable "additional_disks" {
  type    = list(string)
  default = []
}

locals {
  output_dir = "packer-zfsroot-${local.timestamp}"
  timestamp  = formatdate("YYYY-MM-DD-hhmm", timestamp())
  ubuntu_live_iso = "${var.ubuntu_live_iso_src}/ubuntu-${var.ubuntu_version}-live-server-amd64.iso"
}

source "qemu" "ubuntu" {
  vm_name           = "packer-zfsroot-${local.timestamp}.qcow2"

  iso_url           = "${local.ubuntu_live_iso}"
  iso_checksum      = "file:https://releases.ubuntu.com/${var.ubuntu_version}/SHA256SUMS"
  # iso_checksum      = "10f19c5b2b8d6db711582e0e27f5116296c34fe4b313ba45f9b201a5007056cb" # 22.04.1

  cpus              = 2
  memory            = 2048
  accelerator       = "kvm"
  # Set machine type to q35 for secureboot
  # See machine_type in https://developer.hashicorp.com/packer/integrations/hashicorp/qemu/latest/components/builder/qemu
  qemuargs = [
    ["-enable-kvm"], 
    ["-machine", "pc"],
    ["-cpu", "host,+nx,+pae"]
  ]

  efi_firmware_code = "/usr/share/OVMF/OVMF_CODE_4M.fd"
  efi_firmware_vars = "/usr/share/OVMF/OVMF_VARS_4M.fd"
  efi_boot          = true

  # NOTE: output_prefix MUST have trailing slash in var definition
  output_directory  = "${var.output_prefix}${local.output_dir}"

  # virtio-scsi needed to populate /dev/disk/by-id
  # virtio alone does not populate that
  disk_interface    = "virtio-scsi"
  disk_size         = var.disk_size
  format            = "qcow2"

  # For additional disks, use disk_additional_size(s) - see ZFS-root_local.vars.hcl
  disk_additional_size  = var.additional_disks

  http_directory    = "./"
  net_device        = "virtio-net"

  ssh_username      = "ubuntu-server"
  ssh_password      = "packer"
  ssh_wait_timeout  = "30m"
  shutdown_command  = "sudo poweroff -f"  # force to avoid "remove installation media" msg
  headless          = "${var.headless}"   # NOTE: set this to true when using in CI Pipelines

  boot_wait         = "10s"
  # Trigger the "Try Ubuntu" right away, then wait 60secs to get to installer
  # ctrl-z the installer into background to get shell, then
  # need to set a password so packer can ssh in to provision.
  # Could also curl ZFS-root.sh/.conf then run script right here
  boot_command = [
    "<wait><enter><wait60>",
    "<leftCtrlOn>z<leftCtrlOff>",
    "<wait><enter><wait>", 
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
    source      = "ZFS-root.conf.packerci"
    destination = "/tmp/ZFS-root.conf.packerci"
  }

  provisioner "file" {
    source      = "./95zfs-rootflags-fix"
    destination = "/tmp/"
  }

  # Actually run the ZFS-root.sh script to build the system as root
  # Put the debug output somewhere that ubuntu-server user can reach
  provisioner "shell" {
    execute_command = "echo 'packer' | sudo -S sh -c '{{ .Vars }} {{ .Path }}'"
    inline = [
      "cd /tmp",
      "./ZFS-root.sh -p",
      "mv /root/ZFS-setup.log /tmp/ZFS-setup-packerci.log"
    ]
  }

  # Push the debug output back to host machine
  provisioner "file" {
    source      = "/tmp/ZFS-setup-packerci.log"
    destination = "${var.output_prefix}${local.output_dir}/ZFS-setup-packerci.log"
    direction   = "download"
  }

  post-processor "manifest" {
    output     = "${var.output_prefix}${local.output_dir}/manifest.json"
    strip_path = true 
  }

  post-processor "artifice" {
    files = [
      "${var.output_prefix}${local.output_dir}/ZFS-setup-packerci.log",
      "${var.output_prefix}${local.output_dir}/manifest.json", 
      "${var.output_prefix}${local.output_dir}/packer-zfsroot-${local.timestamp}.qcow2"
    ]
  }
  # Finally Generate a Checksum (SHA256) which can be used for further stages in the `output` directory
  post-processor "checksum" {
      checksum_types      = [ "sha256" ]
      output              = "${var.output_prefix}${local.output_dir}/packer-zfsroot-${local.timestamp}.qcow2.{{.ChecksumType}}"
      keep_input_artifact = true
  }
}
