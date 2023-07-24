
#
# For running packer locally
#

output_prefix       = "/home/deano/VirtualBox/qemu/"

# false -> we can see the VM console gui
# true  -> console is hidden
headless            = false

ubuntu_version      = "22.04.1"
# Usually set to "" as the entire src dir is specified in ubuntu_live_iso_src
ubuntu_version_dir  = ""
ubuntu_live_iso_src = "file:///home/deano/VirtualBox/ISOs"
