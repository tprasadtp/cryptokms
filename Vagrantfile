VM_NAME = "cryptokms"

$install = <<-SCRIPT
echo "Installing Tools"
echo "---------------------------------"
dnf install -y curl jq htop
SCRIPT

Vagrant.require_version ">= 2.2.0"
Vagrant.configure("2") do |config|
  config.vm.box = "fedora/38-cloud-base"
  config.vm.box_version = "38.20230413.1"
  config.vm.define VM_NAME
  config.vm.hostname = VM_NAME
  config.vm.network "private_network", type: "dhcp"

  host = RbConfig::CONFIG['host_os']
  if host =~ /darwin/
    cpus = `sysctl -n hw.ncpu`.to_i
  elsif host =~ /linux/
    cpus = `nproc`.to_i
  else
    cpus = 2
  end

  # virtualbox is not officially supported
  config.vm.provider "virtualbox" do |virtualbox|
    virtualbox.name = VM_NAME
    virtualbox.cpus = cpus
    virtualbox.memory = 2048
  end

  config.vm.synced_folder ".", "/vagrant", disabled: true
  if Vagrant.has_plugin?("vagrant-libvirt")
    # vagrant-libvirt plugin and vagrant should be installed from repos
    # for integration to work out of the box. Using upstream vagrant
    # with vagrant-libvirt from repos will not work.
    config.vm.provider "libvirt" do |libvirt, override|
      libvirt.title = VM_NAME
      libvirt.cpus = cpus
      libvirt.cpu_mode = 'host-passthrough'
      libvirt.memory = 2048
      libvirt.machine_virtual_size = 30
      libvirt.nic_model_type = 'virtio'
      libvirt.random :model => 'random'
      libvirt.graphics_type = "spice"
      (1..2).each do
        libvirt.redirdev :type => "spicevmc"
      end
      libvirt.channel :type => 'unix', :target_name => 'org.qemu.guest_agent.0', :target_type => 'virtio'

      # - run /usr/share/swtpm/swtpm-create-user-config-files as non-root if running with user session.
      #   See https://github.com/libvirt/libvirt/commit/c66115b6e81688649da13e00093278ce55c89cb5
      # - If not running as user session, ensure  that /var/lib/swtpm-localca is owned by swtpm:swtpm
      libvirt.tpm_type = 'emulator'
      libvirt.tpm_model = 'tpm-crb'
      libvirt.tpm_version = '2.0'

    end
  end

  # config.vm.provision "podman" do |podman|
  #   podman.run "localkms_cryptokms",
  #       image: "nsmithuk/local-kms:latest",
  #       args: "-e KMS_REGION=us-east-1 -e KMS_ACCOUNT_ID=000000000000"
  # end
  config.vm.provision "shell", inline: $install
end
