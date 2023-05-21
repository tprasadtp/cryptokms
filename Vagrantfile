# VM Configurations. All values except VM_BOX_VERSION are required.
VM_NAME = "cryptokms"
VM_BOX = "debian/testing64"
VM_BOX_VERSION = "v20230501.1"
VM_MEMORY = 512

# VM provisioning script
$provision = <<-SCRIPT
echo "---------------------------------"
echo "Installing Required Tools"
echo "---------------------------------"
apt-get update
apt-get install -y curl jq podman --install-recommends

echo "---------------------------------"
echo "Enable restarting containers on reboot"
echo "---------------------------------"
systemctl daemon-reload || echo "Failed  to reload systemd units"
systemctl enable podman-restart --now && echo "Enabled podman-restart.service" || echo "Failed to enable restarting containers on reboot"

echo "---------------------------------"
echo "Run AWS KMS emulator (nsmithuk/local-kms)"
echo "---------------------------------"
podman run -d --publish 8080:8080 --env KMS_REGION=us-east-1 --env=KMS_ACCOUNT_ID=000000000000 docker.io/nsmithuk/local-kms:latest
podman run -d --publish 8200:8200 docker.io/hashicorp/vault:latest
SCRIPT

# Template below is desiged to be used with libvirt and HyperV.
# Only debian images are supported.
# - HyperV
#    - Only Generation 2 VM
#    - VM integration is enabled by default
# - libvirt
#   - Only supported if provider and vagrant both are installed from distro repos.

Vagrant.require_version ">= 2.2.0"
Vagrant.configure("2") do |config|
  # Automatic CPU allocations and per host plugin verificataion.
  # Allocates all CPUs to VM by default.
  host = RbConfig::CONFIG['host_os']
  if host =~ /darwin/
    cpus = `sysctl -n hw.ncpu`.to_i
  elsif host =~ /linux/
    cpus = `nproc`.to_i
    # vagrant-libvirt plugin and vagrant should be installed from repos
    # for integration to work out of the box. Using upstream vagrant
    # with vagrant-libvirt from repos will not work.
    unless Vagrant.has_plugin?("vagrant-libvirt")
      puts "=> Missing plugin - vagrant-libvirt"
      puts "=> This project only supports libvirt boxes on linux."
      abort
    end
  elsif host =~ /windows/
    cpus = `powershell.exe -Command '(Get-CimInstance Win32_ComputerSystem).NumberOfLogicalProcessors'`.to_i
  else
    # Other platforms will not detect number of CPU cores. Statically allocate single core.
    cpus = 1
  end

  # Verify VM_NAME is defined and is a string.
  if defined?(VM_NAME)
    if ! VM_NAME.respond_to?(:to_s)
      puts "=> VM_NAME must be an string."
      abort
    else
      config.vm.define VM_NAME.to_s
    end
  else
    puts "=> VM_NAME is undefined!"
    puts "=> Please check if your Vagrantfile defines constant VM_NAME string."
    abort
  end

  # Verify VM_BOX is defined and is integer.
  if defined?(VM_BOX)
    if ! VM_BOX.respond_to?(:to_s)
      puts "=> VM_BOX must be string"
      abort
    end
  else
    puts "=> VM_BOX is undefined!"
    puts "=> Please check if your Vagrantfile defines constant VM_BOX set to box name."
    abort
  end

  # Verify VM_MEMORY is defined and is an integer.
  if defined?(VM_MEMORY)
    if ! VM_MEMORY.respond_to?(:to_i)
      puts "=> VM_MEMORY must be an integer."
      abort
    end
  else
    puts "=> VM_MEMORY is undefined!"
    puts "=> Please check if your Vagrantfile defines constant VM_MEMORY in megabytes."
    abort
  end

  # Verify if VM_BOX_VERSION is defined it is string.
  if defined?(VM_BOX_VERSION)
    if ! VM_BOX_VERSION.respond_to?(:to_s)
      puts "=> VM_BOX_VERSION must be string"
      abort
    end
  end

  # configure Box image name and version.
  # version is optional.
  config.vm.hostname = VM_NAME.to_s
  config.vm.box = VM_BOX.to_s
  if defined?(VM_BOX_VERSION)
    # Versions can have prefix v. Strip it.
    config.vm.box_version = VM_BOX_VERSION.to_s.delete_prefix("v")
  end

  # disable synced folder by default.
  config.vm.synced_folder ".", "/vagrant", disabled: true

  # configure libvirt machine.
  config.vm.provider "libvirt" do |libvirt, override|
    libvirt.title = VM_NAME.to_s
    libvirt.cpus = cpus
    libvirt.cpu_mode = 'host-passthrough'
    libvirt.memory = VM_MEMORY.to_i
    libvirt.nic_model_type = 'virtio'
    override.vm.network :private_network, :type => "dhcp", :libvirt__network_name => 'default'

    # - Run /usr/share/swtpm/swtpm-create-user-config-files as non-root if running with user session.
    #   See https://github.com/libvirt/libvirt/commit/c66115b6e81688649da13e00093278ce55c89cb5
    # - If not running as user session, ensure  that /var/lib/swtpm-localca is owned by swtpm:swtpm
    libvirt.tpm_type = 'emulator'
    libvirt.tpm_model = 'tpm-crb'
    libvirt.tpm_version = '2.0'

    libvirt.random :model => 'random'
    libvirt.graphics_type = "spice"
    (1..2).each do
      libvirt.redirdev :type => "spicevmc"
    end
    libvirt.channel :type => 'unix', :target_name => 'org.qemu.guest_agent.0', :target_type => 'virtio'

    $libvirt_provision = <<-SCRIPT
    echo "---------------------------------"
    echo "Installing qemu daemon"
    echo "---------------------------------"
    apt-get update
    apt-get install -y qemu-guest-agent
    SCRIPT

    # # Install libvirt guest agent.
    override.vm.provision "shell", inline: $libvirt_provision

    # override sync to use rsync if using libvirt providers
    override.vm.synced_folder ".", "/vagrant", type: "rsync", rsync__exclude: ".git/"
  end

  config.vm.provider "hyperv" do |hyperv, override|
    hyperv.vmname = VM_NAME.to_s
    hyperv.cpus = cpus
    hyperv.maxmemory = VM_MEMORY.to_i

    # Enable HyperV integration services
    hyperv.vm_integration_services = {
      guest_service_interface: true,
      time_synchronization: true,    # NTP Time services
      key_value_pair_exchange: true, # KV-Pair exchange service.
      heartbeat: true,               # Hyper-V Heartbeat.
      shutdown: true,                # ACPI.
      vss: true                      # Volume shadow copy service
    }

    $hyperv_provision = <<-SCRIPT
    echo "---------------------------------"
    echo "Installing HyperV daemons"
    echo "---------------------------------"
    apt-get update
    apt-get install -y hyperv-daemons
    SCRIPT

    # Install Hyper-V tools
    override.vm.provision "shell", inline: $hyperv_provision
  end

  # Provision Required Tools and Software.
  config.vm.provision "shell", inline: $provision
end
