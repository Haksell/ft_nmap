Vagrant.configure("2") do |config|
  config.vm.box = "debian/bullseye64"
  
  config.vm.provider "virtualbox" do |vb|
    vb.memory = 6144
    vb.cpus = 6
  end

  config.vm.provision "shell", inline: <<-SHELL
    export DEBIAN_FRONTEND=noninteractive

    apt-get update
    apt-get install -y binutils curl clang git make nmap valgrind zsh

    su -l vagrant -s "/bin/sh" -c "curl -fsSO https://raw.githubusercontent.com/ohmyzsh/ohmyzsh/master/tools/install.sh; chmod 755 install.sh; ./install.sh --unattended"
    sed -i 's/ZSH_THEME=".*"/ZSH_THEME="jonathan"/g' /home/vagrant/.zshrc
    chsh -s /bin/zsh vagrant
    echo "cd /vagrant" >> /home/vagrant/.zshrc

    ln -fs /usr/share/zoneinfo/Europe/Paris /etc/localtime
    echo "Europe/Paris" > /etc/timezone
    dpkg-reconfigure -f noninteractive tzdata
  SHELL
end
