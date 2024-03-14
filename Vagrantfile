Vagrant.configure("2") do |config|
  config.vm.box = "debian/bullseye64"
  
  config.vm.provider "virtualbox" do |vb|
    vb.memory = 6144
    vb.cpus = 6
  end

  config.vm.provision "shell", inline: <<-SHELL
    export DEBIAN_FRONTEND=noninteractive

    apt-get update
    apt-get install -y binutils build-essential bzip2 curl clang git make valgrind wget zsh openssl libssl-dev python3 python3-distutils
    
    wget https://nmap.org/dist/nmap-7.94.tar.bz2
    bzip2 -cd nmap-7.94.tar.bz2 | tar xvf -
    cd nmap-7.94
    ./configure
    make
    make install
    cd ..
    rm -rf nmap-*

    su -l vagrant -s "/bin/sh" -c "curl -fsSO https://raw.githubusercontent.com/ohmyzsh/ohmyzsh/master/tools/install.sh; chmod 755 install.sh; ./install.sh --unattended"
    sed -i 's/ZSH_THEME=".*"/ZSH_THEME="jonathan"/g' /home/vagrant/.zshrc
    chsh -s /bin/zsh vagrant
    echo "cd /vagrant" >> /home/vagrant/.zshrc

    ln -fs /usr/share/zoneinfo/Europe/Paris /etc/localtime
    echo "Europe/Paris" > /etc/timezone
    dpkg-reconfigure -f noninteractive tzdata
  SHELL
end
