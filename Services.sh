# VSFTPD

echo -n "Should VSFTP Be Installed/Reinstalled? [Y/n] "
read option
if [[ $option =~ ^[Yy]$ ]]
then
  sudo apt-get -y install vsftpd > /dev/null 2>&1 
  # Disable anonymous uploads
  sudo sed -i '/^anon_upload_enable/ s/=.*/= NO/' /etc/vsftpd.conf
  sudo sed -i '/^anonymous_enable/ s/=.*/= NO/' /etc/vsftpd.conf
  # FTP user directories use chroot
  sudo sed -i '/^chroot_local_user/ s/=.*/= YES/' /etc/vsftpd.conf
  sudo systemctl restart vsftpd
else
  sudo dpkg --purge vsftpd > /dev/null 2>&1 
fi



# Apache2
#!/bin/bash

echo -n "Should Apache2 Be Installed/Reinstalled? [Y/n] "
read option
if [[ $option =~ ^[Yy]$ ]]
then
  sudo apt-get install apache2 libapache2-mod-php7.4 > /dev/null 2>&1
  file="/etc/apache2/conf-enabled/security.conf"
  
  # Replace ServerTokens and ServerSignature
  sudo sed -i 's/^ServerTokens.*/ServerTokens Prod/' $file
  sudo sed -i 's/^ServerSignature.*/ServerSignature Off/' $file
  
  # Append directory settings
  echo "<Directory />
        Options -Indexes
  </Directory>" | sudo tee -a $file
  
  # Critical File Permissions
  sudo chown -R root:root /etc/apache2

  # Secure Apache2
  if [[ -e /etc/apache2/apache2.conf ]]; then
    sudo echo -e "<Directory />" | sudo tee -a /etc/apache2/apache2.conf
    sudo echo -e "    AllowOverride None" | sudo tee -a /etc/apache2/apache2.conf
    sudo echo -e "    Order Deny,Allow" | sudo tee -a /etc/apache2/apache2.conf
    sudo echo -e "    Deny from all" | sudo tee -a /etc/apache2/apache2.conf
    sudo echo -e "</Directory>" | sudo tee -a /etc/apache2/apache2.conf
    sudo echo "UserDir disabled root" | sudo tee -a /etc/apache2/apache2.conf
  fi
  
  # Restart Apache
  sudo systemctl restart apache2
else
  sudo dpkg --purge apache2 > /dev/null 2>&1
fi


# MySQL
echo -n "Should MySQL Be Installed/Reinstalled? [Y/n] "
read option
if [[ $option =~ ^[Yy]$ ]]
then
  # Install MySQL and PHP MySQL extension
  apt-get install mysql-server php5-mysql -y > /dev/null 2>&1 

  # Run MySQL secure installation (this will prompt you for setting a root password, removing insecure defaults, etc.)
  mysql_secure_installation

  # Define the path to the MySQL config file
  file="/etc/mysql/my.cnf"

  # Modify the bind-address to allow MySQL to only listen on localhost (127.0.0.1)
  sed -i 's/^bind-address.*/bind-address = 127.0.0.1 # /g' $file

  # Restart MySQL service to apply the changes
  service mysql restart

else
  # Purge MySQL and its PHP extension if the user chooses to uninstall
  dpkg --purge mysql-server php5-mysql > /dev/null 2>&1 
fi



# PHP
echo -n "Should PHP5 Be Installed/Reinstalled? [Y/n] "
read option
if [[ $option =~ ^[Yy]$ ]]
then
  # Install python-software-properties package (needed for adding repositories)
  apt-get install python-software-properties -y > /dev/null 2>&1 

  # Add PPA repository for PHP5 (old stable)
  add-apt-repository ppa:ondrej/php5-oldstable
  apt-get update -y > /dev/null 2>&1 

  # Install PHP5
  apt-get install -y php5 > /dev/null 2>&1 

  # Define the path to the PHP configuration file
  file="/etc/php5/apache2/php.ini"

  # Modify PHP settings using sed
  sed -i 's/expose_php/expose_php=Off ; /g' $file
  sed -i 's/allow_url_fopen/allow_url_fopen=Off ; /g' $file
  sed -i 's/allow_url_include/allow_url_include=Off ; /g' $file
  sed -i 's/disable_functions=/disable_functions=exec,shell_exec,passthru,system,popen,curl_exec,curl_multi_exec,parse_ini_file,show_source,proc_open,pcntl_exec,/g' $file
  sed -i 's/upload_max_filesize/upload_max_filesize = 2M ; /g' $file
  sed -i 's/max_execution_time/max_execution_time = 30 ; /g' $file
  sed -i 's/max_input_time/max_input_time = 60 ; /g' $file

else
  # If user chooses "no", purge PHP5
  dpkg --purge php5 > /dev/null 2>&1 
fi



# SSH
echo -n "Should SSH Be Installed/Reinstalled? [Y/n] "
read option
if [[ $option =~ ^[Yy]$ ]]
then
  # Install SSH components
  apt-get install ssh openssh-server openssh-client -y > /dev/null 2>&1 

  # Log the action of replacing sshd_config
  echo "$(date '+%Y-%m-%d %H:%M:%S') - Replacing /etc/ssh/sshd_config" >> WorkProperly.txt

  # Backup the current sshd_config before overwriting
  cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup
  if [[ $? -eq 0 ]]; then
    echo "$(date '+%Y-%m-%d %H:%M:%S') - Backup of sshd_config successful." >> WorkProperly.txt
  else
    echo "$(date '+%Y-%m-%d %H:%M:%S') - Backup of sshd_config failed." >> WorkProperly.txt
  fi

  # Replace the sshd_config with the new configuration
  echo "# Package generated configuration file
# See the sshd_config(5) manpage for details
# What ports, IPs and protocols we listen for
Port 22
Protocol 2
HostKey /etc/ssh/ssh_host_rsa_key
HostKey /etc/ssh/ssh_host_dsa_key
HostKey /etc/ssh/ssh_host_ecdsa_key
UsePrivilegeSeparation yes
KeyRegenerationInterval 3600
ServerKeyBits 768
SyslogFacility AUTH
LogLevel INFO
LoginGraceTime 120
PermitRootLogin no
StrictModes yes
RSAAuthentication yes
PubkeyAuthentication yes
IgnoreRhosts yes
RhostsRSAAuthentication no
HostbasedAuthentication no
PermitEmptyPasswords no
ChallengeResponseAuthentication no
KerberosAuthentication no
GSSAPIAuthentication no
X11Forwarding no
X11DisplayOffset 10
PrintMotd no
PrintLastLog yes
TCPKeepAlive yes
ClientAliveInterval 60
ClientAliveCountMax 3
MaxAuthTries 3
LoginGraceTime 20
PermitUserEnvironment no
AllowAgentForwarding no
AllowTcpForwarding no
PermitTunnel no
AcceptEnv LANG LC_*
Subsystem sftp /usr/lib/openssh/sftp-server
UsePAM yes" > /etc/ssh/sshd_config

  # Restart SSH service to apply changes
  service ssh restart
  if [[ $? -eq 0 ]]; then
    echo "$(date '+%Y-%m-%d %H:%M:%S') - SSH service restarted successfully." >> WorkProperly.txt
  else
    echo "$(date '+%Y-%m-%d %H:%M:%S') - SSH service restart failed." >> WorkProperly.txt
  fi

  # Log completion
  echo "$(date '+%Y-%m-%d %H:%M:%S') - Finished with SSH configuration" >> WorkProperly.txt

else
  # Purge SSH if the user opts out
  dpkg --purge ssh openssh-server openssh-client > /dev/null 2>&1 
  echo "$(date '+%Y-%m-%d %H:%M:%S') - SSH uninstalled." >> WorkProperly.txt
fi

