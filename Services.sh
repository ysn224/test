# VSFTPD
echo -n "Should VSFTP Be Installed/Reinstalled? [Y/n] "
read option
if [[ $option =~ ^[Yy]$ ]]
then
 	apt-get -y install vsftpd > /dev/null 2>&1 
 	# Disable anonymous uploads
 	sed -i '/^anon_upload_enable/ c\anon_upload_enable no   #' /etc/vsftpd.conf # outdated?
 	sed -i '/^anonymous_enable/ c\anonymous_enable=NO  #' /etc/vsftpd.conf
	# FTP user directories use chroot
	sed -i '/^chroot_local_user/ c\chroot_local_user=YES  #' /etc/vsftpd.conf
	service vsftpd restart
else
	dpkg --purge vsftpd > /dev/null 2>&1 
fi


# Apache2
echo -n "Should Apache2 Be Installed/Reinstalled? [Y/n] "
read option
if [[ $option =~ ^[Yy]$ ]]
then
 	apt-get install apache2 libapache2-mod-php5  > /dev/null 2>&1 
file=$( echo /etc/apache2/conf-enabled/security.conf )
#replace ServerTokens and ServerSignature
sed -i 's/ServerTokens/ServerTokens Prod  # /g' $file
sed -i 's/ServerSignature/ServerSignature Off # /g' $file
echo "<Directory />
    		Options -Indexes 
		</Directory>" >> $file
#Critical File Permissions
	chown -R root:root /etc/apache2
	chown -R root:root /etc/apache

	#Secure Apache 2
	if [[ -e /etc/apache2/apache2.conf ]]; then
		echo \<Directory \> >> /etc/apache2/apache2.conf
		echo -e ' \t AllowOverride None' >> /etc/apache2/apache2.conf
		echo -e ' \t Order Deny,Allow' >> /etc/apache2/apache2.conf
		echo -e ' \t Deny from all' >> /etc/apache2/apache2.conf
		echo \<Directory \/\> >> /etc/apache2/apache2.conf
		echo UserDir disabled root >> /etc/apache2/apache2.conf
	fi
#THIS MAY BREAK APACHE2, NOT ENTIRELY SURE, TEST FIRST

 else
	  dpkg --purge apache2 > /dev/null 2>&1 
fi


# MySQL
echo -n "Should MySQL Be Installed/Reinstalled? [Y/n] "
read option
if [[ $option =~ ^[Yy]$ ]]
then
 	apt-get install mysql-server php5-mysql -y > /dev/null 2>&1 
	mysql_secure_installation
file=$( echo /etc/mysql/my.cnf )
#bind-address = 127.0.0.1 #
sed -i 's/bind-address/bind-address = 127.0.0.1 # /g' $file
service mysql restart

 else
	  dpkg --purge mysql-server php5-mysql > /dev/null 2>&1 
fi


# Php
echo -n "Should PHP5 Be Installed/Reinstalled? [Y/n] "
read option
if [[ $option =~ ^[Yy]$ ]]
then
 	apt-get install python-software-properties -y > /dev/null 2>&1 
	add-apt-repository ppa:ondrej/php5-oldstable
	apt-get update -y > /dev/null 2>&1 
	apt-get install -y php5 > /dev/null 2>&1 
	file=$(echo /etc/php5/apache2/php.ini)

	#At the end of each of these lines is a ; instead of a #, this is b/c this configuration has different syntax than bash and the ; tells it to comment the rest out.

	sed -i 's/expose_php/expose_php=Off ; /g' $file
sed -i 's/allow_url_fopen/allow_url_fopen=Off ; /g' $file
sed -i 's/allow_url_include/allow_url_include=Off ; /g' $file
#disable_functions 
sed -i 's/disable_functions=/disable_functions=exec,shell_exec,passthru,system,popen,curl_exec,curl_multi_exec,parse_ini_file,show_source,proc_open,pcntl_exec,/g' $file
sed -i 's/upload_max_filesize/upload_max_filesize = 2M ; /g' $file
sed -i 's/max_execution_time/max_execution_time = 30 ; /g' $file
sed -i 's/max_input_time/max_input_time = 60 ; /g' $file
else
	  dpkg --purge php5 > /dev/null 2>&1 
fi


# SSH
echo -n "Should SSH Be Installed/Reinstalled? [Y/n] "
read option
if [[ $option =~ ^[Yy]$ ]]
then
apt-get install ssh openssh-server openssh-client -y > /dev/null 2>&1 
#goes and replaces the /etc/ssh/sshd_config with clean one
echo "Replacing /etc/ssh/sshd_config" >> WorkProperly.txt
cp /etc/ssh/sshd_config /etc/ssh/.sshd_config
echo "# Package generated configuration file
# See the sshd_config(5) manpage for details
# What ports, IPs and protocols we listen for
Port 22
# Use these options to restrict which interfaces/protocols sshd will bind to
#ListenAddress ::
#ListenAddress 0.0.0.0
Protocol 2
# HostKeys for protocol version 2
HostKey /etc/ssh/ssh_host_rsa_key
HostKey /etc/ssh/ssh_host_dsa_key
HostKey /etc/ssh/ssh_host_ecdsa_key
#Privilege Separation is turned on for security
UsePrivilegeSeparation yes
# Lifetime and size of ephemeral version 1 server key
KeyRegenerationInterval 3600
ServerKeyBits 768
# Logging
SyslogFacility AUTH
LogLevel INFO

# Authentication:
LoginGraceTime 120
PermitRootLogin no
StrictModes yes

RSAAuthentication yes
PubkeyAuthentication yes
#AuthorizedKeysFile	%h/.ssh/authorized_keys

# Don't read the user's ~/.rhosts and ~/.shosts files
IgnoreRhosts yes
# For this to work you will also need host keys in /etc/ssh_known_hosts
RhostsRSAAuthentication no
# similar for protocol version 2
HostbasedAuthentication no
# Uncomment if you don't trust ~/.ssh/known_hosts for RhostsRSAAuthentication
#IgnoreUserKnownHosts yes
# To enable empty passwords, change to yes (NOT RECOMMENDED)

PermitEmptyPasswords no
# Change to yes to enable challenge-response passwords (beware issues with
# some PAM modules and threads)
ChallengeResponseAuthentication no

# Change to no to disable tunnelled clear text passwords
#PasswordAuthentication yes

# Kerberos options
#KerberosAuthentication no
#KerberosGetAFSToken no
#KerberosOrLocalPasswd yes
#KerberosTicketCleanup yes

# GSSAPI options
#GSSAPIAuthentication no
#GSSAPICleanupCredentials yes
X11Forwarding no

X11DisplayOffset 10
PrintMotd no
PrintLastLog yes
TCPKeepAlive yes
#UseLogin no

#MaxStartups 10:30:60
#Banner /etc/issue.net
# Allow client to pass locale environment variables
AcceptEnv LANG LC_*

Subsystem sftp /usr/lib/openssh/sftp-server

# Set this to 'yes' to enable PAM authentication, account processing,
# and session processing. If this is enabled, PAM authentication will
# be allowed through the ChallengeResponseAuthentication and
# PasswordAuthentication.  Depending on your PAM configuration,
# PAM authentication via ChallengeResponseAuthentication may bypass
# the setting of \"PermitRootLogin without-password\".
# If you just want the PAM account and session checks to run without
# PAM authentication, then enable this but set PasswordAuthentication
# and ChallengeResponseAuthentication to 'no'.
UsePAM yes" > /etc/ssh/sshd_config
service ssh restart
echo "" >> WorkProperly.txt
echo "Finished with SSH"

else
	dpkg --purge ssh openssh-server openssh-client > /dev/null 2>&1 
fi
