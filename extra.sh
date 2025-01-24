#!/bin/bash

# Load users from approvedUsers.txt
allowed_users=()
while IFS= read -r line; do
    [[ -n "$line" ]] && allowed_users+=("$line")
done < approvedUsers.txt

# Load admins from approvedAdmin.txt
allowed_admins=()
while IFS= read -r line; do
    [[ -n "$line" ]] && allowed_admins+=("$line")
done < approvedAdmin.txt

# Find UID=0 users
echo "Find UID/GID=0 users? (y/n)"
read -r find_uid
if [[ "$find_uid" == "y" ]]; then
    uid0_users=$(awk -F: '($3 == 0 || $4 == 0) && $1 != "root" {print $1}' /etc/passwd)
    if [[ -n "$uid0_users" ]]; then
        echo "WARNING: UID/GID=0 USERS FOUND:"
        echo "$uid0_users"
    else
        echo "No UID/GID=0 users found."
    fi
fi
echo "---------"

# Reset /etc/rc.local
echo "Reset /etc/rc.local? (y/n)"
read -r reset_rc
if [[ "$reset_rc" == "y" ]]; then
    sudo cp -n /etc/rc.local backup/rc.local
    echo -e "#!/bin/bash\nexit 0" | sudo tee /etc/rc.local > /dev/null
    sudo chmod +x /etc/rc.local
    echo "/etc/rc.local reset to default."
fi
echo "---------"

# Reset sources.list
echo "Reset sources.list? (y/n)"
read -r reset_sources
if [[ "$reset_sources" == "y" ]]; then
    codename=$(lsb_release -sc)
    sudo cp -n /etc/apt/sources.list backup/sources.list
    {
        echo "deb http://archive.ubuntu.com/ubuntu $codename main multiverse universe restricted"
        echo "deb http://archive.ubuntu.com/ubuntu $codename-security main multiverse universe restricted"
    } | sudo tee /etc/apt/sources.list > /dev/null
    sudo apt update
    echo "sources.list reset and updated."
fi
echo "---------"

# Change passwords for allowed users (not admins)
echo "Change all allowed users' passwords (not admins)? (y/n)"
read -r change_passwords
if [[ "$change_passwords" == "y" ]]; then
    for user in "${allowed_users[@]}"; do
        if [[ ! " ${allowed_admins[@]} " =~ " $user " ]]; then
            echo "Changing password for user: $user"
            echo -e "Cyberpatriot1!\nCyberpatriot1!" | sudo passwd "$user" > /dev/null
            echo "Password changed for $user."
        fi
    done
fi
echo "---------"

# Secure shared memory
echo "Secure shared memory? (y/n)"
read -r secure_memory
if [[ "$secure_memory" == "y" ]]; then
    if ! grep -q "# Script ran" /etc/fstab; then
        echo -e "\n# Script ran\nnone     /run/shm     tmpfs     rw,noexec,nosuid,nodev     0     0" | sudo tee -a /etc/fstab > /dev/null
        echo "Shared memory secured."
    else
        echo "Shared memory is already secured."
    fi
fi
echo "---------"

# Install and configure fail2ban
echo "Install and configure fail2ban? (y/n)"
read -r install_fail2ban
if [[ "$install_fail2ban" == "y" ]]; then
    sudo apt install -y fail2ban
    sudo cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local
    sudo systemctl enable fail2ban
    sudo systemctl start fail2ban
    echo "Fail2ban installed and configured."
fi
echo "---------"
