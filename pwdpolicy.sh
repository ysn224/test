#!usr/bin/env bash

echo "Setting password policy, please ensure you are logged in as root."
read -p "Press Enter to continue..."

apt install -y libpam-pwquality #-y: will say yes and install automatically without prompting

#login.defs settings
sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   60/' /etc/login.defs #^ means find line that starts with the following phrase
sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS   1/' /etc/login.defs #.* means replace the entire line (* represents all the following characters)
sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE   7/' /etc/login.defs #phrase between /   / is the new line
sed -i 's/^LOGIN_RETRIES.*/LOGIN_RETRIES   3/' /etc/login.defs
sed -i 's/^LOGIN_TIMEOUT.*/LOGIN_TIMEOUT   60/' /etc/login.defs

#pam.d settings
sed -i 's/^password.*pam_pwquality.so.*/password  requisite  pam_pwquality.so retry=3 minlen=10 difok=3 ucredit=-1 lcredit=-1 ocredit=-1 dcredit=-1/' /etc/pam.d/common-password
#need also in /etc/security/pwquality.conf + dictionary check

# Ensure pam_unix.so is correctly configured 
sed -i 's/^\(password.*pam_unix.so.*\)/\1 obscure use_authtok try_first_pass yescrypt remember=5/' /etc/pam.d/common-password
# back up version sed -i 's/[success.*/[success=1, default=ignore]    pam_unix.so obscure use_authtok try_first_pass yescrypt remember=5/' /etc/pam.d/common-password

#pwquality
#enable dictionary check
CONFIG_FILE="/etc/security/pwquality.conf"
if grep -q "^dictcheck" "$CONFIG_FILE"; then
        sed -i 's/^dictcheck=.*/dictcheck=1/' "CONFIG_FILE"
else
        echo "dictcheck=1" >> "$CONFIG_FILE"
fi

#failed login don't authenticate?

# Function to configure PAM account locking
configure_pam_account_locking() {
    echo "Configuring PAM account locking..."

    pam_config_file="/etc/pam.d/common-auth"  # Path for Ubuntu/Debian systems

    # Check if pam_faillock is already configured in common-auth
    if grep -q "pam_faillock.so" "$pam_config_file"; then
        echo "PAM account locking already configured."
    else
        # Add pam_faillock configuration to pam.d/common-auth
        echo -e "\n# Lock accounts after 3 failed attempts" | sudo tee -a "$pam_config_file" > /dev/null
        echo "auth required pam_faillock.so preauth audit silent deny=3 unlock_time=600" | sudo tee -a "$pam_config_file" > /dev/null
        echo "auth required pam_faillock.so authfail audit deny=3 unlock_time=600" | sudo tee -a "$pam_config_file" > /dev/null

        echo "PAM account locking configured successfully."
    fi
}

# Function to configure PAM password policy
configure_pam_password_policy() {
    echo "Configuring PAM password policy..."

    pam_password_file="/etc/pam.d/common-password"  # Path for Ubuntu/Debian systems

    # Check if pam_pwquality is already configured in common-password
    if grep -q "pam_pwquality.so" "$pam_password_file"; then
        echo "PAM password policy already configured."
    else
        # Add pam_pwquality configuration to common-password
        echo -e "\n# Enforce strong password policy" | sudo tee -a "$pam_password_file" > /dev/null
        echo "password requisite pam_pwquality.so retry=3 minlen=12 minclass=4" | sudo tee -a "$pam_password_file" > /dev/null

        echo "PAM password policy configured successfully."
    fi
}

# Main function to configure PAM settings
noauthenticate() {
    echo "Configuring PAM security settings..."
    configure_pam_account_locking
    configure_pam_password_policy
    echo "PAM security configuration completed."
}

# Execute the main function
noauthenticate


#set encryption to sha512?

# Function to check and set SHA-512 password hashing in /etc/login.defs
check_and_set_sha512_in_login_defs() {
    echo "Checking and setting SHA-512 in /etc/login.defs..."

    login_defs_file="/etc/login.defs"

    # Check if ENCRYPT_METHOD is set to SHA512 in /etc/login.defs
    if grep -q "^ENCRYPT_METHOD" "$login_defs_file"; then
        if ! grep -q "SHA512" "$login_defs_file"; then
            echo "Password hashing method is not SHA-512 in /etc/login.defs. Updating..."
            # Update to SHA-512
            sudo sed -i 's/^ENCRYPT_METHOD.*/ENCRYPT_METHOD SHA512/' "$login_defs_file"
            echo "Updated password hashing method to SHA-512 in /etc/login.defs."
        else
            echo "Password hashing method is already SHA-512 in /etc/login.defs."
        fi
    else
        echo "ENCRYPT_METHOD not found in /etc/login.defs. Adding SHA-512..."
        echo "ENCRYPT_METHOD SHA512" | sudo tee -a "$login_defs_file" > /dev/null
        echo "Added SHA-512 to /etc/login.defs."
    fi
}

# Function to check and set SHA-512 in /etc/pam.d/common-password
check_and_set_sha512_in_common_password() {
    echo "Checking and setting SHA-512 in /etc/pam.d/common-password..."

    common_password_file="/etc/pam.d/common-password"

    # Check if SHA-512 is set in /etc/pam.d/common-password
    if grep -q "sha512" "$common_password_file"; then
        echo "Password hashing is already set to SHA-512 in /etc/pam.d/common-password."
    else
        echo "SHA-512 not found in /etc/pam.d/common-password. Updating..."
        # Add or modify line to use sha512
        sudo sed -i 's/^password.*pam_unix.so.*/password requisite pam_unix.so sha512/' "$common_password_file"
        echo "Updated password hashing method to SHA-512 in /etc/pam.d/common-password."
    fi
}

# Main function to check and set SHA-512 password hashing
configure_sha512_password_hashing() {
    echo "Checking and setting password hashing method to SHA-512..."
    check_and_set_sha512_in_login_defs
    check_and_set_sha512_in_common_password
    echo "Password hashing verification and updates complete."
}

# Call the main function
configure_sha512_password_hashing

#disable null password
# Check if the file exists
if [ -f /etc/pam.d/common-password ]; then
    echo "Modifying /etc/pam.d/common-password to disable null passwords..."

    # Backup the file before making changes
    sudo cp /etc/pam.d/common-password /etc/pam.d/common-password.backup

    # Remove 'nullok' if it exists in the common-password file
    sudo sed -i '/nullok/d' /etc/pam.d/common-password

    # Inform the user
    echo "Null passwords have been disabled. Please check your system's PAM configuration for verification."
else
    echo "Error: PAM configuration file /etc/pam.d/common-password not found."
    exit 1
fi



# Confirmation message
echo "Password policy has been updated. Please test to ensure it works as expected."

#to do
#failed login do not authenticate
#dictionary check enable y
#encryption set to SHA512
#password history policy configured
#add for pwquality.conf
