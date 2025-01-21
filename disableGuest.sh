#!/bin/bash

# Path to LightDM configuration file
LIGHTDM_CONF="/etc/lightdm/lightdm.conf"

# Check if the LightDM configuration file exists
if [ -f "$LIGHTDM_CONF" ]; then
    echo "Modifying LightDM configuration..."

    # Function to add or replace a configuration
    modify_config() {
        local config="$1"
        local value="$2"
        
        # Check if the configuration already exists and modify it
        if grep -q "^$config" "$LIGHTDM_CONF"; then
            sudo sed -i "s/^$config=.*/$config=$value/" "$LIGHTDM_CONF"
            echo "Updated: $config=$value"
        else
            # If it doesn't exist, add the configuration to the file
            echo "$config=$value" | sudo tee -a "$LIGHTDM_CONF" > /dev/null
            echo "Added: $config=$value"
        fi
    }

    # List of configurations to be modified or added
    modify_config "allow-guest" "false"
    modify_config "greeter-hide-users" "true"
    modify_config "greeter-show-manual-login" "true"
    modify_config "autologin-user" "none"

    echo "LightDM configuration has been updated."

else
    echo "LightDM configuration file not found at $LIGHTDM_CONF. Please check the file path."
fi
