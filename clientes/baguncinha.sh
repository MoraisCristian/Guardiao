#!/bin/bash

# Common users and their default passwords
declare -A users=(
    ["root"]="root"
    ["admin"]="admin"
    ["ubuntu"]="ubuntu"
    ["debian"]="debian"
    ["kali"]="kali"
)

# Function to generate random password
generate_random_password() {
    tr -dc A-Za-z0-9 </dev/urandom | head -c 12
}

# Function to simulate login attempt
simulate_login() {
    local username=$1
    local password=$2
    echo "Attempting login with: $username:$password"
    # Replace this with your actual login command
    # sshpass -p "$password" ssh "$username@localhost"
}

# Test common users
for user in "${!users[@]}"; do
    password=${users[$user]}
    simulate_login "$user" "$password"
done

# Test random root passwords
for i in {1..6}; do
    random_password=$(generate_random_password)
    simulate_login "root" "$random_password"
done

echo "All login attempts completed!"