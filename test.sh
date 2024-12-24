#!/bin/bash
export DEBIAN_FRONTEND=noninteractive

# Ensure the script is run as root
if [ "$(id -u)" != "0" ]; then
   echo "This script must be run as root" 1>&2
   exit 1
fi

# Parse command line arguments
while getopts "s:" opt; do
  case ${opt} in
    s )
      radius_server_ip=$OPTARG
      ;;
    \? )
      echo "Usage: $0 -s radius_server_ip"
      exit 1
      ;;
  esac
done

# Check if radius_server_ip is provided
if [ -z "$radius_server_ip" ]; then
  echo "Please provide the RADIUS server IP using -s option."
  exit 1
fi

# Define EasyRSA version for easy updates
EASYRSA_VERSION="3.0.1"

# Update package list and install OpenVPN and Easy-RSA
apt-get update
apt-get install -y openvpn easy-rsa iptables-persistent nginx freeradius freeradius-utils uuid-runtime

# Download and verify EasyRSA
wget -O ~/EasyRSA-$EASYRSA_VERSION.tgz "https://github.com/OpenVPN/easy-rsa/releases/download/$EASYRSA_VERSION/EasyRSA-$EASYRSA_VERSION.tgz"

# Extract EasyRSA and set permissions
tar xzf ~/EasyRSA-$EASYRSA_VERSION.tgz -C /etc/openvpn/
mv /etc/openvpn/EasyRSA-$EASYRSA_VERSION/ /etc/openvpn/easy-rsa/
chown -R root:root /etc/openvpn/easy-rsa/
rm ~/EasyRSA-$EASYRSA_VERSION.tgz

# Initialize Easy-RSA and build CA
cd /etc/openvpn/easy-rsa/
./easyrsa init-pki
./easyrsa --batch build-ca nopass
./easyrsa gen-dh
./easyrsa build-server-full server nopass
./easyrsa gen-crl

# Move necessary files and set correct permissions
cp pki/ca.crt pki/private/ca.key pki/dh.pem pki/issued/server.crt pki/private/server.key pki/crl.pem /etc/openvpn/
chown nobody:nogroup /etc/openvpn/crl.pem

# Generate key for tls-auth
openvpn --genkey secret /etc/openvpn/ta.key

# Get the server IP Address
if [[ "$IP" = "" ]]; then
    IP=$(wget -4qO- "http://whatismyip.akamai.com/")
    if [[ "$IP" = "" ]]; then
        IP=$(wget -4qO- "http://ipecho.net/plain")
    fi
fi

# Network optimizations for high concurrency
cat >> /etc/sysctl.conf <<EOF
net.core.rmem_max=2097152
net.core.wmem_max=2097152
net.ipv4.tcp_rmem=4096 87380 2097152
net.ipv4.tcp_wmem=4096 65536 2097152
net.ipv4.ip_forward=1
EOF
sysctl -p

# File path for the authentication script
auth_script_path="/etc/openvpn/auth_script.sh"

# Contents of the authentication script
auth_script_content="#!/bin/bash

# Script to authenticate against FreeRADIUS using radtest

# Path to the temporary file is passed as the first argument
credentials_file=\"\$1\"

# Read username and password from the file
username=\$(awk 'NR==1' \$credentials_file)
password=\$(awk 'NR==2' \$credentials_file)

# RADIUS server details
radius_server=\"$radius_server_ip\"
radius_secret=\"testing123\"
radius_port=\"1812\"  # Default RADIUS port for authentication

# Send request to RADIUS server using radtest
response=\$(radtest \"\$username\" \"\$password\" \$radius_server \$radius_port \$radius_secret)

# Check response
if echo \"\$response\" | grep -q \"Access-Accept\"; then
    exit 0  # Authentication successful
else
    exit 1  # Authentication failed
fi"

# Create the authentication script file
echo "$auth_script_content" > "$auth_script_path"

# Give read and write permissions to the script
chmod +x "$auth_script_path"

# Create RADIUS accounting script
accounting_script_path="/etc/openvpn/accounting_script.sh"

accounting_script_content="#!/bin/bash

# Log accounting events to /var/log/openvpn/accounting.log
log_file=\"/var/log/openvpn/accounting.log\"

# Define RADIUS server shared secret and IP
radius_server_ip=\"$radius_server_ip\"
radius_secret=\"testing123\"

# Extract important OpenVPN environment variables
username=\"\$common_name\"
client_ip=\"\$ifconfig_pool_remote_ip\"
server_ip=\"\$trusted_ip\"
bytes_received=\"\${bytes_received:-0}\"  # Ensure bytes received has a default value
bytes_sent=\"\${bytes_sent:-0}\"  # Ensure bytes sent has a default value
time_connected=\$(date)

# Generate session ID if not provided
if [ -z \"\$tls_id\" ]; then
    session_id=\$(uuidgen)  # Generate a UUID for the session ID if it's not provided
else
    session_id=\"\$tls_id\"
fi

# Check if it's a client connect or disconnect event
if [ \"\$script_type\" = \"client-connect\" ]; then
    # Log client connection
    echo \"[\$time_connected] CONNECT: User '\$username' (Session ID: \$session_id) connected with IP \$client_ip\" >> \$log_file

    # Send data to RADIUS server for accounting start
    echo \"User-Name=\$username
Acct-Session-Id=\$session_id
Framed-IP-Address=\$client_ip
NAS-IP-Address=\$server_ip
Acct-Status-Type=Start\" | radclient -x \$radius_server_ip acct \$radius_secret

elif [ \"\$script_type\" = \"client-disconnect\" ]; then
    # Log client disconnection and bandwidth usage
    echo \"[\$time_connected] DISCONNECT: User '\$username' (Session ID: \$session_id) disconnected. Bytes received: \$bytes_received, Bytes sent: \$bytes_sent\" >> \$log_file

    # Send data to RADIUS server for accounting stop
    echo \"User-Name=\$username
Acct-Session-Id=\$session_id
Framed-IP-Address=\$client_ip
NAS-IP-Address=\$server_ip
Acct-Input-Octets=\$bytes_received
Acct-Output-Octets=\$bytes_sent
Acct-Status-Type=Stop\" | radclient -x \$radius_server_ip acct \$radius_secret
fi"

# Create the accounting script file
echo "$accounting_script_content" > "$accounting_script_path"

# Give read and write permissions to the accounting script
chmod +x "$accounting_script_path"

# Create server configuration with secure defaults
cat > /etc/openvpn/server.conf <<EOF
port 1194
proto udp
dev tun
ca ca.crt
cert server.crt
key server.key
dh dh.pem
topology subnet
server 10.8.0.0 255.255.252.0
# ifconfig-pool-persist ipp.txt
push "redirect-gateway def1 bypass-dhcp"
push "dhcp-option DNS 8.8.8.8"
push "dhcp-option DNS 8.8.4.4"
keepalive 10 120
auth-nocache
#cipher AES-256-CBC
cipher AES-128-GCM
auth SHA256
user nobody
group nogroup
persist-key
persist-tun
# log /var/log/openvpn.log
# status /var/log/openvpn-status.log
verb 0
explicit-exit-notify 1
auth-user-pass-verify /etc/openvpn/auth_script.sh via-file
client-connect /etc/openvpn/accounting_script.sh
client-disconnect /etc/openvpn/accounting_script.sh
script-security 2
management 127.0.0.1 7505
--verify-client-cert none
username-as-common-name

ifconfig-pool-persist /dev/null
log /dev/null
status /dev/null

max-clients 1024
# sndbuf 524288
# rcvbuf 524288
# push "sndbuf 524288"
# push "rcvbuf 524288"
tcp-queue-limit 256
sndbuf 1048576
rcvbuf 1048576
push "sndbuf 1048576"
push "rcvbuf 1048576"
# inactive 3600
EOF

# Enable IP forwarding
sed -i '/net.ipv4.ip_forward=1/s/^#//g' /etc/sysctl.conf
sysctl -p

# Set up iptables for NAT and forwarding with comments for clarity
iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o eth0 -j MASQUERADE
iptables -A INPUT -p udp --dport 1194 -j ACCEPT
iptables -A OUTPUT -p udp --sport 1194 -j ACCEPT
iptables -A FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
iptables -A FORWARD -s 10.8.0.0/24 -j ACCEPT

# Save iptables rules
netfilter-persistent save

# Create client configuration directory
mkdir -p /etc/openvpn/client

# Set up the client configuration file with secure defaults
cat > /etc/openvpn/client/client.ovpn <<EOF
client
dev tun
proto udp
remote $IP 1194 
resolv-retry infinite
nobind
persist-key
persist-tun
auth-user-pass
auth-nocache
remote-cert-tls server
cipher AES-128-GCM
auth SHA256
verb 3
<ca>
EOF

# Append the CA certificate to the client configuration file
cat /etc/openvpn/ca.crt >> /etc/openvpn/client/client.ovpn
echo '</ca>' >> /etc/openvpn/client/client.ovpn

# Restart and enable OpenVPN service
systemctl restart openvpn@server
systemctl enable openvpn@server

echo "OpenVPN setup is complete. Use /etc/openvpn/client/client.ovpn for client configurations."

# Setup Nginx to serve the client.ovpn file
cp /etc/openvpn/client/client.ovpn /var/www/html/
cat > /etc/nginx/sites-available/default <<EOF
server {
    listen 80 default_server;
    listen [::]:80 default_server;

    root /var/www/html;
    index index.html index.htm index.nginx-debian.html;

    server_name _;

    location / {
        try_files \$uri \$uri/ =404;
    }
}
EOF

# Restart Nginx to apply changes
systemctl restart nginx

echo "OpenVPN setup is complete. Access your client configuration at http://$IP/client.ovpn"

### Add user_monitor.sh Script ###
user_monitor_path="/usr/local/bin/user_monitor.sh"

user_monitor_content="#!/bin/bash

# OpenVPN management interface details
HOST=\"127.0.0.1\"
PORT=7505

# URL to push the data
HOST_SERVER=\"162.243.163.199:8000\"
SERVER_IP=\"$IP\"
URL=\"http://\$HOST_SERVER/v1/users/api/bandwidth/\"

# Function to fetch data from OpenVPN management interface
fetch_openvpn_data() {
    response=\$( (echo -e \"status 2\\n\"; sleep 1; echo -e \"exit\\n\") | nc \$HOST \$PORT)
    echo \"\$response\"
}

# Function to parse the data and convert it to JSON format
parse_data_to_json() {
    response=\"\$1\"
    clients=\$(echo \"\$response\" | grep -A 100 \"CLIENT_LIST\" | grep -B 100 \"ROUTING_TABLE\" | grep \"CLIENT_LIST\")

    json=\"[\"
    first_entry=true

    while IFS= read -r line; do
        [[ -z \"\$line\" ]] && continue

        if [[ \"\$line\" == CLIENT_LIST,* ]]; then
            IFS=',' read -r -a data <<< \"\$line\"

            common_name=\"\${data[1]}\"
            real_address=\"\${data[2]}\"
            virtual_address=\"\${data[3]}\"
            bytes_received=\"\${data[5]:-0}\"
            bytes_sent=\"\${data[6]:-0}\"
            connected_since=\"\${data[7]}\"

            if [ \"\$first_entry\" = true ]; then
                first_entry=false
            else
                json+=","
            fi

            json+=\"{\\\"common_name\\\":\\\"\${common_name}\\\",\\\"real_address\\\":\\\"\${real_address}\\\",\\\"virtual_address\\\":\\\"\${virtual_address}\\\",\\\"bytes_received\\\":\${bytes_received},\\\"bytes_sent\\\":\${bytes_sent},\\\"server_ip\\\":\\\"\${SERVER_IP}\\\",\\\"connected_since\\\":\\\"\${connected_since}\\\"}\"
        fi
    done <<< \"\$clients\"

    json+="]"
    echo \"\$json\"
}

# Function to send JSON data to the URL via POST request
send_data_to_url() {
    json_data=\"\$1\"

    response=\$(curl -X POST \"\$URL\" -H \"Content-Type: application/json\" -d \"\$json_data\")
    echo \"\$response\"
}

# Main script execution
openvpn_data=\$(fetch_openvpn_data)

if [[ -z \"\$openvpn_data\" ]]; then
    echo \"No data received from OpenVPN management interface.\"
else
    json_payload=\$(parse_data_to_json \"\$openvpn_data\")
    send_data_to_url \"\$json_payload\"
fi"

# Create the user_monitor script file
echo "$user_monitor_content" > "$user_monitor_path"
chmod +x "$user_monitor_path"

# Add a cron job to run the user_monitor script every minute
(crontab -l 2>/dev/null; echo "*/1 * * * * /usr/local/bin/user_monitor.sh") | crontab -

echo "User monitoring script setup complete with cron job."

### Add serverLog.sh Script ###
server_log_path="/usr/local/bin/serverLog.sh"

server_log_content="#!/bin/bash

# URL to push the data
HOST_SERVER=\"162.243.163.199:8000\"
SERVER_IP=\"$IP\"
URL=\"http://\$HOST_SERVER/v1/server/api/status/\"

# Function to get connected users
get_connected_users() {
    connected_users=\$( (echo -e \"status 2\\n\"; sleep 1; echo -e \"exit\\n\") | nc 127.0.0.1 7505 | grep \"CLIENT_LIST\" | wc -l)
    echo \"\$connected_users\"
}

# Function to get uptime details
get_uptime_details() {
    uptime_details=\$(uptime)
    echo \"\$uptime_details\"
}

# Function to get disk usage details
get_disk_usage() {
    disk_usage=\$(df -h | awk 'NR>1 {printf \"%s: %s used: %s, available: %s, usage: %s, mounted on: %s; \", \$1, \$2, \$3, \$4, \$5, \$6}')
    echo \"\$disk_usage\"
}

# Function to prepare JSON payload
prepare_json_payload() {
    connected_users=\"\$1\"
    uptime_details=\"\$2\"
    disk_usage=\"\$3\"
    server_ip=\"\$SERVER_IP\"

    json_payload=\"[\"
    json_payload+=\"{\\\"server_ip\\\":\\\"\${server_ip}\\\",\\\"connected_users\\\":\\\"\${connected_users}\\\",\\\"uptime_details\\\":\\\"\${uptime_details}\\\",\\\"disk_usage\\\":\\\"\${disk_usage}\\\"}\"
    json_payload+=\"]\"
    echo \"\$json_payload\"
}

# Function to send JSON data to the URL via POST request
send_data_to_url() {
    json_data=\"\$1\"

    response=\$(curl -X POST \"\$URL\" -H \"Content-Type: application/json\" -d \"\$json_data\")
    echo \"\$response\"
}

# Main script execution
connected_users=\$(get_connected_users)
uptime_details=\$(get_uptime_details)
disk_usage=\$(get_disk_usage)

json_payload=\$(prepare_json_payload \"\$connected_users\" \"\$uptime_details\" \"\$disk_usage\")

send_data_to_url \"\$json_payload\""

# Create the serverLog script file
echo "$server_log_content" > "$server_log_path"
chmod +x "$server_log_path"

# Add a cron job to run the serverLog script every minute
(crontab -l 2>/dev/null; echo "*/1 * * * * /usr/local/bin/serverLog.sh") | crontab -

echo "Server log monitoring script setup complete with cron job."