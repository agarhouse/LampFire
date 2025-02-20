#!/bin/bash

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to print status messages
print_status() {
    echo -e "${YELLOW}[*] $1${NC}"
}

# Function to print success messages
print_success() {
    echo -e "${GREEN}[+] $1${NC}"
}

# Function to print error messages
print_error() {
    echo -e "${RED}[-] $1${NC}"
}

# Function to check if command was successful
check_status() {
    if [ $? -eq 0 ]; then
        print_success "$1"
    else
        print_error "$2"
        exit 1
    fi
}

# Function to check available memory
check_memory() {
    local available_mem=$(free -m | awk '/Mem:/ {print $2}')
    if [ "$available_mem" -lt 1024 ]; then
        print_error "Your system has less than 1GB of RAM (${available_mem}MB)"
        print_status "Creating swap space to prevent memory issues..."
        
        # Create 1GB swap file
        dd if=/dev/zero of=/swapfile bs=1024 count=1048576
        chmod 600 /swapfile
        mkswap /swapfile
        swapon /swapfile
        echo '/swapfile none swap sw 0 0' >> /etc/fstab
        
        print_success "Swap space created successfully"
    fi
}

# Function to create MySQL configuration
create_mysql_config() {
    local available_mem=$(free -m | awk '/Mem:/ {print $2}')
    local innodb_buffer_pool_size=$(awk "BEGIN {print int($available_mem * 0.5)}")M
    
    cat > /etc/mysql/conf.d/mysql-custom.cnf << EOL
[mysqld]
# Memory optimizations
innodb_buffer_pool_size = ${innodb_buffer_pool_size}
innodb_log_file_size = 48M
innodb_log_buffer_size = 8M
innodb_flush_method = O_DIRECT
innodb_flush_log_at_trx_commit = 2

# Connection and thread settings
max_connections = 50
thread_cache_size = 8
thread_stack = 256K

# Query cache (disabled in MySQL 8+)
performance_schema = OFF

# Other optimizations
tmp_table_size = 32M
max_heap_table_size = 32M
EOL
}

# Check if script is run as root
if [[ $EUID -ne 0 ]]; then
    print_error "This script must be run as root"
    echo "Please run with: sudo $0"
    exit 1
fi

# Check and optimize memory
print_status "Checking system memory..."
check_memory

# Update system packages
print_status "Updating system packages..."
apt update
check_status "System packages updated successfully" "Failed to update system packages"

# Install Apache
print_status "Installing Apache..."
apt install -y apache2
check_status "Apache installed successfully" "Failed to install Apache"

# Configure firewall
print_status "Configuring firewall..."
ufw allow in "Apache"
ufw allow in "Apache Full"
check_status "Firewall configured successfully" "Failed to configure firewall"

# Create MySQL configuration before installation
print_status "Creating optimized MySQL configuration..."
create_mysql_config

# Install MySQL with proper error handling
print_status "Installing MySQL..."
export DEBIAN_FRONTEND=noninteractive
apt install -y mysql-server || {
    print_error "MySQL installation failed. Trying alternative approach..."
    # Clean up failed installation
    apt remove --purge -y mysql-server mysql-server-8.0 mysql-common
    apt autoremove -y
    apt autoclean
    rm -rf /var/lib/mysql
    rm -rf /etc/mysql
    
    # Try installation again with minimal configuration
    apt install -y mysql-server-8.0
}
check_status "MySQL installed successfully" "Failed to install MySQL after retry"

# Start MySQL with proper error handling
print_status "Starting MySQL service..."
systemctl start mysql || {
    print_error "Failed to start MySQL. Checking logs..."
    journalctl -xe --unit=mysql.service
    exit 1
}

# Configure MySQL Security
print_status "Configuring MySQL security..."
mysql -e "ALTER USER 'root'@'localhost' IDENTIFIED WITH mysql_native_password BY 'temppass123';" || {
    print_error "Failed to set MySQL root password. Trying alternative method..."
    mysqld --init-file=/tmp/mysql-init &
    sleep 10
    mysql -e "ALTER USER 'root'@'localhost' IDENTIFIED WITH mysql_native_password BY 'temppass123';"
}
mysql -e "FLUSH PRIVILEGES;"

# Install PHP and required modules
print_status "Installing PHP and required modules..."
apt install -y php libapache2-mod-php php-mysql php-mbstring php-zip php-gd php-json php-curl
check_status "PHP and modules installed successfully" "Failed to install PHP and modules"

# Enable PHP modules
print_status "Enabling PHP modules..."
phpenmod mbstring
check_status "PHP modules enabled successfully" "Failed to enable PHP modules"

# Install phpMyAdmin with pre-configuration
print_status "Installing phpMyAdmin..."
export DEBIAN_FRONTEND=noninteractive
echo "phpmyadmin phpmyadmin/dbconfig-install boolean true" | debconf-set-selections
echo "phpmyadmin phpmyadmin/app-password-confirm password tempphpmyadminpass123" | debconf-set-selections
echo "phpmyadmin phpmyadmin/mysql/admin-pass password temppass123" | debconf-set-selections
echo "phpmyadmin phpmyadmin/mysql/app-pass password tempphpmyadminpass123" | debconf-set-selections
echo "phpmyadmin phpmyadmin/reconfigure-webserver multiselect apache2" | debconf-set-selections

apt install -y phpmyadmin php-mbstring php-zip php-gd php-json php-curl
check_status "phpMyAdmin installed successfully" "Failed to install phpMyAdmin"

# Create symbolic link for phpMyAdmin
print_status "Configuring phpMyAdmin web access..."
ln -sf /usr/share/phpmyadmin /var/www/html/phpmyadmin

# Enable needed Apache modules
print_status "Enabling required Apache modules..."
a2enmod rewrite
a2enmod headers
a2enmod ssl

# Enable phpMyAdmin Apache configuration
print_status "Enabling phpMyAdmin Apache configuration..."
a2enconf phpmyadmin


# Secure phpMyAdmin
print_status "Securing phpMyAdmin..."
cat > /etc/apache2/conf-available/phpmyadmin.conf << 'EOL'
<Directory /usr/share/phpmyadmin>
    Options SymLinksIfOwnerMatch
    DirectoryIndex index.php
    AllowOverride All
    Require all granted
</Directory>
EOL

# Create .htaccess file
cat > /usr/share/phpmyadmin/.htaccess << 'EOL'
AuthType Basic
AuthName "Restricted Files"
AuthUserFile /etc/phpmyadmin/.htpasswd
Require valid-user
EOL

# Prompt for phpMyAdmin admin username
read -p "Enter username for phpMyAdmin web authentication: " ADMIN_USER
htpasswd -c /etc/phpmyadmin/.htpasswd "$ADMIN_USER"

# Restart Apache
print_status "Restarting Apache..."
apache2ctl configtest
systemctl restart apache2
check_status "Apache restarted successfully" "Failed to restart Apache"

# Verify phpMyAdmin installation
print_status "Verifying phpMyAdmin installation..."
if [ -f "/var/www/html/phpmyadmin/index.php" ]; then
    print_success "phpMyAdmin is properly installed and accessible"
else
    print_error "phpMyAdmin files not found in expected location. Manual investigation required."
    echo "Please check:"
    echo "1. /usr/share/phpmyadmin exists and contains files"
    echo "2. Symbolic link at /var/www/html/phpmyadmin points to correct location"
    echo "3. Apache configuration in /etc/apache2/conf-enabled/phpmyadmin.conf"
fi

# Configure MySQL users and permissions
print_status "Setting up MySQL users..."

# Change MySQL root password
read -s -p "Enter new MySQL root password: " MYSQL_ROOT_PASS
echo
mysql -u root -ptemppass123 -e "ALTER USER 'root'@'localhost' IDENTIFIED WITH mysql_native_password BY '$MYSQL_ROOT_PASS';"
check_status "MySQL root password changed successfully" "Failed to change MySQL root password"

# Create phpMyAdmin user
read -p "Enter username for phpMyAdmin database access: " MYSQL_USER
read -s -p "Enter password for $MYSQL_USER: " MYSQL_PASS
echo

# Create user and grant privileges
mysql -u root -p"$MYSQL_ROOT_PASS" << EOF
CREATE USER IF NOT EXISTS '${MYSQL_USER}'@'localhost' IDENTIFIED WITH mysql_native_password BY '${MYSQL_PASS}';
GRANT ALL PRIVILEGES ON *.* TO '${MYSQL_USER}'@'localhost' WITH GRANT OPTION;
FLUSH PRIVILEGES;
EOF
check_status "MySQL user created successfully" "Failed to create MySQL user"

# Update phpMyAdmin configuration
print_status "Updating phpMyAdmin configuration..."
cat > /etc/phpmyadmin/config.inc.php << EOF
<?php
\$cfg['blowfish_secret'] = '$(openssl rand -base64 32)';
\$cfg['Servers'][1]['auth_type'] = 'cookie';
\$cfg['Servers'][1]['host'] = 'localhost';
\$cfg['Servers'][1]['port'] = '3306';
\$cfg['Servers'][1]['user'] = '${MYSQL_USER}';
\$cfg['Servers'][1]['password'] = '${MYSQL_PASS}';
\$cfg['Servers'][1]['AllowNoPassword'] = false;
\$cfg['Servers'][1]['connect_type'] = 'tcp';
\$cfg['Servers'][1]['compress'] = false;
\$cfg['UploadDir'] = '';
\$cfg['SaveDir'] = '';
\$cfg['PmaNoRelation_DisableWarning'] = true;
\$cfg['ExecTimeLimit'] = 0;
?>
EOF
chmod 644 /etc/phpmyadmin/config.inc.php

print_success "LAMP stack and phpMyAdmin installation completed!"
echo
echo "Installation Summary:"
echo "-------------------"
echo "Apache: Installed and running"
echo "MySQL: Installed and secured with optimized configuration"
echo "PHP: Installed with required modules"
echo "phpMyAdmin: Installed and secured with basic authentication"
echo
echo "You can access phpMyAdmin at: http://your_server_ip/phpmyadmin"
echo "Use the following credentials:"
echo "Web authentication username: $ADMIN_USER"
echo "Web authentication password: (the password you just set)"
echo "MySQL username: root"
echo "MySQL password: (the password you just set)"
echo
echo "Please make sure to:"
echo "1. Delete installation script for security"
echo "2. Keep your passwords safe"
echo "3. Configure SSL/TLS for secure access"
echo "4. Monitor /var/log/mysql/error.log for any issues"
