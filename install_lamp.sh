#!/bin/bash

set -e  # Exit immediately on error

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Output helpers
print_status() { echo -e "${YELLOW}[*] $1${NC}"; }
print_success() { echo -e "${GREEN}[+] $1${NC}"; }
print_error() { echo -e "${RED}[-] $1${NC}"; }
check_status() {
    if [ $? -eq 0 ]; then
        print_success "$1"
    else
        print_error "$2"
        exit 1
    fi
}

# Root check
if [[ $EUID -ne 0 ]]; then
    print_error "This script must be run as root"
    echo "Use: sudo $0"
    exit 1
fi

# Ensure required frontend dependencies are installed
print_status "Installing debconf frontend tools..."
apt install -y apt-utils dialog
check_status "Frontend tools installed" "Failed to install dialog"

# Memory check
check_memory() {
    local mem=$(free -m | awk '/Mem:/ {print $2}')
    if [ "$mem" -lt 1024 ]; then
        print_error "Less than 1GB RAM detected (${mem}MB)"
        print_status "Adding 1GB swap to prevent memory issues..."
        dd if=/dev/zero of=/swapfile bs=1024 count=1048576
        chmod 600 /swapfile
        mkswap /swapfile
        swapon /swapfile
        echo '/swapfile none swap sw 0 0' >> /etc/fstab
        print_success "Swap created and enabled"
    fi
}

# Create MySQL config
create_mysql_config() {
    mkdir -p /etc/mysql/conf.d
    local mem=$(free -m | awk '/Mem:/ {print $2}')
    local pool_size=$(awk "BEGIN {print int($mem * 0.5)}")M
    cat > /etc/mysql/conf.d/mysql-custom.cnf << EOL
[mysqld]
innodb_buffer_pool_size = ${pool_size}
innodb_log_file_size = 48M
innodb_log_buffer_size = 8M
innodb_flush_method = O_DIRECT
innodb_flush_log_at_trx_commit = 2
max_connections = 50
thread_cache_size = 8
thread_stack = 256K
performance_schema = OFF
tmp_table_size = 32M
max_heap_table_size = 32M
EOL
}

# Start
print_status "Checking memory..."
check_memory

print_status "Updating packages..."
apt update
check_status "System updated" "Package update failed"

print_status "Installing Apache..."
apt install -y apache2
check_status "Apache installed" "Apache installation failed"

# Firewall setup
if ! command -v ufw &> /dev/null; then
    print_status "Installing ufw firewall..."
    apt install -y ufw
    check_status "ufw installed" "ufw install failed"
fi

print_status "Configuring firewall rules..."
ufw allow in "Apache"
ufw allow in "Apache Full"
check_status "Firewall configured" "Firewall rule setup failed"

print_status "Generating optimized MySQL config..."
create_mysql_config

# Install MySQL with improved error handling
print_status "Installing MySQL..."
DEBIAN_FRONTEND=noninteractive apt install -y mysql-server
if [ $? -ne 0 ]; then
    print_error "MySQL installation failed. Cleaning up and retrying..."
    apt remove --purge -y mysql-server* mysql-common mysql-client*
    apt autoremove -y
    apt autoclean
    rm -rf /etc/mysql /var/lib/mysql* /var/log/mysql
    apt update
    DEBIAN_FRONTEND=noninteractive apt install -y mysql-server
fi
check_status "MySQL installed" "MySQL installation failed after retry"

print_status "Configuring MySQL service..."
systemctl enable mysql
systemctl restart mysql
sleep 3  # Give MySQL time to fully start
check_status "MySQL service configured" "MySQL service configuration failed"

print_status "Starting MySQL..."
systemctl start mysql
check_status "MySQL started" "MySQL failed to start"

print_status "Setting temporary MySQL root password..."

# Debug: Show MySQL status first  
print_status "Checking MySQL status..."
systemctl status mysql --no-pager -l || true
sleep 2

TEMP_PASS="temppass123"

# Method 1: Try direct connection (most common for fresh installs)
print_status "Method 1: Testing direct MySQL access..."
if mysql -u root -e "SELECT 1;" 2>/dev/null; then
    print_success "Direct MySQL access works!"
    mysql -u root -e "ALTER USER 'root'@'localhost' IDENTIFIED WITH mysql_native_password BY '$TEMP_PASS'; FLUSH PRIVILEGES;"
    print_success "Password set via direct method"
else
    print_status "Direct access failed, trying sudo method..."
    
    # Method 2: Try sudo (Ubuntu/Debian default)
    if sudo mysql -u root -e "SELECT 1;" 2>/dev/null; then
        print_success "Sudo MySQL access works!"
        sudo mysql -u root -e "ALTER USER 'root'@'localhost' IDENTIFIED WITH mysql_native_password BY '$TEMP_PASS'; FLUSH PRIVILEGES;"
        print_success "Password set via sudo method"
    else
        print_status "Sudo method failed, using safe mode..."
        
        # Method 3: Safe mode (last resort)
        print_status "Stopping MySQL for safe mode setup..."
        systemctl stop mysql
        
        print_status "Starting MySQL in safe mode..."
        mysqld_safe --skip-grant-tables --skip-networking &
        SAFE_PID=$!
        sleep 5
        
        print_status "Setting password in safe mode..."
        mysql -u root << 'EOF'
USE mysql;
ALTER USER 'root'@'localhost' IDENTIFIED WITH mysql_native_password BY 'temppass123';
FLUSH PRIVILEGES;
EOF
        
        print_status "Stopping safe mode and restarting MySQL normally..."
        kill $SAFE_PID 2>/dev/null || true
        sleep 3
        systemctl start mysql
        sleep 3
        print_success "Password set via safe mode"
    fi
fi

# Verify the password works
print_status "Verifying password setup..."
if mysql -u root -p"$TEMP_PASS" -e "SELECT 'Password verification successful' as Status;" 2>/dev/null; then
    print_success "MySQL root password is working correctly"
else
    print_error "Password verification failed!"
    print_status "Attempting manual mysql_secure_installation..."
    mysql_secure_installation
    # Set our temp password after secure installation
    read -s -p "Enter the root password you just set: " USER_ROOT_PASS
    mysql -u root -p"$USER_ROOT_PASS" -e "ALTER USER 'root'@'localhost' IDENTIFIED WITH mysql_native_password BY '$TEMP_PASS'; FLUSH PRIVILEGES;"
    print_success "Using user-provided password"
fi

# PHP Install
print_status "Installing PHP + modules..."
apt install -y php libapache2-mod-php php-mysql php-mbstring php-zip php-gd php-json php-curl
check_status "PHP installed" "PHP install failed"

print_status "Enabling PHP modules..."
phpenmod mbstring
check_status "Modules enabled" "PHP module error"

# phpMyAdmin Install
print_status "Installing phpMyAdmin..."
echo "phpmyadmin phpmyadmin/dbconfig-install boolean true" | debconf-set-selections
echo "phpmyadmin phpmyadmin/app-password-confirm password tempphpmyadminpass123" | debconf-set-selections
echo "phpmyadmin phpmyadmin/mysql/admin-pass password temppass123" | debconf-set-selections
echo "phpmyadmin phpmyadmin/mysql/app-pass password tempphpmyadminpass123" | debconf-set-selections
echo "phpmyadmin phpmyadmin/reconfigure-webserver multiselect apache2" | debconf-set-selections

apt install -y phpmyadmin php-mbstring php-zip php-gd php-json php-curl
check_status "phpMyAdmin installed" "phpMyAdmin installation failed"

ln -sf /usr/share/phpmyadmin /var/www/html/phpmyadmin

# Apache tuning
print_status "Enabling Apache modules..."
a2enmod rewrite headers ssl
a2enconf phpmyadmin
check_status "Apache modules enabled" "Failed to enable Apache config"

print_status "Securing phpMyAdmin..."
cat > /etc/apache2/conf-available/phpmyadmin.conf << 'EOL'
<Directory /usr/share/phpmyadmin>
    Options SymLinksIfOwnerMatch
    DirectoryIndex index.php
    AllowOverride All
    Require all granted
</Directory>
EOL

# Create .htaccess
cat > /usr/share/phpmyadmin/.htaccess << 'EOL'
AuthType Basic
AuthName "Restricted Files"
AuthUserFile /etc/phpmyadmin/.htpasswd
Require valid-user
EOL

read -p "Enter web username for phpMyAdmin: " ADMIN_USER
htpasswd -c /etc/phpmyadmin/.htpasswd "$ADMIN_USER"

print_status "Restarting Apache..."
apache2ctl configtest
systemctl restart apache2
check_status "Apache restarted" "Apache failed to restart"

# Validate phpMyAdmin
if [ -f "/var/www/html/phpmyadmin/index.php" ]; then
    print_success "phpMyAdmin setup complete"
else
    print_error "phpMyAdmin not properly configured"
fi

# Final DB setup
print_status "Securing MySQL root user..."
read -s -p "Enter new MySQL root password: " MYSQL_ROOT_PASS
echo
mysql -u root -ptemppass123 -e "ALTER USER 'root'@'localhost' IDENTIFIED WITH mysql_native_password BY '$MYSQL_ROOT_PASS';"
check_status "Root password updated" "Failed to update root password"

read -p "Enter DB username for phpMyAdmin: " MYSQL_USER
read -s -p "Enter password for $MYSQL_USER: " MYSQL_PASS
echo

mysql -u root -p"$MYSQL_ROOT_PASS" << EOF
CREATE USER IF NOT EXISTS '${MYSQL_USER}'@'localhost' IDENTIFIED BY '${MYSQL_PASS}';
GRANT ALL PRIVILEGES ON *.* TO '${MYSQL_USER}'@'localhost' WITH GRANT OPTION;
FLUSH PRIVILEGES;
EOF
check_status "MySQL user created" "Failed to create MySQL user"

print_status "Configuring phpMyAdmin default login..."
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

# Summary
print_success "LAMP + phpMyAdmin stack installed successfully!"
echo
echo "phpMyAdmin URL: http://<your_server_ip>/phpmyadmin"
echo "Web Auth Username: $ADMIN_USER"
echo "MySQL Username: $MYSQL_USER"
echo "MySQL Root Password: (you just set it)"
echo
echo "🔥 Cleanup tip: Delete this script when done!"
