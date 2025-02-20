# 🔥 LAMPfire

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Ubuntu Version](https://img.shields.io/badge/Ubuntu-18.04%2B-brightgreen)](https://ubuntu.com/)
[![Bash](https://img.shields.io/badge/Bash-Script-brightgreen)](https://www.gnu.org/software/bash/)

> One-click LAMP stack installer with automated optimization and security features

LAMPfire is a powerful bash script that automates the installation and configuration of a complete LAMP (Linux, Apache, MySQL, PHP) stack along with phpMyAdmin. It includes smart memory optimization, security hardening, and interactive configuration, making it perfect for both development and production environments.

## ✨ Features

* **One-Command Installation**: Complete LAMP stack setup with a single command
* **Smart Memory Management**: 
  * Automatic memory detection and optimization
  * Dynamic MySQL configuration based on available system resources
  * Automatic swap creation for low-memory systems
* **Security Features**:
  * Automated MySQL security configuration
  * phpMyAdmin access protection with .htaccess
  * Firewall configuration for Apache
* **Optimized Configurations**:
  * Custom-tuned MySQL settings for optimal performance
  * Apache virtual host configuration
  * PHP module optimization
* **Interactive Setup**:
  * Guided user creation for phpMyAdmin
  * Secure password management
  * Installation status feedback

## 🚀 Quick Start

1. Clone the repository:
   ```bash
   git clone https://github.com/agarhouse/LampFire.git
   cd LampFire
   ```

2. Make the script executable:
   ```bash
   chmod +x install_lamp.sh
   ```

3. Run the installer:
   ```bash
   sudo ./install_lamp.sh
   ```

## 📋 Requirements

* Ubuntu 18.04 or higher
* Minimum 512MB RAM (1GB+ recommended)
* Root or sudo privileges
* Clean Ubuntu installation

## 🛠️ What Gets Installed

* Apache2 web server
* MySQL 8.0
* PHP (latest version) with essential modules
* phpMyAdmin with security features
* Required PHP extensions
* UFW (Firewall) configurations

## 🔒 Security Features

* Protected phpMyAdmin installation
* Secure MySQL configuration
* Apache security best practices
* Web-based authentication
* Database user isolation

## ⚙️ Customization

The script includes several variables that can be customized:
* MySQL configuration parameters
* Apache virtual host settings
* PHP module selection
* Security configurations

## 📝 Post-Installation

After installation, you'll need to:

1. Save your MySQL root password in a secure location
2. Delete or secure the installation script
3. Configure SSL/TLS for secure access
4. Review and customize PHP settings if needed

## 🌐 Accessing Services

* **Apache**: `http://your_server_ip`
* **phpMyAdmin**: `http://your_server_ip/phpmyadmin`
* **Default Web Root**: `/var/www/html`

## 🔍 Troubleshooting

Common issues and solutions:

### MySQL Won't Start
* Check system memory
* Review error logs: `/var/log/mysql/error.log`

### phpMyAdmin Access Issues
* Verify Apache configuration
* Check user permissions
* Review Apache error logs

### Permission Problems
* Verify user ownership in `/var/www/html`
* Check Apache user permissions

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch:
   ```bash
   git checkout -b feature/AmazingFeature
   ```
3. Commit your changes:
   ```bash
   git commit -m 'Add some AmazingFeature'
   ```
4. Push to the branch:
   ```bash
   git push origin feature/AmazingFeature
   ```
5. Open a Pull Request

## ⚠️ Disclaimer

This script is provided as-is, without warranties. Always review scripts before running them with root privileges and ensure you have proper backups.

---
Created with ❤️ by [agarhouse](https://github.com/agarhouse)
