#!/usr/bin/env python3
"""
🔥 LAMPfire (Python)
License: MIT
Tested on: Ubuntu 20.04/22.04/24.04 (server/Desktop)

One‑click LAMP stack installer with automated optimization and security features.
This Python port mirrors the original Bash script’s behavior while providing
structured functions, clearer logging, and safer error handling.

Features
- One‑command installation & configuration (Apache, MySQL, PHP, phpMyAdmin)
- Smart memory/swap detection and MySQL tuning
- Security hardening (UFW, phpMyAdmin .htaccess protection)
- Interactive prompts for admin accounts & passwords

Run with root privileges:
    sudo python3 lampfire.py

Extras
- --self-test    Run quoting/command tests without changing the system
"""

import argparse
import base64
import getpass
import os
import re
import shlex
import subprocess
import sys
from pathlib import Path

# =============== UI Helpers ===============
RED = "\033[0;31m"
GREEN = "\033[0;32m"
YELLOW = "\033[1;33m"
NC = "\033[0m"


def status(msg: str):
    print(f"{YELLOW}[*] {msg}{NC}")


def success(msg: str):
    print(f"{GREEN}[+] {msg}{NC}")


def error(msg: str):
    print(f"{RED}[-] {msg}{NC}")


class CmdError(RuntimeError):
    pass


def run(cmd: str | list[str], check: bool = True, capture: bool = False, env: dict | None = None) -> subprocess.CompletedProcess:
    """Run a shell command with consistent logging and error handling.
    Accepts either a command string or a list.
    """
    printable = cmd if isinstance(cmd, str) else " ".join(cmd)
    status(f"$ {printable}")
    res = subprocess.run(
        cmd if isinstance(cmd, list) else shlex.split(cmd),
        stdout=subprocess.PIPE if capture else None,
        stderr=subprocess.PIPE if capture else None,
        env=env,
        check=False,
        text=True,
    )
    if check and res.returncode != 0:
        stderr = (res.stderr or "").strip()
        stdout = (res.stdout or "").strip()
        msg = f"Command failed ({res.returncode}): {printable}\nSTDOUT: {stdout}\nSTDERR: {stderr}"
        raise CmdError(msg)
    return res


# =============== Preconditions ===============

def require_root():
    if os.geteuid() != 0:
        error("This script must be run as root. Use: sudo python3 lampfire.py")
        sys.exit(1)


# =============== System Introspection ===============

def total_mem_mb() -> int:
    try:
        res = run("free -m", capture=True)
        for line in res.stdout.splitlines():
            if line.startswith("Mem:"):
                parts = re.split(r"\s+", line.strip())
                return int(parts[1])
    except Exception:
        pass
    # fallback: read MemTotal from /proc/meminfo
    with open("/proc/meminfo") as f:
        for line in f:
            if line.startswith("MemTotal:"):
                kb = int(re.findall(r"(\d+)", line)[0])
                return max(1, kb // 1024)
    return 0


# =============== Swap Management ===============

def ensure_swap_if_low_memory(threshold_mb: int = 1024, swap_mb: int = 1024):
    mem = total_mem_mb()
    status(f"Detected RAM: {mem} MB")
    if mem >= threshold_mb:
        success("Sufficient memory detected. No swap file needed.")
        return

    error(f"Less than {threshold_mb//1024 if threshold_mb>=1024 else threshold_mb}GB RAM detected ({mem} MB)")
    status(f"Adding {swap_mb}MB swap to prevent memory issues…")
    swapfile = Path("/swapfile")
    if not swapfile.exists():
        run(f"dd if=/dev/zero of=/swapfile bs=1M count={swap_mb}")
        run("chmod 600 /swapfile")
        run("mkswap /swapfile")
        run("swapon /swapfile")
        with open("/etc/fstab", "a") as f:
            f.write("/swapfile none swap sw 0 0\n")
        success("Swap created and enabled")
    else:
        success("Swapfile already exists; skipping creation")


# =============== Package Installation ===============

def apt_update():
    run("apt update")
    success("Package index updated")


def apt_install(pkgs: list[str]):
    run("apt install -y " + " ".join(pkgs))
    success(f"Installed: {', '.join(pkgs)}")


# =============== MySQL Tuning ===============

def write_mysql_config():
    mem = total_mem_mb()
    pool_mb = max(128, int(mem * 0.5))  # 50% of RAM, min 128MB
    Path("/etc/mysql/conf.d").mkdir(parents=True, exist_ok=True)
    config = f"""
[mysqld]
innodb_buffer_pool_size = {pool_mb}M
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
""".lstrip()
    Path("/etc/mysql/conf.d/mysql-custom.cnf").write_text(config)
    success("Wrote /etc/mysql/conf.d/mysql-custom.cnf")


def systemctl(action: str, svc: str):
    run(f"systemctl {action} {svc}")


# =============== phpMyAdmin Protection ===============

def secure_phpmyadmin_with_htaccess(web_user: str):
    # Ensure apache utilities for htpasswd are present
    apt_install(["apache2-utils"])  # provides htpasswd

    Path("/etc/apache2/conf-available").mkdir(parents=True, exist_ok=True)
    conf = """
<Directory /usr/share/phpmyadmin>
    Options SymLinksIfOwnerMatch
    DirectoryIndex index.php
    AllowOverride All
    Require all granted
</Directory>
""".lstrip()
    Path("/etc/apache2/conf-available/phpmyadmin.conf").write_text(conf)

    htaccess = """
AuthType Basic
AuthName "Restricted Files"
AuthUserFile /etc/phpmyadmin/.htpasswd
Require valid-user
""".lstrip()
    Path("/usr/share/phpmyadmin/.htaccess").write_text(htaccess)

    # Create htpasswd user
    status("Create a web user for /phpmyadmin Basic Auth")
    admin_user = input("Web username for phpMyAdmin: ").strip() or web_user
    run(f"htpasswd -c /etc/phpmyadmin/.htpasswd {shlex.quote(admin_user)}")
    return admin_user


def generate_blowfish_secret() -> str:
    return base64.b64encode(os.urandom(32)).decode()


def write_phpmyadmin_config(db_user: str, db_pass: str):
    cfg = f"""<?php
$cfg['blowfish_secret'] = '{generate_blowfish_secret()}';
$cfg['Servers'][1]['auth_type'] = 'cookie';
$cfg['Servers'][1]['host'] = 'localhost';
$cfg['Servers'][1]['port'] = '3306';
$cfg['Servers'][1]['user'] = '{db_user}';
$cfg['Servers'][1]['password'] = '{db_pass}';
$cfg['Servers'][1]['AllowNoPassword'] = false;
$cfg['Servers'][1]['connect_type'] = 'tcp';
$cfg['Servers'][1]['compress'] = false;
$cfg['UploadDir'] = '';
$cfg['SaveDir'] = '';
$cfg['PmaNoRelation_DisableWarning'] = true;
$cfg['ExecTimeLimit'] = 0;
?>
"""
    Path("/etc/phpmyadmin/config.inc.php").write_text(cfg)
    os.chmod("/etc/phpmyadmin/config.inc.php", 0o644)
    success("phpMyAdmin config written")


# =============== MySQL Root Password Handling ===============

def try_mysql_command(cmd_sql: str, user: str = "root", password: str | None = None, sudo_mode: bool = False) -> bool:
    try:
        if sudo_mode:
            run(["sudo", "mysql", "-u", user, "-e", cmd_sql])
        else:
            if password:
                run(["mysql", "-u", user, f"-p{password}", "-e", cmd_sql])
            else:
                run(["mysql", "-u", user, "-e", cmd_sql])
        return True
    except CmdError:
        return False


def set_root_password_workflow(temp_pass: str) -> None:
    status("Checking MySQL service status…")
    run("systemctl status mysql --no-pager -l", check=False)

    status("Method 1: Direct MySQL access test…")
    if try_mysql_command("SELECT 1;"):
        success("Direct MySQL access works")
        run(["mysql", "-u", "root", "-e", f"ALTER USER 'root'@'localhost' IDENTIFIED WITH mysql_native_password BY '{temp_pass}'; FLUSH PRIVILEGES;"])
        success("Root password set (direct)")
        return

    status("Method 2: Using sudo mysql…")
    if try_mysql_command("SELECT 1;", sudo_mode=True):
        success("sudo mysql works")
        run(["sudo", "mysql", "-u", "root", "-e", f"ALTER USER 'root'@'localhost' IDENTIFIED WITH mysql_native_password BY '{temp_pass}'; FLUSH PRIVILEGES;"])
        success("Root password set (sudo)")
        return

    status("Method 3: Safe mode (grant tables skipped)…")
    run("systemctl stop mysql")
    # start mysqld_safe in background
    proc = subprocess.Popen(["bash", "-lc", "mysqld_safe --skip-grant-tables --skip-networking & echo $!"], stdout=subprocess.PIPE, text=True)
    pid = int((proc.stdout.read() or "0").strip() or 0)
    if pid <= 0:
        raise CmdError("Failed to start mysqld_safe")
    status(f"mysqld_safe started (pid {pid}) — waiting 5s…")
    subprocess.run(["sleep", "5"])  # simple wait

    # set password without auth
    run(["bash", "-lc", f"mysql -u root <<'EOF'\nUSE mysql;\nALTER USER 'root'@'localhost' IDENTIFIED WITH mysql_native_password BY '{temp_pass}';\nFLUSH PRIVILEGES;\nEOF\n"], check=True)

    # kill safe mode and restart
    run(f"kill {pid}", check=False)
    subprocess.run(["sleep", "3"])  # allow shutdown
    run("systemctl start mysql")
    success("Root password set (safe mode)")


# =============== Debconf preseeding helper ===============

def debconf_preseed_commands(temp_mysql_root: str, app_pass: str = "tempphpmyadminpass123") -> list[str]:
    """Return properly quoted bash -lc command strings for debconf preseeding.
    We use single quotes around the outer Python string and double quotes inside
    to avoid conflicting delimiters.
    """
    cmds = [
        'bash -lc "echo phpmyadmin phpmyadmin/dbconfig-install boolean true | debconf-set-selections"',
        'bash -lc "echo phpmyadmin phpmyadmin/app-password-confirm password ' + app_pass + ' | debconf-set-selections"',
        'bash -lc "echo phpmyadmin phpmyadmin/mysql/admin-pass password ' + temp_mysql_root + ' | debconf-set-selections"',
        'bash -lc "echo phpmyadmin phpmyadmin/mysql/app-pass password ' + app_pass + ' | debconf-set-selections"',
        'bash -lc "echo phpmyadmin phpmyadmin/reconfigure-webserver multiselect apache2 | debconf-set-selections"',
    ]
    return cmds


# =============== Main Routine ===============

def main(argv: list[str] | None = None):
    parser = argparse.ArgumentParser(description="LAMPfire (Python) — one‑click LAMP installer")
    parser.add_argument("--self-test", action="store_true", help="run quoting tests and exit")
    args = parser.parse_args(argv)

    if args.self_test:
        status("Running self tests for quoting and shlex splitting…")
        temp = "temppass123"
        tests = debconf_preseed_commands(temp)
        for i, cmd in enumerate(tests, 1):
            # Ensure shlex keeps the inner double‑quoted payload intact as arg 3
            parts = shlex.split(cmd)
            assert parts[0] == "bash" and parts[1] == "-lc", f"bad split for test {i}: {parts}"
            assert "debconf-set-selections" in parts[2], f"payload missing in test {i}: {parts}"
            # Try actually executing a harmless analogue of the command
            # Replace the echo payload with a safe echo pipeline to validate pipes work
            safe = 'bash -lc "echo selftest | cat"'
            run(safe)
        success("Self‑tests passed: quoting and pipes are valid.")
        return

    require_root()

    # Preinstall debconf frontends (dialog) like original script
    status("Installing debconf frontend tools…")
    apt_install(["apt-utils", "dialog"])

    # Memory & swap
    ensure_swap_if_low_memory()

    # Update & base packages
    apt_update()
    status("Installing Apache…")
    apt_install(["apache2"])

    # Firewall (UFW)
    if subprocess.run(["bash", "-lc", "command -v ufw"], stdout=subprocess.DEVNULL).returncode != 0:
        status("Installing ufw firewall…")
        apt_install(["ufw"])
    status("Configuring firewall rules…")
    run('ufw allow in "Apache"', check=False)
    run('ufw allow in "Apache Full"', check=False)
    success("Firewall rules configured")

    # MySQL tuning file before install
    status("Generating optimized MySQL config…")
    write_mysql_config()

    # MySQL install (with retry)
    status("Installing MySQL server…")
    env = os.environ.copy()
    env["DEBIAN_FRONTEND"] = "noninteractive"
    try:
        run("apt install -y mysql-server", env=env)
    except CmdError:
        error("MySQL installation failed — cleaning up and retrying…")
        run("apt remove --purge -y mysql-server* mysql-common mysql-client*", check=False)
        run("apt autoremove -y", check=False)
        run("apt autoclean", check=False)
        run("rm -rf /etc/mysql /var/lib/mysql* /var/log/mysql", check=False)
        apt_update()
        run("apt install -y mysql-server", env=env)
    success("MySQL installed")

    status("Configuring MySQL service…")
    systemctl("enable", "mysql")
    systemctl("restart", "mysql")
    subprocess.run(["sleep", "3"])  # give it a moment
    systemctl("start", "mysql")
    success("MySQL service running")

    # Set a temporary root password
    TEMP_PASS = "temppass123"
    status("Setting temporary MySQL root password…")
    set_root_password_workflow(TEMP_PASS)

    # Verify password works
    status("Verifying MySQL root password…")
    if not try_mysql_command("SELECT 'Password verification successful' as Status;", password=TEMP_PASS):
        error("Automatic password verification failed. Running mysql_secure_installation interactively…")
        run("mysql_secure_installation", check=False)
        # Ask user what password they set, then reset to TEMP_PASS for continuity
        user_root_pass = getpass.getpass("Enter the MySQL root password you just set: ")
        run(["mysql", "-u", "root", f"-p{user_root_pass}", "-e", f"ALTER USER 'root'@'localhost' IDENTIFIED WITH mysql_native_password BY '{TEMP_PASS}'; FLUSH PRIVILEGES;"])
    success("MySQL root password OK")

    # PHP + modules
    status("Installing PHP & modules…")
    apt_install([
        "php",
        "libapache2-mod-php",
        "php-mysql",
        "php-mbstring",
        "php-zip",
        "php-gd",
        "php-json",
        "php-curl",
    ])
    run("phpenmod mbstring", check=False)

    # phpMyAdmin (pre-seed debconf like bash) — FIXED QUOTING
    status("Installing phpMyAdmin… (preseeding debconf)")
    for cmd in debconf_preseed_commands(TEMP_PASS):
        run(cmd)

    apt_install(["phpmyadmin"])  # modules already installed above

    # Symlink to web root for convenience
    Path("/var/www/html/phpmyadmin").unlink(missing_ok=True)
    Path("/var/www/html/phpmyadmin").symlink_to("/usr/share/phpmyadmin")

    # Apache modules & config
    status("Enabling Apache modules…")
    run("a2enmod rewrite headers ssl")
    run("a2enconf phpmyadmin", check=False)

    # Protect phpMyAdmin with .htaccess
    web_admin_user = secure_phpmyadmin_with_htaccess(web_user="admin")

    # Restart Apache
    status("Restarting Apache…")
    run("apache2ctl configtest")
    systemctl("restart", "apache2")

    # Create final MySQL root password and phpMyAdmin DB user
    status("Finalizing database user configuration…")
    new_root = getpass.getpass("Enter NEW MySQL root password (will replace temporary): ")
    run(["mysql", "-u", "root", f"-p{TEMP_PASS}", "-e", f"ALTER USER 'root'@'localhost' IDENTIFIED WITH mysql_native_password BY '{new_root}'; FLUSH PRIVILEGES;"])

    db_user = input("Enter DB username for phpMyAdmin (e.g., admin): ").strip() or "admin"
    db_pass = getpass.getpass(f"Enter password for {db_user}: ")

    run(["mysql", "-u", "root", f"-p{new_root}", "-e",
         f"CREATE USER IF NOT EXISTS '{db_user}'@'localhost' IDENTIFIED BY '{db_pass}'; GRANT ALL PRIVILEGES ON *.* TO '{db_user}'@'localhost' WITH GRANT OPTION; FLUSH PRIVILEGES;"])

    write_phpmyadmin_config(db_user, db_pass)

    # Summary
    success("LAMP + phpMyAdmin stack installed successfully!")
    print()
    print("phpMyAdmin URL: http://<your_server_ip>/phpmyadmin")
    print(f"Web Auth Username: {web_admin_user}")
    print(f"MySQL Username: {db_user}")
    print("MySQL Root Password: (you just set it)")
    print("\n🔥 Cleanup tip: Delete this script when done!")


if __name__ == "__main__":
    try:
        main()
    except CmdError as ce:
        error(str(ce))
        sys.exit(1)
    except KeyboardInterrupt:
        error("Interrupted by user")
        sys.exit(130)
