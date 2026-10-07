#!/usr/bin/python3
"""
This script performs various setup and maintenance tasks including dependency management,
auto-updating, SSH key generation, crontab installation, and data transmission.
It ensures the presence of required tools and libraries, updates itself from a remote source,
generates SSH keys if needed, schedules itself to run hourly via crontab, and sends
signed machine ID data to a specified URL.
"""

import os
import sys
import subprocess
import json
import urllib.request
import urllib.error
import random
import time
try:
    import paramiko
except ImportError:
    paramiko = None
import base64
import struct
import hashlib
import logging
import re
from logging.handlers import TimedRotatingFileHandler


# Bump on every change: autoupdate only installs a remote copy with a higher version.
CRABE_VERSION = 6
UPDATE_URL = os.environ.get(
    "CRABE_UPDATE_URL",
    "https://raw.githubusercontent.com/monperrus/crabe/main/crabe.py",
)
SSH_KEY_PATH = os.path.expanduser("~/.ssh/crabe/id_ed25519")
STAGGER_MAX_SECONDS = 45  # cron runs us under `timeout 60`
LOG_FILE = os.environ.get(
    "CRABE_LOG_FILE", os.path.expanduser("~/.local/state/crabe/crabe.log")
)
LOG_BACKUP_DAYS = 30
logger = logging.getLogger("crabe")


def setup_logging():
    """Configure the dedicated daily-rotated agent log."""
    if logger.handlers:
        return

    try:
        os.makedirs(os.path.dirname(LOG_FILE), mode=0o700, exist_ok=True)
        handler = TimedRotatingFileHandler(
            LOG_FILE,
            when="midnight",
            backupCount=LOG_BACKUP_DAYS,
            encoding="utf-8",
        )
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
        logger.propagate = False
    except OSError as error:
        print(f"Failed to configure log file {LOG_FILE}: {error}")


def log(message, level=logging.INFO):
    """Write an event to the dedicated log; only warnings and errors reach the console.

    Cron mails any output, so a successful run must print nothing.
    """
    logger.log(level, message)
    if level >= logging.WARNING:
        print(message)


def ensure_pip():
    """Checks for pip availability and installs missing dependencies."""
    try:
        subprocess.run(
            [sys.executable, "-m", "pip", "--version"],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
    except (subprocess.CalledProcessError, FileNotFoundError):
        log("Error: pip is not available. Please install pip to continue.", logging.ERROR)
        sys.exit(1)

    global paramiko
    if paramiko is None:
        log("Dependency 'paramiko' not found. Installing...")
        try:
            # Check if --break-system-packages is supported
            pip_help = subprocess.check_output([sys.executable, "-m", "pip", "install", "--help"], text=True)
            install_args = [sys.executable, "-m", "pip", "install", "-q", "paramiko"]
            if "--break-system-packages" in pip_help:
                install_args.append("--break-system-packages")
            
            subprocess.check_call(install_args)
            log("'paramiko' installed successfully. Restarting...")
            target_file = os.path.abspath(__file__)
            if not os.path.exists(target_file):
                 target_file = os.path.abspath("crabe.py")
            os.execv(sys.executable, [sys.executable, target_file] + sys.argv[1:])
        except subprocess.CalledProcessError as e:
            log(f"Failed to install 'paramiko': {e}", logging.ERROR)
            sys.exit(1)


def autoupdate():
    target_file = os.path.abspath(__file__)
    if not os.path.exists(target_file):
        # If running from stdin or non-existent file, target local crabe.py
        target_file = os.path.abspath("crabe.py")

    try:
        with urllib.request.urlopen(UPDATE_URL, timeout=15) as response:
            if response.getcode() == 200:
                new_content = response.read()
                remote_version = parse_version(new_content)
                if remote_version <= CRABE_VERSION:
                    log(
                        "update not allowed "
                        f"(remote version {remote_version} <= local version {CRABE_VERSION})."
                    )
                    return

                # Check if content is different before updating
                try:
                    with open(target_file, 'rb') as f:
                        current_content = f.read()
                except FileNotFoundError:
                    current_content = b""

                if new_content != current_content:
                    with open(target_file, 'wb') as f:
                        f.write(new_content)
                    
                    # Ensure the file is executable
                    st = os.stat(target_file)
                    os.chmod(target_file, st.st_mode | 0o111)

                    log(f"Update successful ({target_file}). Restarting...")
                    os.execv(sys.executable, [sys.executable, target_file] + sys.argv[1:])
                else:
                    log("No update needed.")
            else:
                log(f"Update failed: HTTP {response.getcode()}", logging.ERROR)
    except Exception as e:
        log(f"Update failed: {e}", logging.ERROR)


def parse_version(content):
    """Return the CRABE_VERSION declared in a crabe.py source, 0 if absent."""
    match = re.search(rb"^CRABE_VERSION = (\d+)$", content, re.MULTILINE)
    return int(match.group(1)) if match else 0


def encode_string(s):
    if isinstance(s, str):
        s = s.encode('utf-8')
    return struct.pack('>I', len(s)) + s


def create_ssh_signature(key, namespace, message):
    hash_alg = "sha512"
    h_message = hashlib.sha512(message).digest()

    magic = b"SSHSIG"
    reserved = b""
    
    data_to_sign = (
        magic + 
        encode_string(namespace) + 
        encode_string(reserved) + 
        encode_string(hash_alg) + 
        encode_string(h_message)
    )

    sig = key.sign_ssh_data(data_to_sign)

    version = 1
    public_key_blob = key.asbytes()
    
    sig_blob = (
        magic + 
        struct.pack('>I', version) + 
        encode_string(public_key_blob) + 
        encode_string(namespace) + 
        encode_string(reserved) + 
        encode_string(hash_alg) +
        encode_string(sig.asbytes())
    )

    armor = f"-----BEGIN SSH SIGNATURE-----\n{base64.b64encode(sig_blob).decode('utf-8')}\n-----END SSH SIGNATURE-----"
    return armor


def ensure_ssh_key_exists():
    """Generates crabe's dedicated passphrase-less signing key if it does not exist.

    The user's own keys (~/.ssh/id_rsa etc.) are never used: they may be encrypted.
    """
    ssh_key_path = SSH_KEY_PATH
    if not os.path.exists(ssh_key_path):
        log("SSH key not found. Generating...")
        try:
            os.makedirs(os.path.dirname(ssh_key_path), mode=0o700, exist_ok=True)
            # Generate key non-interactively
            subprocess.run(
                ["ssh-keygen", "-t", "ed25519", "-f", ssh_key_path, "-N", "",
                 "-C", f"crabe@{os.uname().nodename}"],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            log("SSH key generated successfully.")
        except subprocess.CalledProcessError:
            log("Failed to generate SSH key.", logging.ERROR)
    else:
        log("SSH key already exists.")


def install_crontab():
    """Installs the current file into crontab as an hourly job at a random minute."""
    script_path = os.path.abspath(__file__)
    
    try:
        current_crontab = subprocess.check_output(["crontab", "-l"], text=True)
    except subprocess.CalledProcessError:
        current_crontab = ""

    # Check if the script is already scheduled (loosely)
    # Allows for things like "chronic /path/to/crabe.py"
    if re.search(rf"\s{re.escape(script_path)}(\s|$)", current_crontab):
        log(f"Job for '{script_path}' already exists in crontab.")
        return

    # Generate a random minute between 0 and 59
    random_minute = random.randint(0, 59)
    job = f"{random_minute} * * * * {script_path}"

    new_crontab = current_crontab.strip() + "\n" + job + "\n"

    new_crontab = current_crontab.strip() + "\n" + job + "\n"

    process = subprocess.Popen(["crontab", "-"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    stdout, stderr = process.communicate(input=new_crontab)

    if process.returncode == 0:
        log(f"Successfully added '{job}' to crontab.")
    else:
        log(f"Failed to update crontab: {stderr}", logging.ERROR)


def send_data():
    """Sends machine_id, hostname, and public_ip to the specified URL with a random initial delay."""
    try:
        with open("/etc/hostname", "r") as f:
            hostname = f.read().strip()
    except FileNotFoundError:
        hostname = "unknown"

    # Sleep for a random amount of time to stagger requests, short enough to finish
    # under cron's `timeout 60`, unless we are on the development machine 'beethoven'
    if hostname != "beethoven":
        delay = random.randint(0, STAGGER_MAX_SECONDS)
        log(f"Staggering request: sleeping for {delay} seconds...")
        time.sleep(delay)

    try:
        with open("/etc/machine-id", "r") as f:
            machine_id = f.read().strip()
    except FileNotFoundError:
        log("Error: /etc/machine-id not found.", logging.ERROR)
        return

    try:
        with urllib.request.urlopen("https://api.ipify.org") as response:
            public_ip = response.read().decode('utf-8')
    except Exception:
        public_ip = "unknown"

    signatures = {}
    ssh_key_path = SSH_KEY_PATH

    if os.path.exists(ssh_key_path):
        try:
            key = paramiko.Ed25519Key.from_private_key_file(ssh_key_path)
            signature = create_ssh_signature(key, "file", machine_id.encode('utf-8'))
            signatures["ssh"] = signature
        except Exception as e:
            log(f"Error signing with SSH key: {e}", logging.ERROR)
    else:
        log(f"SSH key not found at {ssh_key_path}", logging.ERROR)

    data = {
        "payload": {
            "machine_id": machine_id,
            "hostname": hostname,
            "public_ip": public_ip,
            "python_version": sys.version
        },
        "signatures": signatures
    }

    # the main endpoint
    url = "https://www.monperrus.net/martin/crabe.py"

    try:
        jsondata = json.dumps(data).encode('utf-8')
        req = urllib.request.Request(url, data=jsondata)
        req.add_header('Content-Type', 'application/json')
        
        with urllib.request.urlopen(req) as response:
            log(f"Data sent. Status code: {response.getcode()}")
    except urllib.error.URLError as e:
        log(f"Error sending data: {e}", logging.ERROR)


def main():
    setup_logging()
    # Attempt to self-update before proceeding with the rest of the execution
    autoupdate()
    ensure_pip()
    ensure_ssh_key_exists()
    install_crontab()
    send_data()

if __name__ == "__main__":
    main()
