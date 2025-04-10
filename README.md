# Automated Attack Surface Scanning Tool (Linux)

## Feature:
- Find **all subdomains** on them from an input domain name.
- Allows users to provide registered hosts: if a new host was found when scanning --> **Alert** 
- Automatically scan after a certain period of time.
- Send alert to administrator's email, MS teams 

## How it works:
- This is a series of tool commands run.
- The user enters input using the command line
- Uses Subfinder, Sublist3r, Assetfinder, Security-trails
- Combines results of subdomains and opening ports from all tools to terminal or a single file

## Installation:
1. Install python, go and git (if not already)
```
sudo apt update
sudo apt install python3 python3-pip -y
sudo apt install git
```
2. Install tool and run the setup.sh:
```
git clone https://github.com/it-sec-vf/asm
```
```
cd asm
chmod +x install.sh
./install.sh
```

## Usage:
  You can change your Securitytrails API key and registered host-port in config.ini
  ### Summary of <code>option</code> flag

| Option        | Description                                           | Example Command                                           |
|---------------|-------------------------------------------------------|----------------------------------------------------------|
| `-d`      | Use Subfinder, Sublist3r, Assetfinder and Security-trails API to scan for subdomain   | `python3 asm.py -d <domain name> ` |
| `-f` | Multiple Domain Input for scanning | `python3 asm.py -f <domain file txt>` |
| `-a` | Get valid host-port data from config.ini, compare with scanned host-ports and ALERT if there is a difference | `python3 asm.py -d <domain name> -p -a` |
| `-o` | Write to output file to save the results | `python3 asm.py -d <domain name> -o` |
| `-email` | Send email alerts for detected issues | `python3 asm.py -d <domain name> -a -email` |
| `--teams` | Send teams alerts for detected issues | `python3 asm.py -d <domain name> -a --teams` |
| `-t` | Run tool automatically every specified second | `python3 asm.py -d <domain name> -a -t 86400` |

## Step by step to send ALERT to Email or MS Teams
1. Set up:
- Add your registered domains to domain_validated.ini
- Add your domains you want to monitor to domain_monitor.txt  
2. Change config.ini:
- Change "your_gmail" and "your_app_password", if don't know how to create app password, go [here](https://myaccount.google.com/apppasswords?pli=1&rapt=AEjHL4OVlHBZyIzfrw29E_Q4mYB5-Ei_wmrnL7Bw5Mvr51ST_6r9yfNADQL6wxYkdzGYKzB5DULwwhRcJaOEfKjloUDyhUbRCHUonLcj99aCP6EDXzOBBFM)
- Change "webhook_url", "mention_id" and "mention_name", if you don't know how to create them, go [here](https://github.com/it-sec-vf/asm/tree/main/Get%20webhook%20teams)  
3. Send alert to your email:
- For example, you want to run the tool periodically once a day:
```
python3 asm.py -d <domain name> -p -a -t 86400 
```
And done!!!  

## Step by step to AUTOMATICALLY run ASM tool 24/7 (Scan subdomain and port, alert, send alert email to admin):
1. Build your Domain list to scan. (domain.txt)
2. Config as "send ALERT to email" path above
3. Scan here:
```
python3 asm.py -f <domain file txt> -a -t 86400 
```
4.See log info in asm_tool.log:
- For example:
```
2024-12-03 12:20:55,929 [INFO] Starting scan for domain: google.com
2024-12-03 12:22:38,916 [INFO] Scan completed successfully for domain: google.com
2024-12-03 12:22:38,916 [INFO] Starting scan for domain: youtube.com
2024-12-03 12:23:30,076 [INFO] Scan completed successfully for domain: youtube.com
2024-12-03 12:23:30,076 [INFO] Waiting 86400 seconds for the next cycle...
```
