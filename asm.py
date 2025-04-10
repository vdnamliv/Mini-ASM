import click
import subprocess
import configparser
import os
import tempfile
import schedule
import time
import re 
import logging
import shutil
from datetime import date, datetime, timedelta
from concurrent.futures import ThreadPoolExecutor, as_completed
from function.subdomain import (
    run_subfinder,
    run_sublist3r,
    run_assetfinder,
    run_securitytrails,
    merge_files,
)
from function.alert import console_alert
from function.email_alert import email_alert_message
from function.teams_alert import teams_alert_message

# Configure logging
log_file = "asm_tool.log"
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(log_file),
        logging.StreamHandler()  
    ]
)

def run_command(command):
    try:
        subprocess.run(command, shell=True, check=True)
    except subprocess.CalledProcessError as e:
        click.echo(f"Error occurred: {e}")
        exit(1)

def safe_run(func, *args, **kwargs):
    try:
        func(*args, **kwargs)
    except Exception as e:
        click.echo(f"Error running {func.__name__}: {e}")

def load_validated_subdomains(validated_ini, domain) -> dict:

    if not os.path.exists(validated_ini):
        logging.warning(f"{validated_ini} does not exist, returning empty dict")
        return {}

    parser = configparser.ConfigParser()
    parser.optionxform = str
    parser.read(validated_ini, encoding="utf-8")

    # Lưu ý: section name so sánh lowercase?
    if not parser.has_section(domain):
        return {}

    result = {}
    for sub_key in parser[domain]:
        # sub_key là "subdomain.domain"
        date_str = parser[domain][sub_key].strip()
        result[sub_key] = date_str
    return result

def find_expired_subdomains(old_sub_dict, days_valid=365) -> set:
    """
    Từ dict sub -> date_str, trả về set subdomain nào đã quá hạn so với today
    """
    expired = set()
    today = date.today()

    for sub, date_str in old_sub_dict.items():
        try:
            validated_date = datetime.strptime(date_str, "%Y-%m-%d").date()
            delta = (today - validated_date).days
            if delta >= days_valid:
                expired.add(sub)
        except ValueError:
            # Format ngày sai
            logging.warning(f"Invalid date format for {sub} = {date_str}")
    return expired

def execute_scan(domain, alert_terminal, output, alert_email, alert_teams):

    # Load configuration
    config = configparser.ConfigParser(interpolation=None)
    config.read("config.ini")
    api_key_st = config.get("path", "api_key_st", fallback="none")
    validated_ini = config.get("path", "domain_validated_file", fallback="domain_validated.ini")

    tmp_dir = "temp"
    os.makedirs(tmp_dir, exist_ok=True)

    sub_files = {
        "subfinder": os.path.join(tmp_dir, "subfinder.txt"),
        "sublist3r": os.path.join(tmp_dir, "sublist3r.txt"),
        "assetfinder": os.path.join(tmp_dir, "assetfinder.txt"),
        "securitytrails": os.path.join(tmp_dir, "securitytrails.txt")
    }

    # Subdomain enumeration if "-d" is specified
    if domain:
        with ThreadPoolExecutor(max_workers=4) as executor:
            futures = [
                executor.submit(run_subfinder, domain, sub_files["subfinder"]),
                executor.submit(run_sublist3r, domain, sub_files["sublist3r"]),
                executor.submit(run_assetfinder, domain, sub_files["assetfinder"]),
                executor.submit(run_securitytrails, domain, api_key_st, sub_files["securitytrails"])
            ]
            for future in as_completed(futures):
                future.result()

        # merging subdomains from all tools
        merged_file = os.path.join(tmp_dir, "merged_subdomains.txt")
        merge_files(sub_files, merged_file)

        if os.path.exists(merged_file):
            click.echo(f"\n====== Subdomains for {domain} ======")
            with open(merged_file, "r") as f:
                subdomains_content = f.read().strip()
                if subdomains_content:
                    click.echo(subdomains_content)
                else:
                    click.echo("No subdomains found.")

    found_subdomains = set()
    with open(merged_file, 'r', encoding='utf-8') as f:
        for line in f:
            sub = line.strip()
            if sub:
                found_subdomains.add(sub)

    # Only alert if hosts (scan) are in domain_validated.ini file
    if alert_terminal or alert_email or alert_teams:

        old_subs_dict = load_validated_subdomains(validated_ini, domain)
        new_subs = found_subdomains - set(old_subs_dict.keys())
        exprired_subs = find_expired_subdomains(old_subs_dict, days_valid=365)

        full_message = ""
        
        if new_subs:
            full_message += f"[+] Found {len(new_subs)} new subdomain(s) for [{domain}]:\n"
            full_message += "\n".join(new_subs)
        else:
            full_message += f"No new subdomains for [{domain}]"
        
        if exprired_subs:
            full_message += f"\n\n[!] Found {len(exprired_subs)} expired subdomain(s) for [{domain}]:\n"
            full_message += "\n".join(exprired_subs)
        else:
            full_message += f"\nNo expired subdomains for [{domain}]"

        if alert_terminal:
            console_alert(domain, full_message)
        if alert_email:
            email_alert_message(domain, full_message)
        if alert_teams:
            teams_alert_message(domain, full_message)

    if os.path.exists(tmp_dir):
        try:
            shutil.rmtree(tmp_dir)
            logging.info(f"Removed temp directory: {tmp_dir}")
        except Exception as e:
            logging.warning(f"Could not remove temp directory: {e}")

@click.command()
@click.option('-d', '--domain', type=str, help='Domain to scan for subdomains')
@click.option('-f', '--file', type=click.Path(exists=True), help='File containing multiple domains to scan')
@click.option('-a', '--terminal-alert', is_flag=True, help='Validate results against registered hosts and ports')
@click.option('-email', '--email-alert', is_flag=True, help='Send email alerts for detected issues')
@click.option('-teams', '--msteams-alert', is_flag=True, help='Send Teams alerts for detected issues')
@click.option('-t', '--interval-time', type=int, default=None, help='Interval time in seconds for repeated scans')
@click.option('-o', '--output', type=click.Path(), help='File to save the final results')

def main(domain, file, terminal_alert, output, email_alert, msteams_alert, interval_time):

    logging.info("=== ASM tool started ===")

    def single_scan(target_domain):
        logging.info(f"[*] Begin scanning domain: {target_domain}")
        try:
            execute_scan(
                domain=target_domain,
                alert_terminal=terminal_alert,
                output=output,
                alert_email=email_alert,
                alert_teams=msteams_alert
            )
            logging.info(f"[+] Done scaned: {target_domain}")
        except Exception as e:
            logging.error(f"[!] Error when scan domain {target_domain}: {e}")

    if file:
        with open(file, 'r', encoding='utf-8') as f:
            domains = [line.strip() for line in f if line.strip()]

        logging.info(f"Loading {len(domains)} domains from file: {file}")

        if interval_time:
            while True:
                for d in domains:
                    single_scan(d)
                logging.info(f"Waiting {interval_time} second before next cycle ...")
                time.sleep(interval_time)
        else:
            for d in domains:
                single_scan(d)

    else:
        if not domain:
            logging.error("Please using -d <domain> or -f <file>")
            return

        if interval_time:
            while True:
                single_scan(domain)
                logging.info(f"Waiting {interval_time} second before next cycle ...")
                time.sleep(interval_time)
        else:
            single_scan(domain)

    logging.info("=== ASM scanning finished ===")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        logging.warning("Scan stopped by user.")
        if os.path.exists(tmp_dir):
            try:
                shutil.rmtree(tmp_dir)
                logging.info(f"Removed temp directory: {tmp_dir}")
            except Exception as e:
                logging.warning(f"Could not remove temp directory: {e}")
        exit(0)
