import click
import logging
import os

def load_validated_subdomains(ini_file: str, domain: str) -> set:
    if not os.path.isfile(ini_file):
        logging.warning(f"File {ini_file} không tồn tại. Trả về set rỗng.")
        return set()

    validated_subs = set()
    in_target_section = False

    with open(ini_file, 'r', encoding='utf-8') as f:
        for line in f:
            raw_line = line.strip()

            # Nếu gặp dòng bắt đầu bằng [ ... ]
            if raw_line.startswith("[") and raw_line.endswith("]"):
                # Kiểm tra domain
                section_name = raw_line[1:-1].strip()  # cắt bỏ dấu []
                if section_name.lower() == domain.lower():
                    in_target_section = True
                else:
                    in_target_section = False
                continue
            
            # Nếu đang ở section của domain
            if in_target_section:
                # Bỏ qua dòng trống, comment
                if not raw_line or raw_line.startswith('#') or raw_line.startswith(';'):
                    continue
                # Thêm subdomain vào set
                validated_subs.add(raw_line)

    return validated_subs

def console_alert(domain: str, message: str):
    if message:
        click.echo(f"[{domain}] {message}")
    else:
        logging.info(f"No alert for {domain}")
