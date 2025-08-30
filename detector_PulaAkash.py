import pandas as pd
import json
import re
import csv

def mask_digits(s: str, keep_start: int = 2, keep_end: int = 2, mask_char: str = "X"):
    digits = re.sub(r'\D', '', s)
    if len(digits) <= keep_start + keep_end:
        return mask_char * len(digits)
    start = digits[:keep_start]
    end = digits[-keep_end:]
    middle = mask_char * (len(digits) - keep_start - keep_end)
    return start + middle + end

def mask_email(email: str):
    try:
        local, domain = email.split("@", 1)
    except ValueError:
        return "[REDACTED_PII]"
    if len(local) <= 2:
        masked_local = local[0] + "X" * (max(0, len(local)-1))
    else:
        masked_local = local[0] + "X" * (len(local)-2) + local[-1]
    return masked_local + "@" + domain

def redact_pii(data_json):
    try:
        record = json.loads(data_json)
    except Exception:
        # If JSON is malformed, return it as-is and mark no PII detection
        return data_json, False

    is_pii = False
    redacted = {}

    # Standard standalone PII keys and handling
    pii_key_handlers = {
        "phone": lambda v: "[REDACTED_PII]" if not re.search(r'\d', str(v)) else mask_digits(str(v), 2, 2),
        "aadhar": lambda v: "[REDACTED_PII]" if not re.match(r'^\d{12}$', re.sub(r'\D', '', str(v))) else (re.sub(r'\D', '', str(v))[:4] + "XXXX" + re.sub(r'\D', '', str(v))[-4:]).replace("", "") ,
        "passport": lambda v: "[REDACTED_PII]" if not re.match(r'^[A-Z]\d{7}$', str(v)) else (str(v)[0] + "XXXXXXX"),
        "upi_id": lambda v: "[REDACTED_PII]" if "@" not in str(v) else "[REDACTED_PII]",
        "email": lambda v: mask_email(str(v)),
        "ip_address": lambda v: "[REDACTED_PII]",
        "device_id": lambda v: "[REDACTED_PII]",
        "name": lambda v: "[REDACTED_PII]",
        "address": lambda v: "[REDACTED_PII]",
    }

    # Keys considered non-PII to always pass through
    non_pii_keys_to_skip = {'first_name', 'last_name', 'city', 'state', 'pin_code', 'transaction_id', 'order_id', 'product_description', 'product_name'}

    # Normalize keys present in the record
    present_pii_keys = []
    for key, value in record.items():
        low = key  # keep original key name when writing output
        if low in pii_key_handlers:
            present_pii_keys.append(low)

    # Standalone redaction: redact any recognized PII keys individually
    for key, value in record.items():
        if key in non_pii_keys_to_skip:
            redacted[key] = value
            continue

        if key in pii_key_handlers:
            is_pii = True
            try:
                redacted_value = pii_key_handlers[key](value)
            except Exception:
                redacted_value = "[REDACTED_PII]"
            redacted[key] = redacted_value
        else:
            redacted[key] = value

    # Combinatorial rule: if two or more different PII items appear together, ensure sensitive context keys are redacted
    # (e.g., if name + email present, redact address/ip/device too).
    if len(present_pii_keys) >= 2:
        is_pii = True
        for k in ('address', 'ip_address', 'device_id', 'name', 'email', 'phone', 'aadhar', 'passport', 'upi_id'):
            if k in record:
                redacted[k] = pii_key_handlers.get(k, lambda v: "[REDACTED_PII]")(record[k])

    return json.dumps(redacted, ensure_ascii=False), is_pii

def main():
    input_file = 'iscp_pii_dataset.csv'
    output_file = 'redacted_output_PulaAkash.csv'

    df = pd.read_csv(input_file, dtype=str).fillna('')

    with open(output_file, 'w', newline='', encoding='utf-8') as outfile:
        writer = csv.writer(outfile)
        writer.writerow(['record_id', 'redacted_data_json', 'is_pii'])

        for index, row in df.iterrows():
            record_id = row.get('record_id', '')
            data_json = row.get('data_json', '')

            if not data_json or not data_json.strip():
                # skip empty
                writer.writerow([record_id, json.dumps({}), False])
                continue

            try:
                redacted_json, is_pii = redact_pii(data_json)
            except Exception as e:
                # Log and skip malformed record
                print(f"Skipping malformed or problematic JSON at record_id {record_id}: {e}")
                continue

            writer.writerow([record_id, redacted_json, int(bool(is_pii))])

if __name__ == '__main__':
    main()