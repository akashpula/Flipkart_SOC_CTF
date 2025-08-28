import pandas as pd
import json
import re
import csv

def redact_pii(data_json):
    record = json.loads(data_json)
    is_pii = False
    redacted_record = {}

    # Standalone PII detection and redaction
    pii_keys = ['phone', 'aadhar', 'passport', 'upi_id']
    for key in pii_keys:
        if key in record:
            is_pii = True
            if key == 'phone' and re.match(r'^\d{10}$', str(record[key])):
                redacted_record[key] = re.sub(r'(\d{2})(\d{6})(\d{2})', r'\1XXXXXX\3', record[key])
            elif key == 'aadhar' and re.match(r'^\d{12}$', str(record[key])):
                redacted_record[key] = re.sub(r'(\d{4})(\d{4})(\d{4})', r'\1 XXXX \3', record[key])
            elif key == 'passport' and re.match(r'^[A-Z]\d{7}$', str(record[key])):
                redacted_record[key] = '[REDACTED_PII]'
            elif key == 'upi_id' and '@' in str(record[key]):
                redacted_record[key] = '[REDACTED_PII]'
            else:
                redacted_record[key] = record[key]
        elif key in record: # This is a fallback
            redacted_record[key] = record[key]

    # Combinatorial PII detection and redaction
    combinatorial_pii_candidates = []
    
    # Pre-checks to handle known non-PII keys
    non_pii_keys_to_skip = ['first_name', 'last_name', 'city', 'state', 'pin_code', 'transaction_id', 'order_id', 'product_description', 'product_name']
    
    for key, value in record.items():
        if key in non_pii_keys_to_skip:
            redacted_record[key] = value
            continue

        if key in ['name', 'email', 'address', 'ip_address', 'device_id']:
            combinatorial_pii_candidates.append(key)

    if len(combinatorial_pii_candidates) >= 2:
        is_pii = True
        for key, value in record.items():
            if key in combinatorial_pii_candidates:
                if key == 'email':
                    redacted_record[key] = '[REDACTED_PII]'
                elif key == 'name':
                    redacted_record[key] = '[REDACTED_PII]'
                elif key == 'address':
                    redacted_record[key] = '[REDACTED_PII]'
                elif key in ['ip_address', 'device_id']:
                    redacted_record[key] = '[REDACTED_PII]'
            else:
                if key not in redacted_record: # Keep non-pii keys
                    redacted_record[key] = value
    else:
        for key, value in record.items():
            if key not in redacted_record:
                redacted_record[key] = value

    return json.dumps(redacted_record), is_pii

def main():
    input_file = 'iscp_pii_dataset.csv'
    output_file = 'redacted_output_PulaAkash.csv'

    df = pd.read_csv(input_file)
    
    with open(output_file, 'w', newline='', encoding='utf-8') as outfile:
        writer = csv.writer(outfile)
        writer.writerow(['record_id', 'redacted_data_json', 'is_pii'])

        for index, row in df.iterrows():
            record_id = row['record_id']
            data_json = row['data_json']
            
            # Special handling for empty/corrupted JSON
            if not data_json.strip().startswith('{') or not data_json.strip().endswith('}'):
                print(f"Skipping malformed JSON at record_id {record_id}")
                continue

            redacted_json, is_pii = redact_pii(data_json)
            writer.writerow([record_id, redacted_json, is_pii])

if __name__ == '__main__':
    main()