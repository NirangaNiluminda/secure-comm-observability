import argparse
import base64
import hashlib
import json

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec


def verify_log(log_path, public_key_path):
    with open(public_key_path, 'rb') as key_file:
        public_key = serialization.load_pem_public_key(key_file.read())

    previous_hash = '0' * 64
    line_number = 0

    with open(log_path, 'r', encoding='utf-8') as log_file:
        for raw_line in log_file:
            line_number += 1
            line = raw_line.strip()
            if not line:
                continue

            entry = json.loads(line)
            entry_previous_hash = entry['previous_hash']
            entry_hash = entry['entry_hash']
            signature = base64.b64decode(entry['signature'])
            event = entry['event']

            if entry_previous_hash != previous_hash:
                raise ValueError(
                    f'Chain mismatch at line {line_number}: expected previous_hash={previous_hash}, '
                    f'got {entry_previous_hash}'
                )

            canonical_event = json.dumps(event, sort_keys=True, separators=(',', ':'))
            computed_hash = hashlib.sha256((entry_previous_hash + canonical_event).encode('utf-8')).hexdigest()
            if computed_hash != entry_hash:
                raise ValueError(
                    f'Hash mismatch at line {line_number}: expected entry_hash={computed_hash}, got {entry_hash}'
                )

            try:
                public_key.verify(signature, entry_hash.encode('utf-8'), ec.ECDSA(hashes.SHA256()))
            except InvalidSignature as exc:
                raise ValueError(f'Signature verification failed at line {line_number}') from exc

            previous_hash = entry_hash

    print(f'Audit log verification passed. Entries checked: {line_number}')


def main():
    parser = argparse.ArgumentParser(description='Verify signed audit hash-chain log')
    parser.add_argument('--log', default='backend/audit_log.ndjson', help='Path to audit log file')
    parser.add_argument(
        '--public-key',
        default='backend/audit_signing_public.pem',
        help='Path to audit public key file',
    )
    args = parser.parse_args()

    verify_log(args.log, args.public_key)


if __name__ == '__main__':
    main()
