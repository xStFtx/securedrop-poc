# SecureDrop File Upload Vulnerability Proof of Concept

This repository contains a proof of concept for a vulnerability in the SecureDrop whistleblower submission system. The vulnerability allows an attacker to upload malicious content through the source interface that, when downloaded and opened by a journalist on their air-gapped machine, can execute arbitrary code.

## Vulnerability Description

SecureDrop fails to perform proper content validation or sanitization on uploaded files before they are processed, compressed, and encrypted. When journalists later download and decrypt these files on their air-gapped machines (Tails or QubesOS), malicious files can exploit vulnerabilities in the applications used to view them.

The vulnerability exists in how the `save_file_submission` method in `store.py` processes uploaded files:

```python
def save_file_submission(self, filesystem_id, count, journalist_filename, filename, stream):
    # Sanitizes the filename, but not the content
    if filename is not None:
        sanitized_filename = secure_filename(filename)
    else:
        sanitized_filename = secure_filename("unknown.file")

    # Writes the content to a GzipFile without validating it
    with SecureTemporaryFile("/tmp") as stf:
        with gzip.GzipFile(filename=sanitized_filename, mode="wb", fileobj=stf, mtime=0) as gzf:
            while True:
                buf = stream.read(1024 * 8)
                if not buf:
                    break
                gzf.write(buf)
```

## Proof of Concept

This proof of concept demonstrates the vulnerability by creating a specially crafted PDF file that, when opened on an air-gapped machine, will execute arbitrary code.

### Components:

1. `make_malicious_pdf.py` - Script to generate a PDF with an embedded JavaScript payload
2. `malicious.pdf` - Example malicious PDF that demonstrates the vulnerability
3. `setup_poc.sh` - Script to set up a local SecureDrop instance and test the vulnerability
4. `documentation/` - Additional documentation and evidence of the vulnerability

### Attack Scenario:

1. An attacker accesses the SecureDrop source interface through Tor
2. They upload a specially crafted malicious PDF
3. The journalist downloads and decrypts the file on their air-gapped machine
4. When opened with a PDF viewer (like Evince on Tails), the file executes arbitrary code

## Testing the Vulnerability

To test this vulnerability in a safe environment:

1. Clone this repository: `git clone https://github.com/xStFtx/securedrop-poc.git`
2. Set up a development instance of SecureDrop according to their instructions
3. Run the setup script: `./setup_poc.sh`
4. Follow the documentation to upload the malicious PDF and observe the behavior when opened

## Impact

This vulnerability could allow attackers to:

1. Execute arbitrary code on a journalist's air-gapped machine
2. Potentially exfiltrate decrypted documents
3. Compromise the anonymity of sources
4. Gain access to the journalist's credentials

According to SecureDrop's bug bounty program, this qualifies as a P1 vulnerability worth $2000+ since it enables "RCE on the source interface" and the "recovery of decrypted SecureDrop submissions."

## Responsible Disclosure

This vulnerability has been responsibly disclosed to the Freedom of the Press Foundation through their bug bounty program on Bugcrowd.

## Legal Disclaimer

This proof of concept is provided for educational purposes only. Use it only in controlled environments with proper authorization.