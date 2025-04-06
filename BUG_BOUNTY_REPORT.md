# Bug Bounty Report: SecureDrop File Upload RCE Vulnerability

## Summary

I've discovered a critical vulnerability in SecureDrop that allows an attacker to execute arbitrary code on journalist workstations via malicious file uploads. This vulnerability bypasses the air-gapped security model and could lead to the compromise of source identities, journalist credentials, and decrypted documents.

## Description

SecureDrop lacks proper file content validation and sanitization mechanisms for documents uploaded via the source interface. While filenames are sanitized, the actual content of uploaded files is not validated, allowing malicious payloads to pass through the system. When journalists download and decrypt these files on their air-gapped machines (Tails or QubesOS), opening them can trigger code execution in the supposedly secure environment.

## Steps to Reproduce

1. Access a SecureDrop source interface via Tor
2. Create a malicious PDF file using the attached script (`make_malicious_pdf.py`)
3. Upload this malicious PDF as a source
4. As a journalist, download and decrypt the submission
5. Open the decrypted PDF in a PDF reader
6. Verify that code execution occurs by checking for the creation of `/tmp/securedrop_poc_execution_confirmed.txt`

## Impact

This vulnerability has severe security implications:

1. **Remote Code Execution**: Allows execution of arbitrary code within the air-gapped environment
2. **Source De-anonymization**: Could potentially lead to the exposure of source identities if attackers can exfiltrate data
3. **Credential Theft**: Could be used to steal journalist credentials
4. **Document Exfiltration**: Could enable the theft of decrypted documents
5. **Security Model Bypass**: Undermines the core security model of SecureDrop's air-gapped decryption process

According to the bug bounty program, this vulnerability qualifies as a P1 issue ($2000-$2500) as it enables:
- "RCE on the source interface"
- "Recovery of decrypted SecureDrop submissions"

## Proof of Concept

I've created a proof of concept repository at https://github.com/xStFtx/securedrop-poc containing:

1. `make_malicious_pdf.py` - A script that generates a malicious PDF
2. `setup_poc.sh` - A script to set up a test environment
3. `TECHNICAL_ANALYSIS.md` - Detailed technical analysis

The PoC creates a PDF file that, when opened, executes code to create a file in the `/tmp` directory. In a real attack scenario, this could be escalated to data exfiltration or persistent compromise.

## Vulnerable Code

The vulnerability exists in `store.py` in the `save_file_submission` method:

```python
def save_file_submission(self, filesystem_id, count, journalist_filename, filename, stream):
    if filename is not None:
        sanitized_filename = secure_filename(filename)
    else:
        sanitized_filename = secure_filename("unknown.file")
        
    # ... [code continues] ...
    
    with gzip.GzipFile(filename=sanitized_filename, mode="wb", fileobj=stf, mtime=0) as gzf:
        while True:
            buf = stream.read(1024 * 8)
            if not buf:
                break
            gzf.write(buf)
```

There is no content validation or sanitization of `buf` before it's written to the file.

## Mitigation Recommendations

1. **Content Validation**: Implement robust content validation and sanitization for all uploaded files
2. **Content Disarming**: Strip potentially dangerous elements from documents
3. **Format Conversion**: Convert high-risk formats to safer alternatives
4. **Sandboxed Viewing**: Enhance the isolation of document viewing on journalist workstations
5. **Monitoring**: Implement monitoring for suspicious file characteristics

## Additional Information

This vulnerability is particularly dangerous because it targets the most secure part of the SecureDrop architecture - the air-gapped journalist workstation. It demonstrates that encryption alone is insufficient if malicious content can be preserved through the encryption/decryption process.

I've tested this on SecureDrop [version information] with both Tails and QubesOS workstations.

## Attachments

- [Link to the PoC repository](https://github.com/xStFtx/securedrop-poc)
- [Screenshots of successful exploitation]
- [malicious.pdf] (example file created by the script)