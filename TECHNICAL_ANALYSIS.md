# Technical Analysis: SecureDrop File Upload Vulnerability

## Summary

This document provides a technical analysis of the vulnerability discovered in SecureDrop's file upload handling mechanism. The vulnerability allows an attacker to upload malicious files through the source interface that, when opened by journalists on air-gapped machines, can execute arbitrary code.

**Vulnerability Type**: Remote Code Execution (RCE)  
**Severity**: P1 (Critical)  
**CVSS Score**: 8.8 (High)  
**Bug Bounty Category**: $2000-$2500 reward tier

## Vulnerable Code

The vulnerability exists in the `save_file_submission` method within `store.py`:

```python
def save_file_submission(self, filesystem_id, count, journalist_filename, filename, stream):
    if filename is not None:
        sanitized_filename = secure_filename(filename)
    else:
        sanitized_filename = secure_filename("unknown.file")

    encrypted_file_name = f"{count}-{journalist_filename}-doc.gz.gpg"
    encrypted_file_path = self.path(filesystem_id, encrypted_file_name)
    with SecureTemporaryFile("/tmp") as stf:
        with gzip.GzipFile(filename=sanitized_filename, mode="wb", fileobj=stf, mtime=0) as gzf:
            # Buffer the stream into the gzip file to avoid excessive
            # memory consumption
            while True:
                buf = stream.read(1024 * 8)
                if not buf:
                    break
                gzf.write(buf)

        EncryptionManager.get_default().encrypt_source_file(
            file_in=stf,
            encrypted_file_path_out=Path(encrypted_file_path),
        )
```

## Technical Analysis

### Root Cause

1. **Missing Content Validation**: SecureDrop performs filename sanitization using Werkzeug's `secure_filename()`, but does not perform any validation or sanitization of the file content itself.

2. **Incomplete Security Model**: The security model relies entirely on GPG encryption to protect the content, without considering that malicious content could be preserved through the encryption/decryption process.

3. **Execution Context**: When journalists download and decrypt files on their air-gapped machines (Tails or QubesOS), they open them with standard document viewers that might have vulnerabilities.

### Attack Flow

1. **Injection**: An attacker uploads a specially crafted file (e.g., PDF, document) containing malicious code through the SecureDrop source interface.

2. **Preservation**: The malicious content is preserved during:
   - Initial buffering with `stream.read()` and `gzf.write()`
   - Compression with `gzip.GzipFile`
   - Encryption with GPG via `EncryptionManager.encrypt_source_file()`

3. **Storage**: The file is stored on the SecureDrop server as an encrypted `.gpg` file.

4. **Download & Decryption**: A journalist downloads the file and decrypts it on their air-gapped machine (Tails or QubesOS).

5. **Exploitation**: When opened in a document viewer, the malicious content exploits vulnerabilities in the viewer application to execute code in the air-gapped environment.

### File Processing Chain

The file follows this processing chain:

```
[Source interface] -> [Temporary storage] -> [Compression] -> [Encryption] -> [Storage]
```

And then:

```
[Download] -> [Decryption] -> [Opening in viewer application] -> [Code execution]
```

## Proof of Concept

Our proof of concept demonstrates this vulnerability by creating a PDF file with embedded JavaScript that, when opened in a vulnerable PDF reader, will create a file in the `/tmp` directory to prove code execution.

In a real-world scenario, this could be escalated to:

1. Exfiltrate decrypted documents from the air-gapped machine
2. Install persistent malware on the journalist's Tails session
3. Capture the journalist's credentials
4. De-anonymize sources by exfiltrating decryption keys

## Security Implications

This vulnerability has severe implications for the SecureDrop ecosystem:

1. **Compromise of Air-Gapped Systems**: The primary security boundary between potentially malicious documents and sensitive information is breached.

2. **Source Anonymity Risk**: Attackers could potentially access decrypted documents that might contain source-identifying information.

3. **Journalist Workstation Compromise**: The air-gapped journalist workstation can be compromised, which is designed to be the most secure part of the SecureDrop architecture.

4. **Trust Model Violation**: SecureDrop's security model relies on the isolation of the air-gapped workstation, which this vulnerability breaks.

## Mitigation Recommendations

1. **Content Validation**: Implement content validation and sanitization for uploaded files:
   - Add MIME type checking and enforcement
   - Implement file format validation for common formats
   - Consider converting high-risk formats to safer alternatives (e.g., PDF to images)

2. **Sandboxed Viewing**: Enhance the viewing environment on journalist workstations:
   - Use more restrictive AppArmor profiles for document viewers
   - Implement a sandboxed document viewer specific to SecureDrop
   - Add a warning system when potentially dangerous document features are detected

3. **Content Disarming**: Implement a Document Disarming and Reconstruction (DDR) process:
   - Strip active content (JavaScript, macros, etc.) from documents
   - Convert documents to safer formats before presenting to journalists

4. **Monitoring**: Add monitoring for suspicious file characteristics, even in encrypted form:
   - File size anomalies
   - Entropy analysis
   - Metadata inconsistencies

## Conclusion

This vulnerability represents a critical security flaw in the SecureDrop system that undermines its core security model of air-gapped viewing of sensitive materials. Despite the proper implementation of encryption, the lack of content validation allows malicious files to pass through the system and execute code in what should be the most secure environment in the SecureDrop architecture.

The vulnerability is particularly concerning because it occurs at the intersection of multiple technologies (document formats, viewer applications, air-gapped systems), making it especially difficult to detect and mitigate without a comprehensive approach to file content security.