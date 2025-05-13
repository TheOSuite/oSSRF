---

# oSSRF Vulnerability Tester

## Overview

The oSSRF Vulnerability Tester is a Python-based tool designed to identify Server-Side Request Forgery (SSRF) vulnerabilities in web applications. It tests a target application's ability to fetch external or internal resources based on user-supplied input, using various protocols and encoding techniques to bypass potential filters.

The tool includes a controlled target server to detect blind SSRF, where the target application doesn't directly display the fetched content. It also analyzes the target application's HTTP response for indicators of successful or failed connection attempts, particularly useful for Gopher and `file://` protocols.

A Graphical User Interface (GUI) is provided using Tkinter for ease of use.

## Features

- **Targeted Testing:** Specify the target URL and the vulnerable parameter(s).
- **Controlled Target:** Includes a built-in HTTP server to act as a controlled target for detecting blind SSRF via callbacks.
- **Payload Types:**
  - Controlled Target (HTTP/HTTPS)
  - Common Internal IP Addresses and Ports
  - Cloud Metadata Endpoints (AWS, GCP, Azure)
  - File Access (`file://`) for common sensitive files
  - Gopher Payloads for interacting with internal services (e.g., Redis)
- **Response Analysis:** Analyzes the target application's HTTP response for error messages or service-specific response patterns indicating successful or failed internal interactions (especially for Gopher and `file://`).
- **Encoding and Obfuscation:** Apply various techniques to bypass input validation filters:
  - URL Encoding
  - Double URL Encoding
  - IP Address Integer Representation
  - IP Address Hexadecimal Representation
  - IP Address Octal Representation
  - Null Byte Injection
- **Multiple HTTP Methods:** Test GET, POST, PUT, HEAD, and PATCH methods.
- **Retries and Delay:** Configure retries and delays for requests to handle network instability or rate limiting.
- **Proxy Support:** Route traffic through an HTTP proxy (e.g., Burp Suite, OWASP ZAP) for analysis or debugging.
- **GUI Interface:** User-friendly graphical interface for configuring scans and viewing results.
- **Reporting:** Output scan results in text, JSON, or CSV format.

## Prerequisites

- Python 3.x
- `requests` library (`pip install requests`)
- `ipaddress` (standard library in Python 3.3+)
- `tkinter` (usually included with Python installations, but may require separate installation on some Linux distributions)

## Installation

1. **Clone the repository (or download the script):**

   ```bash
   git clone https://github.com/TheOSuite/oSSRF.git
   cd oSSRF  # Change to the script directory
   ```
   Or simply download the Python file `oSSRF.py`.

2. **Install dependencies:**

   ```bash
   pip install requests
   ```
   (Tkinter and ipaddress should be built-in with standard Python 3 installations.)

## Usage

The tool can be run with a GUI.

### Running the GUI

Execute the script directly:

```bash
python oSSRF.py
```

This will open the graphical interface.

### GUI Walkthrough

1. **Target & Controlled Target Tab:**
   - **Target Application URL:** The URL of the web application endpoint you want to test (e.g., `http://example.com/image?url=`).
   - **Parameter(s) to Test:** The name(s) of the URL parameter(s) where the external URL will be injected (e.g., `url` or `image_url,file`). Use commas to separate multiple parameters.
   - **Controlled Target IP:** The public IP address or hostname of the machine running this script. The target application will attempt to connect to this IP if you enable "Test Controlled Target".
   - **Controlled Target Port:** The port the controlled target server will listen on (default: 8080).
   - **HTTP Method(s):** The HTTP method(s) to use when sending requests to the *target application*. Use commas to separate multiple methods (e.g., `GET,POST`).

2. **Payload Options Tab:**
   - Select the types of payloads you want to test (Controlled Target, Internal IPs, Cloud Metadata, File Access, Gopher).
   - **Test Controlled Target:** If selected, the script will generate payloads pointing back to your controlled target.
   - **Generate Unique ID:** If selected with "Test Controlled Target", a UUID will be added to the controlled target URL, helping identify blind SSRF attempts.
   - **Test Common Internal IPs:** If selected, payloads targeting common internal IP ranges will be generated.
   - **Internal Ports:** Specify comma-separated ports to test with internal IP payloads (default: 80,443,8080).
   - **Test Cloud Metadata Endpoints:** If selected, payloads targeting common cloud metadata IPs/hostnames will be generated.
   - **Test Common File Access (file://):** If selected, payloads attempting to read common local files using the `file://` protocol will be generated.
   - **Test Gopher Payloads:** If selected, payloads using the `gopher://` protocol will be generated to interact with a specified internal service.
   - **Gopher Target IP:** The internal IP address of the service to target with Gopher (required if "Test Gopher Payloads" is selected).
   - **Gopher Target Port:** The internal port of the service to target with Gopher (required if "Test Gopher Payloads" is selected).
   - **Gopher Commands:** Comma-separated commands to send to the Gopher target (required if "Test Gopher Payloads" is selected). Example for Redis: `PING,INFO`.

3. **Advanced Options Tab:**
   - **Encoding Techniques:** Select the encoding techniques to apply to the generated payloads. Multiple techniques can be selected. The tool will generate variations of each base payload with the chosen encoding(s).
   - **Request Timeout:** Timeout in seconds for requests sent to the target application.
   - **Retries:** Number of times to retry sending a request to the target application if it fails.
   - **Delay between Retries:** Delay in seconds between retries.
   - **Proxy:** Specify an HTTP proxy (e.g., `http://127.0.0.1:8080`) to route all requests through.

4. **Results Tab:**
   - This tab displays the scan progress, logs, and identified findings.
   - **Start Scan Button:** Located on the "Target & Controlled Target" tab, initiates the scan.
   - **Save Report Button:** Saves the findings to a file in text, JSON, or CSV format.

### Interpreting Results

The results are displayed in the "Results" tab of the GUI and can be saved to a report file. Key indicators of SSRF are:

- **Controlled Target Access (Severity: Low/High):** If the controlled target server receives a request from the target application, it indicates the target successfully fetched the injected URL. A "High" severity is assigned if a unique ID was used, confirming blind SSRF.
- **Target Response Analysis (Severity: Low/High/Critical):**
  - **Error Patterns (Severity: Low):** If the target application's response contains error messages indicative of a failed connection attempt to an internal or external resource (e.g., "connection refused"), it suggests the target *tried* to fetch the payload URL.
  - **Success Patterns (Severity: High/Critical):** If the target application's response contains patterns expected from an internal service or file after a successful fetch (e.g., "+PONG" from Redis, "root:x:" from `/etc/passwd`), it strongly indicates successful SSRF. Severity is "High" for network services (Gopher, internal HTTP) and "Critical" for file access.
- **Injected Payload and Encoding:** The report shows the exact payload URL that triggered the finding and which encoding techniques were applied. This information is crucial for understanding how to exploit the vulnerability.

## Disclaimer

This tool is intended for **educational and ethical security testing purposes only**. Use it responsibly and only on systems you have explicit permission to test. The author is not responsible for any misuse or damage caused by this tool.

---
