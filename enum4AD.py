import socket
from concurrent.futures import ThreadPoolExecutor
import nmap
import sys
import subprocess
from ldap3 import Server, Connection, ALL, ANONYMOUS, SIMPLE

def check_nmap_installed():
    try:
        subprocess.run(["nmap", "--version"], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return True
    except (FileNotFoundError, subprocess.CalledProcessError):
        return False

def python_port_scan(subnet="192.168.1", ports=[389, 636, 3268, 3269], timeout=2):
    detected_hosts = set()

    def scan_ip(port, ip):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                s.connect((ip, port))
                return (ip, port)
        except:
            return None

    with ThreadPoolExecutor(max_workers=100) as executor:
        futures = [executor.submit(scan_ip, port, f"{subnet}.{i}") for i in range(1, 255) for port in ports]
        for future in futures:
            result = future.result()
            if result:
                detected_hosts.add(result[0])
                print(f"[Python Scan] Found open port {result[1]} on {result[0]}")
    return list(detected_hosts)

def nmap_ad_scan(network="192.168.1.0/24"):
    try:
        scanner = nmap.PortScanner()
    except nmap.PortScannerError:
        print("Error: nmap module not properly installed")
        return []
    print("\n[Starting Nmap Scan]")
    scanner.scan(hosts=network, arguments='-n -T4 -p 389,636,3268,3269 --script ldap-rootdse')
    ad_hosts = []
    for host in scanner.all_hosts():
        if 'tcp' in scanner[host]:
            for port in scanner[host]['tcp']:
                if 'script' in scanner[host]['tcp'][port] and 'ldap-rootdse' in scanner[host]['tcp'][port]['script']:
                    ad_hosts.append(host)
                    print(f"[Nmap Scan] Confirmed AD controller: {host}")
    return ad_hosts

def get_ad_details(host):
    """
    Connect to the LDAP server on the given host, perform a search against the root DSE,
    and extract the default naming context (AD domain) and the ldapServiceName (from which the
    domain controller name is derived).
    """
    server = Server(host, get_info=ALL)
    try:
        # Attempt anonymous binding first.
        conn = Connection(server, user=None, password=None, authentication=ANONYMOUS, receive_timeout=10)
        if not conn.bind():
            print(f"Anonymous binding failed for {host}. Trying authenticated binding.")
            conn = Connection(server, user='your_username', password='your_password', authentication=SIMPLE, receive_timeout=10)
            if not conn.bind():
                print(f"Authenticated binding failed for {host}.")
                return None

        # Search the root DSE for AD details.
        conn.search(search_base='', search_filter='(objectClass=*)', search_scope='BASE', attributes=['defaultNamingContext', 'ldapServiceName'])
        if conn.entries:
            entry = conn.entries[0]
            # Extract the default naming context (the AD domain)
            domain_name = entry.defaultNamingContext.value if 'defaultNamingContext' in entry else "Unknown"
            # Extract the LDAP service name; AD usually returns something like 'dc01.example.com:389'
            ldap_service = entry.ldapServiceName.value if 'ldapServiceName' in entry else None
            dc_name = ldap_service.split(':')[0] if ldap_service else "Unknown"
        else:
            domain_name = "Unknown"
            dc_name = "Unknown"

        description = server.info.description if hasattr(server.info, 'description') else "No Description"
        conn.unbind()
        return {"domain": domain_name, "dc_name": dc_name, "description": description}
    except Exception as e:
        print(f"Failed to get AD details for {host}: {e}")
    return None

def cross_verify_results(python_hosts, nmap_hosts):
    return list(set(python_hosts) & set(nmap_hosts))

def generate_html_report(report_data, python_scan, nmap_scan, verified_hosts, network):
    """Generate a styled HTML report with the scan results."""
    html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>Active Directory Detection Report</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            margin: 20px;
            background-color: #f9f9f9;
        }}
        h1, h2 {{
            color: #333;
        }}
        table {{
            border-collapse: collapse;
            width: 100%;
        }}
        th, td {{
            border: 1px solid #ccc;
            padding: 8px;
            text-align: left;
        }}
        th {{
            background-color: #f2f2f2;
        }}
        .summary {{
            margin-bottom: 20px;
        }}
        .failed {{
            color: red;
        }}
    </style>
</head>
<body>
    <h1>Active Directory Detection Report</h1>
    <div class="summary">
        <h2>Scan Summary</h2>
        <p><strong>Network:</strong> {network}</p>
        <p><strong>Python Scan detected:</strong> {len(python_scan)} potential hosts</p>
        <p><strong>Nmap Scan confirmed:</strong> {len(nmap_scan)} AD controllers</p>
        <p><strong>Cross-verified AD controllers:</strong> {", ".join(verified_hosts)}</p>
    </div>
    <h2>AD Controller Details</h2>
    <table>
        <tr>
            <th>IP Address</th>
            <th>Domain</th>
            <th>DC Name</th>
            <th>Description</th>
        </tr>
    """
    for detail in report_data:
        html += f"""        <tr>
            <td>{detail.get('ip', 'Unknown')}</td>
            <td>{detail.get('domain', 'Unknown')}</td>
            <td>{detail.get('dc_name', 'Unknown')}</td>
            <td>{detail.get('description', 'Unknown')}</td>
        </tr>
"""
    html += """    </table>
</body>
</html>
"""
    return html

if __name__ == "__main__":
    if not check_nmap_installed():
        print("Warning: nmap not found. Nmap scans will be skipped")

    network = sys.argv[1] if len(sys.argv) > 1 else "192.168.1.0/24"
    subnet = ".".join(network.split('.')[:3])

    print(f"[*] Starting AD Detection on {network}")
    py_hosts = python_port_scan(subnet=subnet)
    print(f"\nPython Scan Results: {py_hosts}")

    nmap_hosts = nmap_ad_scan(network) if check_nmap_installed() else []
    print(f"\nNmap Scan Results: {nmap_hosts}")

    verified_hosts = cross_verify_results(py_hosts, nmap_hosts) if nmap_hosts else py_hosts
    print("\n[Final Results]")
    print(f"Python detected {len(py_hosts)} potential hosts")
    if nmap_hosts:
        print(f"Nmap confirmed {len(nmap_hosts)} AD controllers")
    print(f"Cross-verified AD controllers: {verified_hosts}")

    report_data = []
    for host in verified_hosts:
        details = get_ad_details(host)
        if details:
            details['ip'] = host
            report_data.append(details)
            print(f"\nAD Controller: {host}")
            print(f"Domain: {details['domain']}")
            print(f"DC Name: {details['dc_name']}")
            print(f"Description: {details['description']}")
        else:
            print(f"\nFailed to get details for {host}")

    # Generate HTML report and store it
    html_report = generate_html_report(report_data, py_hosts, nmap_hosts, verified_hosts, network)
    report_filename = "ad_report.html"
    try:
        with open(report_filename, "w", encoding="utf-8") as f:
            f.write(html_report)
        print(f"\n[Report Generated] The detailed report has been saved as '{report_filename}'.")
    except Exception as e:
        print(f"\nFailed to write report to file: {e}")
