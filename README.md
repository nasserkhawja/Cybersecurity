Information Gathering - Python PenTest Commands gather information before the script


The provided Python script is a Pentester Automation Tool designed to assist in various penetration testing tasks. It automates different reconnaissance, scanning, and vulnerability assessment processes. Here are some key functionalities:

Reconnaissance: Gathers information about DNS, WHOIS, emails, social media presence, and files related to a target domain.
Internal Scanning: Scans for live hosts and open ports within a specified IP address range or list.
Web Scanning: Analyzes web security aspects such as Web Application Firewalls (WAF), SSL/TLS security, load balancers, and web vulnerabilities.
Vulnerability Assessment: Executes vulnerability scans against identified live hosts and open ports.
Brute-Forcing: Attempts to brute-force services on open ports to check for weak or default credentials.
Reporting: Saves the output of each test to appropriately named files in organized directories based on the target domain and test type.
The tool uses command-line arguments to specify the target domain, IP addresses, and desired tests, and it is built with extensibility and automation in mind for penetration testing activities.
