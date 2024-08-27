Information Gathering - Python PenTest Commands gather information before the script

Python-PenTest-Script:  
The provided Python script is a Pentester Automation Tool designed to assist in various penetration testing tasks. It automates different reconnaissance, scanning, and vulnerability assessment processes. Here are some key functionalities:
Reconnaissance: Gathers information about DNS, WHOIS, emails, social media presence, and files related to a target domain.
Internal Scanning: Scans for live hosts and open ports within a specified IP address range or list.
Web Scanning: Analyzes web security aspects such as Web Application Firewalls (WAF), SSL/TLS security, load balancers, and web vulnerabilities.
Vulnerability Assessment: Executes vulnerability scans against identified live hosts and open ports.
Brute-Forcing: Attempts to brute-force services on open ports to check for weak or default credentials.
Reporting: Saves the output of each test to appropriately named files in organized directories based on the target domain and test type.
The tool uses command-line arguments to specify the target domain, IP addresses, and desired tests, and it is built with extensibility and automation in mind for penetration testing activities.

Red-PenTest-And-Report:    Updates to the Script

generate_report() Function: This function creates an HTML report summarizing the results of each phase of the penetration test. The report includes the date and time, details of each test phase, and outputs formatted for readability.

JSON Results Files: Each phase of the penetration test saves its output to a separate JSON file. This approach makes it easy to parse and include in the final report.

HTML Formatting: The report is structured using HTML, with basic styling for readability. The use of <pre> tags ensures that the JSON data is displayed in a readable format.

Improved Error Handling and Output Management: Each function checks for successful execution and captures both stdout and stderr to provide detailed output in the report.

How to Use:    
Run the Script: Execute the script in a Python environment where you have the necessary permissions and tools installed (theHarvester, nmap, msfconsole, etc.).

View the Report: After the script completes, open the generated penetration_test_report.html file in any web browser to view the comprehensive report.

Important Considerations
Permissions and Legal Compliance: Ensure you have explicit authorization from the target organization to perform penetration testing. Unauthorized use is illegal.

Environment Setup: Make sure that all required tools (theHarvester, nmap, msfconsole, etc.) are installed and properly configured on the system running the script.

Customization: Modify the script to suit the specific requirements of your penetration test, including different tools, payloads, and target specifications.

Disclaimer:
This script is intended for ethical hacking and penetration testing purposes in environments where you have explicit permission to test. Unauthorized testing is illegal and unethical. Use responsibly and comply with all applicable laws and regulations.
