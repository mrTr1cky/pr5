CORS & XSS Vulnerability Scanner




This Python script scans domains for Cross-Origin Resource Sharing (CORS) vulnerabilities, Cross-Site Scripting (XSS) vulnerabilities, checks IP addresses, CNAME records, and determines if the domain is protected by Cloudflare.

Features
CORS Vulnerability Check: Tests domains for misconfigured CORS headers.
XSS Vulnerability Check: Identifies XSS vulnerabilities using various payloads.
IP Address and CNAME Retrieval: Retrieves IP address and CNAME records for each domain.
Cloudflare Protection Check: Determines if the domain is protected by Cloudflare.
Requirements
Python 3.6+
Required Python packages: requests, colorama, dnspython
Installation
Clone the repository:

bash
Copy code
git clone https://github.com/mrTr1cky/pr5.git
Install dependencies:

bash
Copy code
pip install -r requirements.txt
Usage
Prepare a text file (domains.txt) containing one domain per line.

Run the script:

bash
Copy code
python masscors.py
Follow the on-screen instructions to input the path to your domains file.

Results will be saved to scan_results_<date>.txt.

Example Output
Sample output will be stored in scan_results_<date>.txt.
Contributing
Contributions are welcome! Please fork the repository and create a pull request.

License
This project is licensed under the MIT License. See the LICENSE file for details.

Author
