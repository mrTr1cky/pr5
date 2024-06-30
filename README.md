# CORS & XSS Vulnerability Scanner

![GitHub repo size](https://img.shields.io/github/repo-size/mrTr1cky/pr5)
![GitHub stars](https://img.shields.io/github/stars/mrTr1cky/pr5?style=social)
![GitHub forks](https://img.shields.io/github/forks/mrTr1cky/pr5?style=social)
![GitHub](https://img.shields.io/github/license/mrTr1cky/pr5)

This Python script scans domains for Cross-Origin Resource Sharing (CORS) vulnerabilities, Cross-Site Scripting (XSS) vulnerabilities, checks IP addresses, CNAME records, and determines if the domain is protected by Cloudflare.

## Features

- **CORS Vulnerability Check**: Tests domains for misconfigured CORS headers.
- **XSS Vulnerability Check**: Identifies XSS vulnerabilities using various payloads.
- **IP Address and CNAME Retrieval**: Retrieves IP address and CNAME records for each domain.
- **Cloudflare Protection Check**: Determines if the domain is protected by Cloudflare.

## Requirements

- Python 3.6+
- Required Python packages: `requests`, `colorama`, `dnspython`

## Installation

1. Clone the repository:

   ```bash
   git clone https://github.com/mrTr1cky/pr5.git
