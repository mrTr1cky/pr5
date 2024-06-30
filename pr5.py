import requests
from colorama import init, Fore, Style
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
import socket
import dns.resolver
from urllib.parse import urlparse

init(autoreset=True)

def print_banner():
    banner = """
    ██████╗ ██████╗ ███████╗    ███████╗ ██████╗ ██████╗ ███████╗
    ██╔══██╗██╔══██╗██╔════╝    ██╔════╝██╔═══██╗██╔══██╗██╔════╝
    ██████╔╝██████╔╝███████╗    █████╗  ██║   ██║██████╔╝███████╗
    ██╔═══╝ ██╔══██╗╚════██║    ██╔══╝  ██║   ██║██╔═══╝ ╚════██║
    ██║     ██║  ██║███████║    ██║     ╚██████╔╝██║     ███████║
    ╚═╝     ╚═╝  ╚═╝╚══════╝    ╚═╝      ╚═════╝ ╚═╝     ╚══════╝
                        CORS & XSS Vulnerability Scanner

                        Author: madtiger
                        Telegram: @devidluice
    """
    print(Fore.CYAN + banner + Style.RESET_ALL)

def normalize_url(url):
    parsed_url = urlparse(url)
    if not parsed_url.scheme:
        return f'http://{url}'
    return url

def check_cors_vulnerability(url):
    test_origins = [
        'http://evil.com',
        'https://0xmad.com',
        'null'
    ]

    headers = {
        'User-Agent': 'Mozilla/5.0',
        'Origin': None
    }

    results = []

    for origin in test_origins:
        headers['Origin'] = origin
        try:
            response = requests.options(url, headers=headers, timeout=5)
            if 'Access-Control-Allow-Origin' in response.headers:
                allowed_origin = response.headers['Access-Control-Allow-Origin']
                if allowed_origin == '*' or allowed_origin == origin:
                    result = (url, origin, 'CORS_VULNERABLE', allowed_origin,
                              'Access-Control-Allow-Credentials' in response.headers)
                    results.append(result)
                else:
                    results.append((url, origin, 'CORS_SAFE', allowed_origin, False))
            else:
                results.append((url, origin, 'CORS_NO_HEADER', None, False))
        except requests.RequestException:
            results.append((url, origin, 'CORS_ERROR', None, False))

    return results

def check_xss_vulnerability(url):
    xss_payloads = [
        '<script>alert(1)</script>',
        '"><script>alert(1)</script>',
        '\'"><script>alert(1)</script>'
    ]

    results = []

    for payload in xss_payloads:
        headers = {
            'User-Agent': payload
        }
        try:
            response = requests.get(url, headers=headers, timeout=5)
            if payload in response.text:
                result = (url, 'XSS_VULNERABLE', payload)
                results.append(result)
            else:
                result = (url, 'XSS_SAFE', payload)
                results.append(result)
        except requests.RequestException:
            results.append((url, 'XSS_ERROR', payload))

    return results

def get_ip_and_cname(url):
    domain = urlparse(url).netloc
    try:
        ip = socket.gethostbyname(domain)
    except socket.gaierror:
        ip = 'Unable to resolve'
    
    try:
        cname = dns.resolver.resolve(domain, 'CNAME')
        cname_record = [str(rdata.target) for rdata in cname]
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        cname_record = ['No CNAME record found']
    
    return ip, cname_record

def check_cloudflare_protection(url):
    domain = urlparse(url).netloc
    try:
        answers = dns.resolver.resolve(domain, 'A')
        for rdata in answers:
            if rdata.address.startswith(('104.', '172.', '185.')):
                return 'Protected by Cloudflare'
        return 'Not protected by Cloudflare'
    except dns.resolver.NoAnswer:
        return 'No A record found'
    except Exception:
        return 'Error checking Cloudflare protection'

def main(domains_file):
    date_str = datetime.now().strftime("%Y%m%d")
    output_file = f"scan_results_{date_str}.txt"
    
    try:
        with open(domains_file, 'r') as file:
            domains = [normalize_url(domain.strip()) for domain in file.readlines()]

        with ThreadPoolExecutor(max_workers=10) as executor:
            cors_futures = {executor.submit(check_cors_vulnerability, domain): domain for domain in domains}
            xss_futures = {executor.submit(check_xss_vulnerability, domain): domain for domain in domains}
            ip_cname_futures = {executor.submit(get_ip_and_cname, domain): domain for domain in domains}
            cloudflare_futures = {executor.submit(check_cloudflare_protection, domain): domain for domain in domains}

            with open(output_file, 'w') as output:
                for future in as_completed(cors_futures):
                    domain = cors_futures[future]
                    try:
                        result = future.result()
                        output.write(f'URL: {domain}\n')
                        for res in result:
                            if 'CORS' in res[2]:
                                if res[2] == 'CORS_VULNERABLE':
                                    url, origin, status, allowed_origin, credentials = res
                                    output.write(f'{url} is CORS vulnerable with origin: {origin}\n')
                                    output.write(f'Access-Control-Allow-Origin: {allowed_origin}\n')
                                    if credentials:
                                        output.write(f'Access-Control-Allow-Credentials is set, which can be risky.\n')
                            elif 'CORS' in res[2] and res[2] == 'CORS_SAFE':
                                output.write(f'This domain is not vulnerable: {domain}\n')
                    except:
                        output.write(f'Dead Domain: {domain}\n')

                for future in as_completed(xss_futures):
                    domain = xss_futures[future]
                    try:
                        result = future.result()
                        output.write(f'URL: {domain}\n')
                        for res in result:
                            if 'XSS' in res[1]:
                                if res[1] == 'XSS_VULNERABLE':
                                    url, status, payload = res
                                    output.write(f'{url} is XSS vulnerable with payload: {payload}\n')
                                elif res[1] == 'XSS_SAFE':
                                    output.write(f'This domain is not vulnerable: {domain}\n')
                    except:
                        output.write(f'Dead Domain: {domain}\n')

                for future in as_completed(ip_cname_futures):
                    domain = ip_cname_futures[future]
                    try:
                        ip, cname_record = future.result()
                        output.write(f'URL: {domain}\n')
                        output.write(f'IP address: {ip}\n')
                        output.write(f'CNAME record: {", ".join(cname_record)}\n')
                    except:
                        output.write(f'Dead Domain: {domain}\n')

                for future in as_completed(cloudflare_futures):
                    domain = cloudflare_futures[future]
                    try:
                        protection_status = future.result()
                        output.write(f'URL: {domain}\n')
                        output.write(f'Cloudflare protection status: {protection_status}\n')
                    except:
                        output.write(f'Dead Domain: {domain}\n')

    except FileNotFoundError:
        pass
    except:
        pass

if __name__ == "__main__":
    print_banner()
    domains_file = input("Enter target file : ").strip()
    main(domains_file)
