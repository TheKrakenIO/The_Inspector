import argparse
import csv
import datetime
import json
import logging
import re
import socket
import ssl
import subprocess
import sys
import time
from urllib.parse import urlparse

import dns.resolver
import requests
import networkx as nx
import matplotlib.pyplot as plt
from colorama import Fore, init

try:
    from tqdm import tqdm
    HAS_TQDM = True
except ImportError:
    HAS_TQDM = False
    def tqdm(iterable, *args, **kwargs): return iterable

try:
    from bs4 import BeautifulSoup
    HAS_BS4 = True
except ImportError:
    HAS_BS4 = False

try:
    from graphviz import Digraph
    HAS_GRAPHVIZ = True
except ImportError:
    HAS_GRAPHVIZ = False

init(autoreset=True)

TIMEOUT = 20
MAX_RETRIES = 3
RETRY_BACKOFF = 2
MAX_REDIRECTS = 10
DEFAULT_USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/78.0.3904.108 Safari/537.36 "

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

ASCII_ART = """

...                                   //*                                                                                                  
                                                                                                //  /               ****                                                                                               
                                                                                             /     //*******                                                                                            
                                                                                          ///       /////////**                                                                                         
                                                                                          //        /////////**/,,                                                                                      
                                                                                         /    .     //////***//,,,,**                                                                                   
                                                                                    /  /     /      ///*****///,,,**                                                                                    
                                                                                        /   /       /,,,,,,,///,****                                                                                    
                                                                           ,/,/          //.   /    /////*,,,/,***/       //**                                                                          
                                                                            /  ,      /             /*////////////       ***/////                                                                       
                                                                          //  /                     /**///,,,**///      //** /******                                                                    
                                                                     */       /  ,/                 /**,,,,,****/     ,*//,     ///****                                                                 
                                                                 /    .         /  /    /     /   . /**,,,,*****/    ***/          ///////                                                              
                                                            *      /   //    ,/    /      /    /  * /*,,,,****//    ,****//     *    ///////,                                                           
                                                                /    /         /*        /  .   /   /*,,****///          ***********    ,*******                                                        
                                                             /          /                 , /    * //,,***///**                 *          ,,,,,,,,                                                     
                                                   .     / *                               .   /    /,**/*****                                *,,,,,//                                                  
                                                              /                           /     /.///*******///                           .********                                                     
                                                         / /     /                      /     /     /******,,,,,//                     ,,,,,,*/*                                                        
                                                                / ./ ,             /   /    /       /********,,,**////              /*,,*////                                                           
                                                                / /     /        /                  /*********,,***///*,,       //////,,,/                                                              
                                                                            / /          //         ///////////* ***/**,,,**.*///////,,                                                                 
                                                                     /   /  /     . /  / ./         /////////**/,,  **,,,,///***///,                                                                    
                                                              //* .    ./       ,/   /   /          //////***//,,,,*   ,/////////     ,,,,,                                                             
                                                            /  /     /    * / /    /   /     //   / ///**** ///,,,***,     //*     //////****,                                                          
                                                        /     /       * /        // /   / / /      //,,,,,,,/ /,*****/*.        **/////   ***,,,*                                                       
                                                         , /        / /   ,/   /       //  /  ,    ,//////,,,/   *//*////    /*****/*      **,,,                                                        
                                                           /  /.      //    /    /,      / /      /   /////////    ***//****/////*    // /***                                                           
                                                                              /    /           //       //,,,////    **////**/**      **///                                                             
                                                                           //         //     ./           ,,/////*      ////**                                                                          
                                                                             /*      / //   /               /////***      /*                                                                            
                                                                                        / /                   ///,,,,                                                                                   
                                                                                  /     /     / / /   ,,//      ******                                                                                  
                                                                                  /  //       /  /     ////       **////                                                                                
                                                                               .     *     //  ,/        *****///////////                                                                               
                                                                                        //                //////                                                                                        
                                                                                                                                                                                                        
                                                                                                                                                                                                        
                                                                                                                                                                                                        
                                                                                                                                                                                                        
                                            ,,,     ,,,,   ,,,,,,,,,,,        ,,,,,      ,,,      ,,,,  ,,,,,,,,,,,,  ,,,,,      ,,,      ,,,    .,,,,,,,,,,                                            
                                            ,,,  ,,,,      ,,,      ,,,      ,,, ,,,     ,,,   ,,,,     ,,,           ,,,,,,,    ,,,      ,,,   ,,,       ,,,                                           
                                            *******        ************    ****   ***    ********       ***********   ***  ****  ***      ***   ***       ***                                           
                                            ///   ////     ///      ///   /////////////  ///    ////    ///*********  ///    ///////      ///   /////////////                                    
                                   ..    .  


"""

CREATED_BY = "Created by KrakenIO"
VERSION = "Version 2.0"

def display_colored_art(art, show_art=True, scale=1):
    if not show_art:
        return
    banner_lines = art.split("\n")
    colors = [Fore.RED, Fore.YELLOW, Fore.GREEN, Fore.CYAN, Fore.BLUE, Fore.MAGENTA]
    for line in banner_lines:
        if not line.strip():
            print()
            continue
        scaled_line = "".join(char * scale for char in line)
        color_line = "".join(colors[i % len(colors)] + char for i, char in enumerate(scaled_line))
        for _ in range(scale):
            print(color_line)

def rainbow_progress(iterations, sleep_duration):
    for _ in tqdm(range(iterations), desc="Initializing", ncols=80, disable=not HAS_TQDM):
        time.sleep(sleep_duration)

def check_whois_command():
    try:
        subprocess.run(['whois', '--version'], capture_output=True, check=True)
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        logging.error("The 'whois' command is not installed.")
        return False

def whois_lookup(identifier):
    try:
        result = subprocess.run(['whois', identifier], capture_output=True, text=True, timeout=30, check=True)
        output = result.stdout
        formatted = []
        for line in output.splitlines():
            line = line.strip()
            if line and not line.startswith(('%', '#')):
                if any(key in line.lower() for key in ['netname', 'country', 'orgname', 'created', 'changed']):
                    formatted.append(line)
        return '\n'.join(formatted) or "No relevant WHOIS data found"
    except subprocess.TimeoutExpired:
        return "WHOIS lookup timed out"
    except subprocess.CalledProcessError as e:
        return f"WHOIS lookup failed: {e.stderr}"
    except FileNotFoundError:
        return "WHOIS command not found"

def prepend_scheme(domain):
    schemes = ['https://', 'http://', 'https://www.', 'http://www.']
    for scheme in schemes:
        url = scheme + domain
        try:
            response = requests.head(url, timeout=TIMEOUT, allow_redirects=False, headers={'User-Agent': USER_AGENT})
            if response.status_code in (200, 301, 302, 303, 307, 308):
                return url
        except requests.exceptions.RequestException:
            pass
    for scheme in schemes:
        url = scheme + domain
        try:
            response = requests.get(url, timeout=TIMEOUT, allow_redirects=False, headers={'User-Agent': USER_AGENT})
            if response.status_code in (200, 301, 302, 303, 307, 308):
                return url
        except requests.exceptions.RequestException as e:
            logging.debug(f"Fallback GET failed for {url}: {e}")
    return None

def retrieve_ip(hostname):
    try:
        return socket.gethostbyname(hostname)
    except socket.gaierror:
        return "IP address not found"

def reverse_dns_lookup(ip_address):
    try:
        return socket.gethostbyaddr(ip_address)[0]
    except socket.herror:
        return "Reverse DNS lookup failed"

def get_ssl_certificate(hostname, port=443):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=TIMEOUT) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                return {
                    'issuer': dict(x[0] for x in cert.get('issuer', [])),
                    'subject': dict(x[0] for x in cert.get('subject', [])),
                    'notBefore': cert.get('notBefore'),
                    'notAfter': cert.get('notAfter')
                }
    except Exception as e:
        return f"SSL certificate retrieval failed: {e}"

def get_dns_records(domain):
    records = {'MX': [], 'TXT': [], 'CNAME': []}
    for record_type in records:
        try:
            answers = dns.resolver.resolve(domain, record_type, raise_on_no_answer=False)
            records[record_type] = [str(r) for r in answers]
        except Exception as e:
            records[record_type] = [f"DNS {record_type} query failed: {e}"]
    return records

def check_server_availability(ip, port, timeout=10):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        return sock.connect_ex((ip, port)) == 0
    finally:
        sock.close()

def make_request_with_retries(url, session):
    parsed_url = urlparse(url)
    port = 443 if parsed_url.scheme == "https" else 80
    ip = retrieve_ip(parsed_url.hostname)
    if ip == "IP address not found":
        logging.error(f"Could not resolve IP for {parsed_url.hostname}")
        return None

    for i in range(MAX_RETRIES):
        try:
            response = session.get(
                url,
                timeout=TIMEOUT,
                allow_redirects=True,
                headers={'User-Agent': USER_AGENT}
            )
            response.raise_for_status()
            return response
        except requests.exceptions.HTTPError as e:
            if response.status_code in (502, 503, 504):
                logging.warning(f"HTTP error {response.status_code} for {url}, retrying...")
                time.sleep(RETRY_BACKOFF ** i)
                continue
            logging.error(f"HTTP error for {url}: {e}")
            return None
        except requests.exceptions.RequestException as e:
            logging.warning(f"Request failed for {url}: {e}, retrying...")
            time.sleep(RETRY_BACKOFF ** i)
    logging.error(f"Failed to fetch {url} after {MAX_RETRIES} retries")
    return None

def validate_domain(domain):
    return bool(re.match(r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,6}$", domain))

def check_dns_resolution(domain):
    try:
        socket.gethostbyname(domain)
        return True
    except socket.gaierror:
        return False

def detect_javascript(response):
    try:
        content = response.text.lower()
        js_indicators = ['<script', '.js"', 'javascript:']
        findings = []
        if any(indicator in content for indicator in js_indicators):
            findings.append("JavaScript detected:")
            if '<script' in content:
                findings.append(" - Inline <script> tags found")
            if '.js"' in content:
                findings.append(" - References to .js files found")
            if 'javascript:' in content:
                findings.append(" - JavaScript URLs found")
        return '\n'.join(findings) or "No JavaScript detected"
    except Exception as e:
        return f"JavaScript detection failed: {e}"

def extract_links(response):
    if not HAS_BS4:
        return ["Link extraction skipped: beautifulsoup4 not installed"]
    try:
        soup = BeautifulSoup(response.text, 'html.parser')
        links = [a.get('href') for a in soup.find_all('a', href=True)]
        return links[:10] if links else ["No links found"]
    except Exception as e:
        return [f"Link extraction failed: {e}"]

def format_headers(headers):
    key_headers = ['Server', 'Content-Type', 'Location', 'Strict-Transport-Security',
                   'X-Frame-Options', 'X-Content-Type-Options', 'Content-Security-Policy']
    return '\n'.join(f" - {k}: {v}" for k, v in headers.items() if k in key_headers) or "No key headers found"

def generate_graphviz_chart(results, domain):
    if not HAS_GRAPHVIZ:
        logging.error("Cannot generate Graphviz chart: graphviz library not installed.")
        return

    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"redirect_graphviz_{domain}_{timestamp}.png"
    
    dot = Digraph(comment='Redirect Chain', format='png')
    dot.attr(rankdir='LR')
    
    for i, r in enumerate(results):
        node_label = f"{r['url']}\nStatus: {r['status_code']}"
        dot.node(str(i), node_label, shape='box', style='filled', fillcolor='lightblue')
        if i > 0:
            prev = results[i-1]
            edge_label = f"{prev['status_code']} -> {r['headers'].get('Location', '')}"
            dot.edge(str(i-1), str(i), label=edge_label, color='blue')
    
    try:
        dot.render(filename, cleanup=True)
        logging.info(f"Graphviz chart saved as {filename}")
    except Exception as e:
        logging.error(f"Failed to generate Graphviz chart: {e}")

def generate_matplotlib_chart(results, domain):
    G = nx.DiGraph()
    for i, r in enumerate(results):
        node_label = f"{r['url']}\nStatus: {r['status_code']}"
        G.add_node(i, label=node_label)
        if i > 0:
            prev = results[i-1]
            edge_label = f"{prev['status_code']} -> {r['headers'].get('Location', '')}"
            G.add_edge(i-1, i, label=edge_label)

    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"redirect_matplotlib_{domain}_{timestamp}.png"
    
    try:
        pos = nx.spring_layout(G)
        plt.figure(figsize=(10, 6))
        nx.draw(G, pos, with_labels=False, node_color='lightblue', node_shape='s', node_size=2000, font_size=10, arrows=True)
        node_labels = nx.get_node_attributes(G, 'label')
        nx.draw_networkx_labels(G, pos, node_labels, font_size=8)
        edge_labels = nx.get_edge_attributes(G, 'label')
        nx.draw_networkx_edge_labels(G, pos, edge_labels, font_size=8)
        plt.title(f"Redirect Chain for {domain}")
        plt.savefig(filename, bbox_inches='tight')
        plt.close()
        logging.info(f"Matplotlib chart saved as {filename}")
    except Exception as e:
        logging.error(f"Failed to generate Matplotlib chart: {e}")

def process_response(response, label, redirect_count, results):
    url = response.url
    status_code = response.status_code
    hostname = urlparse(url).hostname
    ip = retrieve_ip(hostname)

    redirect_types = {301: "Permanent Redirect (301)", 302: "Temporary Redirect (302)",
                      303: "See Other (303)", 307: "Temporary Redirect (307)",
                      308: "Permanent Redirect (308)"}
    redirect_type = redirect_types.get(status_code, "Non-redirect response")

    whois_info = whois_lookup(ip) if ip != "IP address not found" else "No WHOIS data due to invalid IP"
    headers_info = format_headers(response.headers)
    ssl_info = get_ssl_certificate(hostname) if url.startswith('https') else "No SSL/TLS data (HTTP)"

    output = (
        f"\n{'='*50}\n"
        f"{label} #{redirect_count}:\n"
        f" - URL: {url}\n"
        f" - Status Code: {status_code}\n"
        f" - Redirect Type: {redirect_type}\n"
        f" - IP Address: {ip}\n"
        f" - HTTP Headers:\n{headers_info}\n"
        f" - SSL/TLS Info: {ssl_info if isinstance(ssl_info, str) else json.dumps(ssl_info, indent=2)}\n"
        f" - WHOIS Info:\n{whois_info}\n"
    )

    if label == "Final Destination":
        js_info = detect_javascript(response)
        links_info = extract_links(response)
        links_formatted = '\n'.join(f'   - {link}' for link in links_info)
        output += f" - JavaScript Analysis:\n{js_info}\n"
        output += f" - Extracted Links (Top 10):\n{links_formatted}\n"

    logging.info(output)

    results.append({
        'stage': f"{label} #{redirect_count}",
        'url': url,
        'status_code': status_code,
        'redirect_type': redirect_type,
        'ip_address': ip,
        'headers': dict(response.headers),
        'ssl_info': ssl_info,
        'whois_info': whois_info,
        'javascript': detect_javascript(response) if label == "Final Destination" else None,
        'links': links_info if label == "Final Destination" else None
    })

def export_results(results, domain, dns_records, output_format, output_file):
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = output_file or f"inspector_{domain}_{timestamp}.{output_format}"

    if output_format == 'json':
        data = {'domain': domain, 'redirects': results, 'dns_records': dns_records}
        with open(filename, 'w') as f:
            json.dump(data, f, indent=2)
    elif output_format == 'csv':
        with open(filename, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow([
                'Stage', 'URL', 'Status Code', 'Redirect Type', 'IP Address',
                'Headers', 'SSL Info', 'WHOIS Info', 'JavaScript', 'Links'
            ])
            for r in results:
                writer.writerow([
                    r['stage'], r['url'], r['status_code'], r['redirect_type'],
                    r['ip_address'], json.dumps(r['headers']),
                    json.dumps(r['ssl_info']), r['whois_info'],
                    r['javascript'], json.dumps(r['links'])
                ])
    elif output_format == 'txt':
        with open(filename, 'w') as f:
            for r in results:
                f.write(f"{'='*50}\n")
                f.write(f"{r['stage']}:\n")
                for key, value in r.items():
                    if value and key != 'stage':
                        f.write(f" - {key.replace('_', ' ').title()}: {value}\n")
            f.write(f"\nDNS Records:\n{json.dumps(dns_records, indent=2)}\n")
    logging.info(f"Results exported to {filename}")

def get_redirects(domain, user_agent):
    global USER_AGENT
    USER_AGENT = user_agent or DEFAULT_USER_AGENT

    url = prepend_scheme(domain)
    if not url:
        logging.error("Failed to access domain with HTTP or HTTPS. Try adding 'www.' or check domain configuration.")
        return []

    with requests.Session() as session:
        session.max_redirects = MAX_REDIRECTS
        try:
            response = make_request_with_retries(url, session)
            if response is None:
                logging.error("No response received from the domain")
                return []

            results = []
            redirect_count = len(response.history)
            if not response.history:
                logging.info("No redirects occurred")
            else:
                logging.info(f"Total Redirects: {redirect_count}")

            for i, redirect in enumerate(response.history, 1):
                process_response(redirect, "Redirect", i, results)
            process_response(response, "Final Destination", redirect_count + 1, results)
            return results
        except requests.exceptions.TooManyRedirects:
            logging.error("Too many redirects encountered")
            return []
        except Exception as e:
            logging.error(f"Unexpected error in get_redirects: {e}")
            return []

def prompt_for_args():
    args = {
        'show_art': True,
        'user_agent': None,
        'output_format': None,
        'output_file': None
    }
    
    print("\nSelect an option to configure (Enter to skip and start scan):")
    print("1. Disable ASCII art (--no-art)")
    print("2. Set custom User-Agent (--user-agent)")
    print("3. Set output format (--output-format json|csv|txt)")
    print("4. Set output file name (--output-file)")
    
    while True:
        try:
            choice = input("Enter option number (1-4) or press Enter: ").strip()
            if not choice:
                break
            choice = int(choice)
            if choice == 1:
                args['show_art'] = False
                print("ASCII art disabled.")
            elif choice == 2:
                args['user_agent'] = input("Enter User-Agent string: ").strip()
                print(f"User-Agent set to: {args['user_agent']}")
            elif choice == 3:
                fmt = input("Enter output format (json, csv, txt): ").strip().lower()
                if fmt in ['json', 'csv', 'txt']:
                    args['output_format'] = fmt
                    print(f"Output format set to: {fmt}")
                else:
                    print("Invalid format. Use json, csv, or txt.")
            elif choice == 4:
                args['output_file'] = input("Enter output file name: ").strip()
                print(f"Output file set to: {args['output_file']}")
            else:
                print("Invalid option. Choose 1-4 or Enter.")
        except ValueError:
            print("Enter a number (1-4) or press Enter.")
        except (EOFError, KeyboardInterrupt):
            print("\nSkipping configuration.")
            break
    
    return args

def main():
    parser = argparse.ArgumentParser(description="Check domain redirects, WHOIS, DNS, and more")
    parser.add_argument("domain", nargs="?", help="Domain to check (example.com)")
    parser.add_argument("--no-art", action="store_false", dest="show_art", help="Disable ASCII art")
    parser.add_argument("--user-agent", help="Custom User-Agent string")
    parser.add_argument("--output-format", choices=['json', 'csv', 'txt'], help="Export format")
    parser.add_argument("--output-file", help="Custom output file name")
    args = parser.parse_args()

    if not check_whois_command():
        sys.exit(1)

    display_colored_art(ASCII_ART, args.show_art, scale=2)
    print(CREATED_BY)
    print(VERSION)
    rainbow_progress(10, 0.1)

    domain = args.domain
    if not domain:
        while True:
            try:
                domain = input("Enter the domain: ").strip()
                if domain:
                    break
                logging.error("Domain cannot be empty.")
            except (EOFError, KeyboardInterrupt):
                logging.error("No domain provided.")
                sys.exit(1)

    if not validate_domain(domain) or not check_dns_resolution(domain):
        logging.error("Invalid domain or DNS resolution failed.")
        sys.exit(1)

    if not any([args.user_agent, args.output_format, args.output_file, not args.show_art]):
        interactive_args = prompt_for_args()
        args.show_art = interactive_args['show_art']
        args.user_agent = interactive_args['user_agent']
        args.output_format = interactive_args['output_format']
        args.output_file = interactive_args['output_file']

    logging.info(f"\nChecking redirects for {domain}...\n")
    results = get_redirects(domain, args.user_agent)

    domain_ip = retrieve_ip(domain)
    domain_whois_info = whois_lookup(domain_ip)
    domain_reverse_dns_info = reverse_dns_lookup(domain_ip)
    dns_records = get_dns_records(domain)

    summary = (
        f"\n{'='*50}\n"
        f"Summary for {domain}\n"
        f"{'='*50}\n"
        f" - IP Address: {domain_ip}\n"
        f" - Reverse DNS: {domain_reverse_dns_info}\n"
        f" - WHOIS Info:\n{domain_whois_info}\n"
        f" - DNS Records:\n"
        f"   - MX: {', '.join(dns_records['MX']) or 'None'}\n"
        f"   - TXT: {', '.join(dns_records['TXT']) or 'None'}\n"
        f"   - CNAME: {', '.join(dns_records['CNAME']) or 'None'}\n"
    )
    logging.info(summary)

    if args.output_format:
        export_results(results, domain, dns_records, args.output_format, args.output_file)

    if results:
        print("\nRedirect Chain Summary:")
        for r in results:
            location = r['headers'].get('Location', '') if 'headers' in r and isinstance(r['headers'], dict) else ''
            print(f" {r['status_code']} -> {r['url']} {'-> ' + location if location else ''}")
        final = results[-1]
        print(f"\nFinal Destination: {final['url']}")
        print(f" - IP Address: {final['ip_address']}")
        print(f" - MIME-Type: {final['headers'].get('Content-Type', 'Unknown')}")
        print(f" - Status: {final['status_code']}")
        print(f" - Type: Document")
        print(f" - Location: {final['headers'].get('Location', 'N/A')}")

        while True:
            try:
                print("\nGenerate a chart of the redirect chain?")
                print("1. Graphviz chart")
                print("2. Matplotlib flowchart")
                print("Press Enter to skip")
                choice = input("Enter option (1-2) or press Enter: ").strip()
                if not choice:
                    break
                choice = int(choice)
                if choice == 1:
                    if HAS_GRAPHVIZ:
                        generate_graphviz_chart(results, domain)
                    else:
                        logging.error("Graphviz not installed. Install with 'pip install graphviz' and Graphviz binary.")
                    break
                elif choice == 2:
                    generate_matplotlib_chart(results, domain)
                    break
                else:
                    print("Invalid option. Choose 1, 2, or Enter.")
            except ValueError:
                print("Enter a number (1-2) or press Enter.")
            except (EOFError, KeyboardInterrupt):
                print("Skipping chart generation.")
                break

    print("\nThanks and good luck on the hunt! ^_^")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nOperation cancelled by user")
        sys.exit(0)
    except Exception as e:
        logging.error(f"Unexpected error: {e}")
        sys.exit(1)
