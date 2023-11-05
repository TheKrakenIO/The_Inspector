import requests
import socket
import logging
from urllib.parse import urlparse

# Constants
TIMEOUT = 10
MAX_REDIRECTS = 10  #you can change this
USER_AGENT = "Mozilla/5.0 (compatible; RedirectChecker/1.0; +http://example.com/bot)"

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')

def get_redirects(domain):
    url = prepend_scheme(domain)
    if not url:
        logging.error("Failed to access the domain with both http and https.")
        return

    try:
        with requests.Session() as session:
            session.max_redirects = MAX_REDIRECTS
            session.headers.update({'User-Agent': USER_AGENT})
            response = session.get(url, timeout=TIMEOUT, allow_redirects=True)

            if not response.history:
                logging.info("No redirects occurred.")

            for redirect in response.history:
                process_response(redirect, "Redirect")

            process_response(response, "Final destination")
            response.raise_for_status()

    except requests.exceptions.HTTPError as e:
        logging.error("HTTP error: %s", e)
        if response.status_code == 404:
            logging.error("404 Not Found: The requested resource at %s does not exist.", response.url)
    except requests.exceptions.ConnectionError as e:
        logging.error("Error connecting to the server: %s", e)
    except requests.exceptions.Timeout as e:
        logging.error("Timeout error: %s", e)
    except requests.exceptions.TooManyRedirects as e:
        logging.error("Too many redirects: %s", e)
    except requests.exceptions.RequestException as e:
        logging.error("Error during request: %s", e)

def prepend_scheme(domain):
    for scheme in ('http://', 'https://'):
        url = scheme + domain
        try:
            response = requests.head(url, timeout=TIMEOUT, allow_redirects=False, headers={'User-Agent': USER_AGENT})
            if response.status_code in (301, 302, 303, 307, 308):
                url = response.headers.get('Location', url)
            response.raise_for_status()
            return url
        except requests.exceptions.RequestException as e:
            logging.warning("Error with %s: %s", url, e)
            continue
    return None

def process_response(response, label):
    url = response.url
    status_code = response.status_code
    parsed_url = urlparse(url)
    ip = retrieve_ip(parsed_url.hostname)

    logging.info("-" * 40)
    logging.info("%s: %s", label, url)
    logging.info("Status code: %d", status_code)
    logging.info("IP address: %s", ip)

    # Check for a file download attempt in the response headers
    content_disposition = response.headers.get('Content-Disposition', '')
    if 'attachment' in content_disposition:
        logging.warning("Warning: The URL at %s might be trying to initiate a file download.", url)
        # Optionally, you can extract the filename from the header
        filename = content_disposition.partition('filename=')[-1].strip()
        if filename:
            logging.warning("Filename suggested by the server: %s", filename)
    
    logging.info("-" * 40 + "\n")

def retrieve_ip(hostname):
    try:
        return socket.gethostbyname(hostname)
    except socket.gaierror:
        return "IP address not found"

# Main execution
if __name__ == "__main__":
    domain = input("Enter the domain: ")
    get_redirects(domain)
