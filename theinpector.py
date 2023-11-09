import requests
import re
import time
import logging
import socket
from urllib.parse import urlparse

# Constants
TIMEOUT = 20  # Increased timeout
MAX_RETRIES = 3  # Number of retries
RETRY_BACKOFF = 2  # Backoff multiplier for retries
MAX_REDIRECTS = 10  # Maximum number of redirects
USER_AGENT = "Mozilla/5.0 (compatible; RedirectChecker/1.0; +http://example.com/bot)"

# Enhanced logging configuration with timestamps
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s: %(message)s', datefmt='%Y-%m-%d %H:%M:%S')

def rainbow_progress(iterations, sleep_duration):
    colors = [Fore.RED, Fore.YELLOW, Fore.GREEN, Fore.CYAN, Fore.BLUE, Fore.MAGENTA]

    for i in tqdm(range(iterations), desc="Progress", ncols=80, bar_format="{desc}: {bar}"):
        print(colors[i % len(colors)], end="")
        sleep(sleep_duration)

def display_colored_art(art):
    init(autoreset=True)
    banner_lines = art.split("\n")
    colors = [Fore.RED, Fore.YELLOW, Fore.GREEN, Fore.CYAN, Fore.BLUE, Fore.MAGENTA]

    for line in banner_lines:
        color_line = ""
        for i, char in enumerate(line):
            color_line += colors[i % len(colors)] + char
        print(color_line)


# Replace 'your_ascii_art' with the actual ASCII art you want to display
your_ascii_art = """
                                                               
         ...                                   //*                                                                                                  
                                                                                                //  /****                                                                                               
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

created_by = "Created by ketchup"
version = "Version 1.0"


# Function to prepend http or https to the domain
def prepend_scheme(domain):
    schemes = ['http://', 'https://']
    for scheme in schemes:
        url = scheme + domain
        try:
            response = requests.head(url, timeout=TIMEOUT, allow_redirects=False, headers={'User-Agent': USER_AGENT})
            if response.status_code in (200, 301, 302, 303, 307, 308):
                return url
        except requests.exceptions.RequestException as e:
            logging.warning(f"Error with {url}: {e}")
    return None

# Function to process the response
def process_response(response, label):
    url = response.url
    status_code = response.status_code
    ip = retrieve_ip(urlparse(url).hostname)
    logging.info(f"\n{label}:\n - URL: {url}\n - Status code: {status_code}\n - IP address: {ip}\n")


# Function to retrieve IP address
def retrieve_ip(hostname):
    try:
        ip = socket.gethostbyname(hostname)
        return ip
    except socket.gaierror:
        return "IP address not found"

# Check server availability
def check_server_availability(ip, port, timeout=10):
    """Check the server availability by attempting to connect using a socket."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        result = sock.connect_ex((ip, port))
        if result == 0:
            logging.info(f"Server {ip} is responding on port {port}.")
            return True
        else:
            logging.warning(f"Server {ip} is not responding on port {port}.")
            return False
    except socket.error as err:
        logging.error(f"Socket error: {err}")
        return False
    finally:
        sock.close()

# Retry mechanism for HTTP requests
def make_request_with_retries(url, session):
    parsed_url = urlparse(url)
    port = 80 if parsed_url.scheme == "http" else 443
    for i in range(MAX_RETRIES):
        if not check_server_availability(parsed_url.hostname, port):
            logging.warning(f"The server at {parsed_url.netloc} may be down or experiencing issues.")
            time.sleep(RETRY_BACKOFF ** i)
            continue
        try:
            response = session.get(url, timeout=TIMEOUT, allow_redirects=True)
            response.raise_for_status()
            return response
        except requests.exceptions.RequestException as e:
            wait = RETRY_BACKOFF ** i
            logging.warning(f"Attempt {i+1}/{MAX_RETRIES} failed: {e}. Retrying in {wait} seconds...")
            time.sleep(wait)
    logging.error("Failed to connect to the domain after all retries. Please check the domain name and try again.")
    return None

# User input validation
def validate_domain(domain):
    pattern = r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,6}$"
    if re.match(pattern, domain):
        return True
    else:
        logging.error("Invalid domain format. Please enter a valid domain.")
        return False

# DNS resolution check
def check_dns_resolution(domain):
    try:
        ip = socket.gethostbyname(domain)
        logging.info(f"DNS resolution successful: {domain} resolved to {ip}")
        return True
    except socket.gaierror:
        logging.error(f"DNS resolution failed for domain: {domain}")
        return False

# Main function that gets redirects
def get_redirects(domain):
    url = prepend_scheme(domain)
    if not url:
        logging.error("Failed to access the domain with both HTTP and HTTPS.")
        return
    with requests.Session() as session:
        session.max_redirects = MAX_REDIRECTS
        session.headers.update({'User-Agent': USER_AGENT})
        response = make_request_with_retries(url, session)
        if response is None:
            return
        if not response.history:
            logging.info("No redirects occurred.")
        else:
            logging.info(f"Redirects for {domain}:")
        for redirect in response.history:
            process_response(redirect, "Redirect")
        process_response(response, "Final Destination")

# Main execution with input validation and DNS check
def main():
    display_colored_art(your_ascii_art)
    try:
        domain = input("Enter the domain: ")
        if validate_domain(domain) and check_dns_resolution(domain):
            print(f"Checking redirects for {domain}...\n")
            get_redirects(domain)
        else:
            print("Please check the domain name and try again.")
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
    finally:
        print("\nThanks and good luck on the hunt!")


if __name__ == "__main__":
    main()
