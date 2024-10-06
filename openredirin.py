import requests

from urllib.parse import urljoin, urlparse, parse_qs

import colorama

import time

import argparse

from colorama import Fore, Style

from termcolor import colored



colorama.init(autoreset=True)



def print_banner():

    banner = f"""

{Fore.RED}
                )    (               )   (            (       (      (      (         )              
             ( /(    )\ )         ( /(   )\ )         )\ )    )\ )   )\ )   )\ )   ( /(              
             )\())  (()/(   (     )\()) (()/(   (    (()/(   (()/(  (()/(  (()/(   )\())             
 ___        ((_)\    /(_))  )\   ((_)\   /(_))  )\    /(_))   /(_))  /(_))  /(_)) ((_)\     __  ___  
|___| __      ((_)  (_))   ((_)   _((_) (_))   ((_)  (_))_   (_))   (_))   (_))    _((_)   / / |___| 
      \ \    / _ \  | _ \  | __| | \| | | _ \  | __|  |   \  |_ _|  | _ \  |_ _|  | \| |  / /        
       \ \  | (_) | |  _/  | _|  | .` | |   /  | _|   | |) |  | |   |   /   | |   | .` | /_/         
        \_\  \___/  |_|    |___| |_|\_| |_|_\  |___|  |___/  |___|  |_|_\  |___|  |_|\_|             



{Fore.GREEN}Open Redirect Vulnerability Scanner{Style.RESET_ALL}

"""

    print(banner)

    print(colored("by @esefkh740_ (instagram) @cyberhex.tech_", 'yellow'))



def detect_waf(url, timeout=5):

    headers = {

        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3'

    }

    try:

        response = requests.get(url, headers=headers, timeout=timeout)

        waf_signatures = [

            'X-Sucuri-ID', 'X-Sucuri-Cache', 'X-CDN-Geo', 'X-Cdn-Geo', 'X-Cache',

            'X-Frame-Options', 'X-XSS-Protection', 'X-Content-Type-Options',

            'X-Cache-Status', 'CF-Ray', 'Server: cloudflare', 'Server: AkamaiGHost'

        ]

        for header in waf_signatures:

            if header in response.headers:

                print(f"{Fore.YELLOW}[WAF Detected]{Style.RESET_ALL} WAF signature found: {header}")

                return True

        print(f"{Fore.GREEN}[No WAF Detected]{Style.RESET_ALL} No WAF signatures found.")

        return False

    except requests.RequestException as e:

        print(f"{Fore.RED}[Error]{Style.RESET_ALL} {e}")

        return False



def is_redirect_vulnerable(base_url, payload, timeout=5, retries=3, delay=2, verbose=False):

    full_url = urljoin(base_url, payload)

    headers = {

        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3'

    }

    attempt = 0

    while attempt < retries:

        try:

            response = requests.get(full_url, headers=headers, allow_redirects=False, timeout=timeout)

            if response.status_code in [301, 302, 303, 307, 308] and 'Location' in response.headers:

                location = response.headers['Location']

                if location.startswith(payload) or payload in location:

                    print(f"{Fore.RED}[Vulnerable]{Style.RESET_ALL} {full_url}")

                    print(f"{Fore.RED}Full URL: {full_url} - Vulnerable{Style.RESET_ALL}")

                    return True

            print(f"{Fore.GREEN}Full URL: {full_url} - Not Vulnerable{Style.RESET_ALL}")

            break

        except requests.RequestException as e:

            if verbose:

                print(f"{Fore.RED}[Error]{Style.RESET_ALL} {e}")

            time.sleep(delay)

            attempt += 1

    else:

        print(f"{Fore.RED}Full URL: {full_url} - Error after {retries} attempts{Style.RESET_ALL}")

    return False



def detect_parameters(url):

    parsed_url = urlparse(url)

    query_params = parse_qs(parsed_url.query)

    return list(query_params.keys())



def scan_for_open_redirects(base_url, payload_file, output_file, delay, retries, timeout, verbose):

    try:

        with open(payload_file, 'r') as file:

            payloads = [line.strip() for line in file]

    except FileNotFoundError:

        print(f"{Fore.RED}[Error]{Style.RESET_ALL} Payload file not found.")

        return



    parameters = detect_parameters(base_url)

    if parameters:

        print(f"{Fore.CYAN}[Info]{Style.RESET_ALL} Detected parameters: {', '.join(parameters)}")

    else:

        print(f"{Fore.YELLOW}[Warning]{Style.RESET_ALL} No parameters detected in the URL.")



    with open(output_file, 'w') as results:

        results.write(f"Scanning results for {base_url}\n\n")

        print(f"Scanning {base_url} for open redirects...\n")

        

        if parameters:

            for param in parameters:

                for payload in payloads:

                    test_url = f"{base_url}&{param}={payload}" if '?' in base_url else f"{base_url}?{param}={payload}"

                    if is_redirect_vulnerable(test_url, payload, timeout, retries, delay, verbose):

                        results.write(f"[Vulnerable] Parameter: {param}, Payload: {payload}\n")

                    else:

                        results.write(f"[Not Vulnerable] Parameter: {param}, Payload: {payload}\n")

                    time.sleep(delay)

        else:

            for payload in payloads:

                if is_redirect_vulnerable(base_url, payload, timeout, retries, delay, verbose):

                    results.write(f"[Vulnerable] {payload}\n")

                else:

                    results.write(f"[Not Vulnerable] {payload}\n")

                time.sleep(delay)



    print(f"Results saved to {output_file}")



if __name__ == "__main__":

    print_banner()

    

    parser = argparse.ArgumentParser(description='Open Redirect Vulnerability Scanner')

    parser.add_argument('url', help='The URL to scan for open redirects')

    parser.add_argument('payload_file', help='The file containing payloads')

    parser.add_argument('--output', default='results.txt', help='The file to save results')

    parser.add_argument('--delay', type=int, default=2, help='Delay between requests in seconds')

    parser.add_argument('--retries', type=int, default=3, help='Number of retries for failed requests')

    parser.add_argument('--timeout', type=int, default=5, help='Request timeout in seconds')

    parser.add_argument('--verbose', action='store_true', help='Enable verbose output')



    args = parser.parse_args()

    

    if detect_waf(args.url):

        print(f"{Fore.YELLOW}WAF detected. Proceeding with caution...{Style.RESET_ALL}")

    scan_for_open_redirects(args.url, args.payload_file, args.output, args.delay, args.retries, args.timeout, args.verbose)
