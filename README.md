<img src="https://github.com/Hackmain/Open-RedirIN/blob/main/open%20redirect%20scanner.png" alt="OPEN-REDIRIN">

## OPEN_REDIRIN

Open-RedirIN is an open-source tool designed to detect open redirect vulnerabilities in web applications. This tool is aimed at security researchers and developers to help identify and mitigate open redirect issues, ensuring the security and integrity of web applications.

## Features

- **Open Source**: Fully accessible and modifiable codebase.
- **Free to Use**: No cost for utilizing the tool.
- **WAF Detection**: Identifies the presence of Web Application Firewalls.
- **Retry Mechanism**: Retries failed requests to handle transient network issues.
- **Rate Limiting**: Introduces a delay between requests to avoid detection and bans.
- **Result Logging**: Saves scan results to a file for later analysis.
- **Verbose Mode**: Provides detailed logging if enabled.

## Installation

1. Clone this repository:
    ```bash
    git clone https://github.com/Hackmain/Open-RedirIN.git
    cd Open-RedirIN

    ```

2. Install dependencies:
    ```bash
    pip install -r requirements.txt

    ```

3. Install required dependencies:
    ```bash
    pip install -r requirements.txt
    ```

    **Requirements**:
    - `PYTHON3.x`
    - `BeautifulSoup4`
    - `argparse`
    - `termcolor`
    - `colorama`
    - `requests`

4. (Optional) You can use the shell file by doing :
    ```bash
    python -m venv venv
    source venv/bin/activate
    sudo chmod +x run.sh
    ./run.sh
    ```

## Usage

1. Prepare your payload file (e.g., `payloads.txt`).
2. Run the script:

```bash
python3 open_redir_in.py "<target_url>" "payloads.txt" --output "results.txt" --delay 2 --retries 3 --timeout 5 --verbose
 ```
**Example:**
```bash
python3 open_redir_in.py "https://www.example.com/redirect.php?action=url&goto=" "payloads.txt" --output "results.txt" --delay 2 --retries 3 --timeout 5 --verbose
 ```
## Command-Line Arguments
- url: The URL to scan for open redirects.
- payload_file: The file containing payloads.
- --output: The file to save results (default: results.txt).
- --delay: Delay between requests in seconds (default: 2).
- --retries: Number of retries for failed requests (default: 3).
- --timeout: Request timeout in seconds (default: 5).
- --verbose: Enable verbose output.

**Output:**
The tool will crawl the provided URL to gather links and check for parameters.
It will attempt to inject using payloads & URL parameters.
Vulnerable URLs will be marked as `- Vulnerable`, and non-vulnerable URLs will be marked as `- Not Vulnerable `.

**Example Output**

 ```bash 
[No WAF Detected] No WAF signatures found.
[Info] Detected parameters: action
Scanning https://www.playgosmart.cz/redirect.php?action=url&goto= for open redirects...

Full URL: https://www.playgosmart.cz/%09/google.com - Not Vulnerable
Full URL: https://www.playgosmart.cz/%2f%2fgoogle.com - Not Vulnerable
Full URL: https://www.playgosmart.cz/%2f%5c%2f%67%6f%6f%67%6c%65%2e%63%6f%6d/ - Not Vulnerable
 ```
<img src="https://github.com/Hackmain/Open-RedirIN/blob/main/openredirin.png" alt="OPEN-REDIRIN">

**Disclaimer**
This tool is intended for educational purposes only. Use it responsibly and only on targets you have permission to test.

Authors
@esefkh740_ on Instagram
Cyberhex.tech_


---

