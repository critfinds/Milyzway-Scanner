# Milyzway-Scanner

A modular, asynchronous vulnerability scanner for web applications and smart contracts, now with enhanced detection capabilities and a more interactive CLI.

## Features

*   **Asynchronous Scanning:** High-throughput scanning with `aiohttp` and `aiolimiter`.
*   **Plugin Architecture:** Easily extend the scanner with new checks.
*   **Web Application Scanning:** Plugins for CORS, CSRF, RCE, and command injection.
*   **Smart Contract Scanning:** Scan smart contracts from local files or from a crypto address on the blockchain.
*   **Config-driven:** Configure the scanner with a YAML file.
*   **Easy Installation:** Install all the necessary tools and dependencies with a single script.

## Installation

1.  Clone the repository:

    ```
    git clone https://github.com/Milyzway/Milyzway-Scanner.git
    ```

2.  Run the installer script:

    ```
    cd Milyzway-Scanner
    ./install.sh
    ```

    Alternatively, you can install dependencies manually:

    ```bash
    pip install -r requirements.txt
    ```
    This will install `rich` and other necessary packages.

    **Note:** The `subdomain_takeover` plugin requires `subzy` to be installed. You can install it with the following command:

    ```bash
    go install -v github.com/PentestPad/subzy@latest
    ```

## Usage

1.  Activate the virtual environment:

    ```
    source venv/bin/activate
    ```

2.  Run the scanner:

    The scanner now automatically determines the scan type (web2 for web applications and web3 for smart contracts) based on the target. The CLI output has also been enhanced with progress bars and formatted tables for a better user experience.

    To scan a web application (crawling enabled by default):

    ```
    python3 -m scanner.app --target https://example.com
    ```

    To scan a web application without crawling:

    ```
    python3 -m scanner.app --target https://example.com --no-crawl
    ```

    To scan multiple targets from a file:

    ```
    python3 -m scanner.app --targets-file targets.txt
    ```

    To scan smart contracts:

    ```
    python3 -m scanner.app --targets-file targets_with_solidity.txt
    ```

    To save results in a different format (e.g., JSON):

    ```
    python3 -m scanner.app --target https://example.com --output-format json
    ```

    To perform an authenticated scan:

    ```
    python3 -m scanner.app --target https://example.com --login-url https://example.com/login --username user --password pass
    ```

    To use an OAST server for out-of-band detection:

    ```
    python3 -m scanner.app --target https://example.com --oast-server http://your-oast-server.com
    ```

## Configuration

The scanner is configured with the `config.yml` file. The following options are available:

*   `enabled_plugins`: A list of the plugins to run.
*   `concurrency`: The number of concurrent workers.
*   `rate_limit`: The number of requests per second.
*   `output_path`: The path to the output file.

## Plugins

The following plugins are available:

*   `cors`: Checks for CORS misconfigurations.
*   `csrf`: Checks for CSRF vulnerabilities.
*   `rce`: Checks for remote code execution vulnerabilities.
*   `command_injection`: Checks for command injection vulnerabilities.
*   `solidity_tools`: Scans Solidity smart contracts for vulnerabilities.
*   `sqli`: Detects SQL injection vulnerabilities (error-based, boolean-based, time-based, OAST-based).
*   `xss`: Detects Cross-Site Scripting (XSS) vulnerabilities (reflected and stored).
*   `xxe`: Detects XML External Entity (XXE) vulnerabilities (in-band and OAST-based).
*   `xpath`: Detects XPath Injection vulnerabilities (error-based, boolean-based).
*   `insecure_deserialization`: Detects Insecure Deserialization vulnerabilities.
*   `ssti`: Detects Server-Side Template Injection (SSTI) vulnerabilities.

## Creating a Plugin

Creating a new plugin is easy. Here are the basic steps:

1.  **Create a new file** in the `scanner/plugins` directory. The name of the file should be the name of your plugin (e.g., `my_plugin.py`).

2.  **Inherit from `BasePlugin`** and create a `Plugin` class:

    ```python
    from .base import BasePlugin

    class Plugin(BasePlugin):
        name = "my_plugin"

        async def run(self, target: str, requester, oast_server: str = None):
            # Your scanning logic here
            pass
    ```

3.  **Implement the `run` method.** This method should contain your scanning logic. It takes the `target` URL, the `requester` object (an instance of `AioRequester`), and the `oast_server` URL as input. The method should return a dictionary with your findings, or `None` if no vulnerabilities are found.

4.  **Enable your plugin** in the `config.yml` file by adding the name of your plugin to the `enabled_plugins` list.

## Bug Bounties

The Milyzway-Scanner can be a valuable tool for bug bounties. It can help you to find common vulnerabilities quickly and easily. However, it's important to remember that automated scanners are not a silver bullet. They can't find everything. You'll still need to do manual testing to find more complex vulnerabilities.

**Disclaimer:** This tool is for educational purposes and authorized security testing only. Do not use it to scan systems that you do not have permission to test.
