"""scanner.app - entrypoint for the Milyzway scanner

Minimal CLI wrapper that loads config, plugins and runs scans
asynchronously. Designed to be run as a package module:

    python -m scanner.app --targets-file examples/targets.txt
"""

import asyncio
import argparse
from pathlib import Path
from typing import List

from rich.console import Console
from rich.table import Table
from rich.progress import Progress

from scanner.logger import get_logger
from scanner.config import load_config
from scanner.plugins import load_plugins
from scanner.utils.http import AioRequester
from scanner.utils.reporter import write_json, write_csv, write_html
from scanner.utils.crawler import Crawler

LOG = get_logger("vuln-scanner")


import re

URL_REGEX = re.compile(
    r'^(?:http|ftp)s?://'  # http:// or https://
    r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|'  # domain...
    r'localhost|'  # localhost...
    r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'  # ...or ip
    r'(?::\d+)?'  # optional port
    r'(?:/?|[/?]\S+)$', re.IGNORECASE)

def is_valid_url(url):
    return re.match(URL_REGEX, url) is not None


async def scan_target(target: str, plugins: List, requester: AioRequester, oast_server: str = None, plugin_timeout: int = 120):
    """Scan a target with all enabled plugins.

    Args:
        target: URL or target to scan
        plugins: List of plugin instances to run
        requester: HTTP requester instance
        oast_server: Optional OAST server URL
        plugin_timeout: Timeout in seconds for each plugin execution (default: 120s)
    """
    result = {"target": target, "vulnerabilities": []}
    for plugin in plugins:
        plugin_name = getattr(plugin, "name", repr(plugin))
        try:
            # Wrap plugin execution with timeout
            findings = await asyncio.wait_for(
                plugin.run(target, requester, oast_server),
                timeout=plugin_timeout
            )
            if findings:
                for finding in findings:
                    processed_finding = {}
                    if isinstance(finding, dict):
                        processed_finding = finding
                    elif isinstance(finding, str):
                        # If finding is a string (e.g., an error message from a plugin),
                        # wrap it in a dictionary to prevent AttributeError
                        processed_finding = {"message": finding, "type": "plugin_error"}
                    else:
                        # Handle other unexpected types
                        processed_finding = {"message": str(finding), "type": "plugin_output"}

                    severity = processed_finding.pop("severity", "info")
                    confidence = processed_finding.pop("confidence", "tentative")
                    result["vulnerabilities"].append({
                        "plugin": plugin_name,
                        "target": target,
                        "severity": severity,
                        "confidence": confidence,
                        "result": processed_finding,  # The rest of the finding dict
                    })
        except asyncio.TimeoutError:
            LOG.warning("Plugin %s timed out after %ds on target %s", plugin_name, plugin_timeout, target)
        except Exception:
            LOG.exception("Plugin %s failed on target %s", plugin_name, target)
    return result


async def main_async(args: argparse.Namespace):
    cfg = load_config(args.config)

    # config may be a dict
    http_cfg = cfg.get("http", {}) if isinstance(cfg, dict) else {}
    timeout = http_cfg.get("timeout") if isinstance(http_cfg, dict) else None
    proxies = http_cfg.get("proxies") if isinstance(http_cfg, dict) else None
    max_field_size = http_cfg.get("max_field_size", 65536) if isinstance(http_cfg, dict) else 65536

    requester = AioRequester(timeout=timeout, proxies=proxies, username=args.username, password=args.password, login_url=args.login_url, max_field_size=max_field_size)

    console = Console()

    # Milyzway ASCII Art Banner
    milyzway_banner = r"""
  __  __ _ _                           
 |  \/  (_) |_  _ _____ __ ____ _ _  _ 
 | |\/| | | | || |_ /\ V  V / _` | || |
 |_|  |_|_|_|\_, /__| \_/\_/\__,_|\_, |
             |__/                 |__/                                                                                           
"""
    console.print(f"[bold yellow]{milyzway_banner}[/bold yellow]")

    if args.login_url:
        login_success = await requester.login()
        if not login_success:
            console.print("[bold red]Login failed. Exiting.[/bold red]")
            await requester.close()
            return

    targets = []
    if args.target:
        if is_valid_url(args.target):
            targets.append(args.target)
        elif not args.target.startswith(("http://", "https://")):
            # Try prepending http:// if it looks like a domain
            potential_url = "http://" + args.target
            if is_valid_url(potential_url):
                targets.append(potential_url)
            else:
                LOG.error(f"Invalid target: {args.target}. Must be a valid URL or domain.")
                return
        else:
            LOG.error(f"Invalid target: {args.target}. Must be a valid URL.")
            return
    elif args.targets_file:
        targets_config = Path(args.targets_file)
        LOG.info("Starting scan targets from %s", targets_config)
        with targets_config.open() as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue

                if not line.startswith(("http://", "https://")):
                    line = "http://" + line

                if is_valid_url(line):
                    targets.append(line)
                else:
                    LOG.error(f"Invalid URL in targets file: {line}")
    else:
        LOG.error("No --target or --targets-file provided. Nothing to do.")
        return

    if args.plugins:
        enabled_plugins = [p.strip() for p in args.plugins.split(',')]
    else:
        enabled_plugins = cfg.get("enabled_plugins") if isinstance(cfg, dict) else None

    plugins = load_plugins(enabled_plugins)

    if not args.no_crawl:
        console.print("Crawling for more targets...")
        crawled_targets = set()
        for target in targets:
            crawler = Crawler(requester)
            crawled_urls = await crawler.start(target)
            for url in crawled_urls:
                crawled_targets.add(url)
        targets = list(crawled_targets)

    concurrency = args.concurrency or (cfg.get("concurrency", 5) if isinstance(cfg, dict) else 5)
    semaphore = asyncio.Semaphore(concurrency)

    oast_server = args.oast_server or (cfg.get("oast_server") if isinstance(cfg, dict) else None)

    async def sem_scan(target):
        async with semaphore:
            return await scan_target(target, plugins, requester, oast_server)

    tasks = [sem_scan(target) for target in targets]
    with Progress() as progress:
        task = progress.add_task("[cyan]Scanning...", total=len(tasks))
        all_results = []
        for coro in asyncio.as_completed(tasks):
            result = await coro
            all_results.append(result)
            progress.update(task, advance=1)

    # Deduplicate vulnerabilities before reporting
    unique_signatures = set()
    deduplicated_results = []
    for res in all_results:
        unique_vulnerabilities = []
        for vuln in res.get("vulnerabilities", []):
            try:
                # Create a signature for the vulnerability
                target_domain = vuln['target'].split('//', 1)[-1].split('/', 1)[0]
                plugin_name = vuln['plugin']
                result_details = vuln.get('result', {})
                vuln_type = result_details.get('type') or result_details.get('param')
                
                signature = f"{target_domain}|{plugin_name}|{vuln_type}"
                
                if signature not in unique_signatures:
                    unique_signatures.add(signature)
                    unique_vulnerabilities.append(vuln)
            except (KeyError, IndexError):
                # If creating a signature fails, just keep the vuln
                unique_vulnerabilities.append(vuln)

        if unique_vulnerabilities:
            new_res = res.copy()
            new_res["vulnerabilities"] = unique_vulnerabilities
            deduplicated_results.append(new_res)
    
    all_results = deduplicated_results

    table = Table(title="Scan Results")
    table.add_column("Target", justify="right", style="cyan", no_wrap=True)
    table.add_column("Plugin", style="magenta")
    table.add_column("Severity", style="yellow")
    table.add_column("Confidence", style="blue")
    table.add_column("Result", justify="right", style="green")

    found_vulnerabilities = False
    for res in all_results:
        if res["vulnerabilities"]:
            found_vulnerabilities = True
            for vuln in res["vulnerabilities"]:
                table.add_row(
                    vuln["target"],
                    vuln["plugin"],
                    vuln.get("severity", "info"),
                    vuln.get("confidence", "tentative"),
                    str(vuln["result"])
                )

    if found_vulnerabilities:
        console.print(table)
    else:
        console.print("No vulnerabilities found.")

    # Write all results once
    output_path = cfg.get("output_path", "scan_results") if isinstance(cfg, dict) else "scan_results"
    if args.output_format == "json":
        write_json(f"{output_path}.json", all_results)
    elif args.output_format == "csv":
        write_csv(f"{output_path}.csv", all_results)
    elif args.output_format == "html":
        write_html(f"{output_path}.html", all_results)
    elif args.output_format == "table":
        # The table is already printed to the console
        pass

    LOG.info(f"Scan completed. Results saved to {output_path}.{args.output_format}")

    # Close the requester session
    await requester.close()


import os

def main():
    """Entrypoint to run the scanner"""
    parser = argparse.ArgumentParser(description="Milyzway Vulnerability Scanner")
    parser.add_argument("--config", default="config.yml", help="Path to the configuration file")
    parser.add_argument("--target", help="Single target URL to scan")
    parser.add_argument("--targets-file", help="File containing a list of target URLs")
    parser.add_argument("--no-crawl", action="store_true", help="Disable crawling and only scan the target URL")
    parser.add_argument("--output-format", choices=["json", "csv", "html"], default="table", help="Output format for the scan results")
    parser.add_argument("--oast-server", default=os.environ.get("OAST_SERVER"), help="URL of the OAST server for out-of-band detection")
    parser.add_argument("--username", help="Username for authentication")
    parser.add_argument("--password", help="Password for authentication")
    parser.add_argument("--login-url", help="URL of the login page")
    parser.add_argument("--concurrency", type=int, help="Number of concurrent workers")
    parser.add_argument("--plugins", help="Comma-separated list of plugins to run")
    args = parser.parse_args()

    try:
        asyncio.run(main_async(args))
    except KeyboardInterrupt:
        LOG.info("Scanner stopped by user.")
    except Exception as e:
        LOG.error(f"An unexpected error occurred: {e}", exc_info=True)


if __name__ == "__main__":
    main()