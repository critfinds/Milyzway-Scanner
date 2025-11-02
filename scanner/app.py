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


async def scan_target(target: str, plugins: List, requester: AioRequester, oast_server: str = None):
    result = {"target": target, "vulnerabilities": []}
    for plugin in plugins:
        try:
            res = await plugin.run(target, requester, oast_server)
            if res:
                result["vulnerabilities"].append({
                    "plugin": getattr(plugin, "name", repr(plugin)),
                    "target": target,
                    "result": res,
                })
        except Exception:
            LOG.exception("Plugin %s failed on target %s", getattr(plugin, "name", plugin), target)
    return result


async def main_async(args: argparse.Namespace):
    cfg = load_config(args.config)

    # config may be a dict
    http_cfg = cfg.get("http", {}) if isinstance(cfg, dict) else {}
    timeout = http_cfg.get("timeout") if isinstance(http_cfg, dict) else None
    proxies = http_cfg.get("proxies") if isinstance(http_cfg, dict) else None

    requester = AioRequester(timeout=timeout, proxies=proxies, username=args.username, password=args.password, login_url=args.login_url)

    console = Console()

    if args.login_url:
        login_success = await requester.login()
        if not login_success:
            console.print("[bold red]Login failed. Exiting.[/bold red]")
            await requester.close()
            return

    targets = []
    if args.target:
        targets.append(args.target)
    elif args.targets_file:
        targets_config = Path(args.targets_file)
        LOG.info("Starting scan targets from %s", targets_config)
        with targets_config.open() as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                if Path(line).is_file():
                    targets.append(f"file://{Path(line).resolve()}")
                elif not line.startswith(("http://", "https://")):
                    line = "http://" + line
                    targets.append(line)
                else:
                    targets.append(line)
    else:
        LOG.error("No --target or --targets-file provided. Nothing to do.")
        return

    # Determine scan type and enabled plugins based on the first target
    determined_scan_type = None
    if targets:
        first_target = targets[0]
        if first_target.startswith(("http://", "https://")):
            determined_scan_type = "web2"
        elif first_target.startswith(("file://", "0x")):
            determined_scan_type = "web3"

    enabled_plugins = cfg.get("enabled_plugins") if isinstance(cfg, dict) else None
    if determined_scan_type == "web2":
        enabled_plugins = ["cors", "csrf", "rce", "command_injection", "ssrf", "oauth", "sqli", "xss", "xxe", "xpath", "insecure_deserialization", "ssti"]
    elif determined_scan_type == "web3":
        enabled_plugins = ["solidity", "solidity_tools"]

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

    concurrency = cfg.get("concurrency", 5) if isinstance(cfg, dict) else 5
    semaphore = asyncio.Semaphore(concurrency)

    async def sem_scan(target):
        async with semaphore:
            return await scan_target(target, plugins, requester, args.oast_server)

    tasks = [sem_scan(target) for target in targets]
    with Progress() as progress:
        task = progress.add_task("[cyan]Scanning...", total=len(tasks))
        all_results = []
        for coro in asyncio.as_completed(tasks):
            result = await coro
            all_results.append(result)
            progress.update(task, advance=1)

    table = Table(title="Scan Results")
    table.add_column("Target", justify="right", style="cyan", no_wrap=True)
    table.add_column("Plugin", style="magenta")
    table.add_column("Result", justify="right", style="green")

    found_vulnerabilities = False
    for res in all_results:
        if res["vulnerabilities"]:
            found_vulnerabilities = True
            for vuln in res["vulnerabilities"]:
                table.add_row(vuln["target"], vuln["plugin"], str(vuln["result"]))

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


def main():
    """Entrypoint to run the scanner"""
    parser = argparse.ArgumentParser(description="Milyzway Vulnerability Scanner")
    parser.add_argument("--config", default="config.yml", help="Path to the configuration file")
    parser.add_argument("--target", help="Single target URL to scan")
    parser.add_argument("--targets-file", help="File containing a list of target URLs")
    parser.add_argument("--no-crawl", action="store_true", help="Disable crawling and only scan the target URL")
    parser.add_argument("--output-format", choices=["json", "csv", "html"], default="table", help="Output format for the scan results")
    parser.add_argument("--oast-server", help="URL of the OAST server for out-of-band detection")
    parser.add_argument("--username", help="Username for authentication")
    parser.add_argument("--password", help="Password for authentication")
    parser.add_argument("--login-url", help="URL of the login page")
    args = parser.parse_args()

    try:
        asyncio.run(main_async(args))
    except KeyboardInterrupt:
        LOG.info("Scanner stopped by user.")
    except Exception as e:
        LOG.error(f"An unexpected error occurred: {e}", exc_info=True)


if __name__ == "__main__":
    main()