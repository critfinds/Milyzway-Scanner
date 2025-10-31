# scanner/app.py for milyzway
import asyncio 
import argparse
from pathlib import Path
from scanner.logger import get_logger
from scanner.config import load_config
from scanner.plugins import load_plugins
from scanner.utils.http import AioRequester

LOG = get_logger ("vuln-scanner")

# Function to scan a single target with all plugins
async def scan_target(target, plugins, requester):
    result = {"target": target, "vulnerabilities": []}
    for plugin in plugins:
        try:
            res = await plugin.run(target, requester)
            if res:
                result["vulnerabilities"].append({
                    "plugin": plugin.name, 
                    "target": target, 
                    "result": res
                })
        except Exception as e:
            LOG.exception("Plugin %s failed on target %s", (plugin.name, target))
    return result

# Main function to run the scanner
async def main(args):
        config = load_config(args.config)
        requester = AioRequester(timeout = config.http.timeout, proxies = config.http.proxies)
        plugins = load_plugins(config.enabled_plugins)
        targets = []
        if args.target:
            targets.append(args.target)
        else:
            targets_config = Path(args.targets_file)
            LOG.info("Starting scan targets from %s", targets_config)
            with targets_config.open() as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("https://") and not line.startswith("http://"):
                        line = "http://" + line
                    targets.append(line)

        semaphore = asyncio.Semaphore(config.concurrency)
        async def sem_scan(target):
                async with semaphore:
                    return await scan_target(target, plugins, requester,)
                
        tasks = [sem_scan(target) for target in targets]
        results = await asyncio.gather(*tasks)
        for res in results:
             



            