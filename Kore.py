#!/usr/bin/env python3
"""
Kore - Interactive CLI Menu Version
Threat Intelligence Correlation Engine

Inspired by BLACKGLASS v11.0-APEX menu style.
"""

import asyncio
import argparse
import logging
import sys
import re
import csv
import json
import ipaddress
import yaml
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Dict, Set, Any, Optional, Tuple
from dataclasses import dataclass, field
from collections import defaultdict

import aiohttp
import requests
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.panel import Panel
from rich.text import Text
from rich import print as rprint

# Setup logging (quiet by default in interactive mode)
logging.basicConfig(level=logging.WARNING)
logger = logging.getLogger('kore')

# ========================== Data Classes ==========================
# (Same as original Kore)
@dataclass
class Indicator:
    value: str
    type: str
    source: str
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    tags: List[str] = field(default_factory=list)
    confidence: str = 'unknown'

@dataclass
class LogEvent:
    raw: str
    timestamp: Optional[datetime]
    source: str
    indicators: Dict[str, Set[str]] = field(default_factory=lambda: defaultdict(set))

@dataclass
class Match:
    indicator: Indicator
    event: LogEvent
    matched_value: str
    matched_type: str

# ========================== Feed Fetchers ==========================
class FeedFetcher:
    def __init__(self, name: str, config: dict):
        self.name = name
        self.config = config
        self.indicators: List[Indicator] = []

    async def fetch(self, session: aiohttp.ClientSession) -> List[Indicator]:
        raise NotImplementedError

class DShieldFeed(FeedFetcher):
    async def fetch(self, session: aiohttp.ClientSession) -> List[Indicator]:
        url = "https://feeds.dshield.org/block.txt"
        try:
            async with session.get(url, timeout=10) as resp:
                if resp.status != 200:
                    logger.error(f"DShield feed returned {resp.status}")
                    return []
                text = await resp.text()
                indicators = []
                for line in text.splitlines():
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    parts = line.split()
                    if len(parts) >= 1:
                        ip = parts[0]
                        try:
                            ipaddress.ip_address(ip)
                        except ValueError:
                            continue
                        indicators.append(Indicator(
                            value=ip,
                            type='ip',
                            source=self.name,
                            tags=['attacker'],
                            confidence='medium'
                        ))
                return indicators
        except Exception as e:
            logger.error(f"DShield fetch error: {e}")
            return []

class BlocklistDeFeed(FeedFetcher):
    async def fetch(self, session: aiohttp.ClientSession) -> List[Indicator]:
        url = "https://lists.blocklist.de/lists/all.txt"
        try:
            async with session.get(url, timeout=10) as resp:
                if resp.status != 200:
                    logger.error(f"blocklist.de feed returned {resp.status}")
                    return []
                text = await resp.text()
                indicators = []
                for line in text.splitlines():
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    try:
                        ipaddress.ip_address(line)
                        indicators.append(Indicator(
                            value=line,
                            type='ip',
                            source=self.name,
                            tags=['malicious'],
                            confidence='medium'
                        ))
                    except ValueError:
                        continue
                return indicators
        except Exception as e:
            logger.error(f"blocklist.de fetch error: {e}")
            return []

class ThreatFoxFeed(FeedFetcher):
    async def fetch(self, session: aiohttp.ClientSession) -> List[Indicator]:
        api_key = self.config.get('api_key')
        if not api_key:
            logger.warning("ThreatFox API key not provided, skipping")
            return []
        url = "https://threatfox-api.abuse.ch/api/v1/"
        payload = {
            "query": "get_recent",
            "days": self.config.get('days', 1)
        }
        headers = {"Auth-Key": api_key}
        try:
            async with session.post(url, json=payload, headers=headers, timeout=15) as resp:
                if resp.status != 200:
                    logger.error(f"ThreatFox returned {resp.status}")
                    return []
                data = await resp.json()
                if data.get('query_status') != 'ok':
                    logger.error(f"ThreatFox error: {data.get('query_status')}")
                    return []
                indicators = []
                for item in data.get('data', []):
                    ioc_value = item.get('ioc')
                    ioc_type = item.get('ioc_type', '').lower()
                    if ioc_type == 'ip:port':
                        ioc_type = 'ip'
                        if ':' in ioc_value:
                            ioc_value = ioc_value.split(':', 1)[0]
                    elif ioc_type == 'domain':
                        ioc_type = 'domain'
                    elif ioc_type == 'url':
                        ioc_type = 'url'
                    elif ioc_type == 'md5_hash':
                        ioc_type = 'hash'
                    else:
                        continue
                    try:
                        if ioc_type == 'ip':
                            ipaddress.ip_address(ioc_value)
                    except ValueError:
                        continue
                    indicators.append(Indicator(
                        value=ioc_value,
                        type=ioc_type,
                        source=self.name,
                        tags=item.get('tags', []),
                        confidence='high'
                    ))
                return indicators
        except Exception as e:
            logger.error(f"ThreatFox fetch error: {e}")
            return []

# ========================== Log Parsers ==========================
class LogParser:
    def __init__(self, config: dict):
        self.config = config

    def parse_file(self, path: Path) -> List[LogEvent]:
        events = []
        try:
            with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    event = self.parse_line(line.rstrip('\n'), path)
                    if event:
                        events.append(event)
        except Exception as e:
            logger.error(f"Error parsing {path}: {e}")
        return events

    def parse_line(self, line: str, source: Path) -> Optional[LogEvent]:
        raise NotImplementedError

class ApacheLogParser(LogParser):
    def parse_line(self, line: str, source: Path) -> Optional[LogEvent]:
        ip_match = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', line)
        ips = set()
        if ip_match:
            ips.add(ip_match.group())
        domains = set(re.findall(r'\b([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\b', line))
        urls = set(re.findall(r'https?://[^\s"<>]+', line))
        if not (ips or domains or urls):
            return None
        timestamp = None
        ts_match = re.search(r'\[(\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2})', line)
        if ts_match:
            try:
                timestamp = datetime.strptime(ts_match.group(1), '%d/%b/%Y:%H:%M:%S')
            except ValueError:
                pass
        event = LogEvent(raw=line, timestamp=timestamp, source=str(source))
        event.indicators['ip'].update(ips)
        event.indicators['domain'].update(domains)
        event.indicators['url'].update(urls)
        return event

class JsonLogParser(LogParser):
    def parse_line(self, line: str, source: Path) -> Optional[LogEvent]:
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            return None
        event = LogEvent(raw=line, timestamp=None, source=str(source))
        ts = data.get('timestamp') or data.get('@timestamp') or data.get('time')
        if ts:
            try:
                if isinstance(ts, str):
                    if 'T' in ts:
                        event.timestamp = datetime.fromisoformat(ts.replace('Z', '+00:00'))
                    else:
                        event.timestamp = datetime.strptime(ts, '%Y-%m-%d %H:%M:%S')
            except:
                pass
        self._extract_from_dict(data, event.indicators)
        if any(event.indicators.values()):
            return event
        return None

    def _extract_from_dict(self, obj, indicators: Dict[str, Set[str]], path: str = ''):
        if isinstance(obj, dict):
            for k, v in obj.items():
                new_path = f"{path}.{k}" if path else k
                self._extract_from_dict(v, indicators, new_path)
        elif isinstance(obj, list):
            for i, item in enumerate(obj):
                self._extract_from_dict(item, indicators, f"{path}[{i}]")
        elif isinstance(obj, str):
            try:
                ipaddress.ip_address(obj)
                indicators['ip'].add(obj)
            except ValueError:
                pass
            if re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', obj):
                indicators['domain'].add(obj)
            if obj.startswith(('http://', 'https://')):
                indicators['url'].add(obj)
            if re.match(r'^[a-fA-F0-9]{32}$', obj):
                indicators['hash'].add(obj)
            elif re.match(r'^[a-fA-F0-9]{40}$', obj):
                indicators['hash'].add(obj)
            elif re.match(r'^[a-fA-F0-9]{64}$', obj):
                indicators['hash'].add(obj)

class CsvLogParser(LogParser):
    def __init__(self, config: dict):
        super().__init__(config)
        self.delimiter = config.get('delimiter', ',')
        self.columns = config.get('columns', {})

    def parse_file(self, path: Path) -> List[LogEvent]:
        events = []
        try:
            with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                reader = csv.DictReader(f, delimiter=self.delimiter)
                for row in reader:
                    event = self._row_to_event(row, path)
                    if event:
                        events.append(event)
        except Exception as e:
            logger.error(f"Error parsing CSV {path}: {e}")
        return events

    def _row_to_event(self, row: dict, source: Path) -> Optional[LogEvent]:
        event = LogEvent(raw=str(row), timestamp=None, source=str(source))
        ts_col = self.columns.get('timestamp')
        if ts_col and ts_col in row:
            try:
                ts_str = row[ts_col]
                if 'T' in ts_str:
                    event.timestamp = datetime.fromisoformat(ts_str.replace('Z', '+00:00'))
                else:
                    event.timestamp = datetime.strptime(ts_str, '%Y-%m-%d %H:%M:%S')
            except:
                pass
        for ioc_type, col_name in self.columns.items():
            if ioc_type in ('ip', 'domain', 'hash', 'url') and col_name in row:
                value = row[col_name].strip()
                if value:
                    if ioc_type == 'ip':
                        try:
                            ipaddress.ip_address(value)
                            event.indicators[ioc_type].add(value)
                        except ValueError:
                            pass
                    elif ioc_type == 'domain':
                        if re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', value):
                            event.indicators[ioc_type].add(value)
                    elif ioc_type == 'url' and value.startswith(('http://', 'https://')):
                        event.indicators[ioc_type].add(value)
                    elif ioc_type == 'hash' and re.match(r'^[a-fA-F0-9]{32,64}$', value):
                        event.indicators[ioc_type].add(value)
        if any(event.indicators.values()):
            return event
        return None

# ========================== Correlator ==========================
class Correlator:
    def __init__(self, indicators: List[Indicator]):
        self.indicators_by_type: Dict[str, Dict[str, Indicator]] = defaultdict(dict)
        for ind in indicators:
            self.indicators_by_type[ind.type][ind.value] = ind

    def correlate(self, events: List[LogEvent]) -> List[Match]:
        matches = []
        for event in events:
            for ioc_type, values in event.indicators.items():
                lookup = self.indicators_by_type.get(ioc_type, {})
                for val in values:
                    if val in lookup:
                        matches.append(Match(
                            indicator=lookup[val],
                            event=event,
                            matched_value=val,
                            matched_type=ioc_type
                        ))
        return matches

# ========================== Reporter ==========================
class Reporter:
    def __init__(self, matches: List[Match]):
        self.matches = matches

    def console_report(self):
        console = Console()
        if not self.matches:
            console.print("[green]No matches found.[/green]")
            return
        table = Table(title="Correlation Matches")
        table.add_column("Indicator", style="cyan")
        table.add_column("Type", style="magenta")
        table.add_column("Source Feed", style="yellow")
        table.add_column("Matched In", style="green")
        table.add_column("Timestamp", style="blue")
        table.add_column("Confidence", style="red")
        for match in sorted(self.matches, key=lambda m: m.event.timestamp or datetime.min):
            ts = match.event.timestamp.strftime('%Y-%m-%d %H:%M:%S') if match.event.timestamp else 'N/A'
            table.add_row(
                match.indicator.value,
                match.indicator.type,
                match.indicator.source,
                match.event.source,
                ts,
                match.indicator.confidence
            )
        console.print(table)
        console.print(f"\n[bold]Total Matches: {len(self.matches)}[/bold]")

    def csv_report(self, output_file: str):
        with open(output_file, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['indicator', 'type', 'source_feed', 'log_file', 'timestamp', 'confidence', 'raw_log'])
            for match in self.matches:
                ts = match.event.timestamp.isoformat() if match.event.timestamp else ''
                writer.writerow([
                    match.indicator.value,
                    match.indicator.type,
                    match.indicator.source,
                    match.event.source,
                    ts,
                    match.indicator.confidence,
                    match.event.raw
                ])
        print(f"CSV report written to {output_file}")

    def json_report(self, output_file: str):
        output = []
        for match in self.matches:
            output.append({
                'indicator': {
                    'value': match.indicator.value,
                    'type': match.indicator.type,
                    'source': match.indicator.source,
                    'confidence': match.indicator.confidence,
                    'tags': match.indicator.tags
                },
                'event': {
                    'source': match.event.source,
                    'timestamp': match.event.timestamp.isoformat() if match.event.timestamp else None,
                    'raw': match.event.raw
                },
                'matched_value': match.matched_value
            })
        with open(output_file, 'w') as f:
            json.dump(output, f, indent=2)
        print(f"JSON report written to {output_file}")

# ========================== Kore Engine ==========================
class KoreEngine:
    def __init__(self, config_file: str):
        self.config = self._load_config(config_file)
        self.feeds = self._init_feeds()
        self.parsers = self._init_parsers()
        self.indicators = []
        self.events = []
        self.matches = []

    def _load_config(self, config_file: str) -> dict:
        with open(config_file, 'r') as f:
            return yaml.safe_load(f)

    def _init_feeds(self) -> List[FeedFetcher]:
        feed_configs = self.config.get('feeds', {})
        feeds = []
        feed_classes = {
            'dshield': DShieldFeed,
            'blocklist_de': BlocklistDeFeed,
            'threatfox': ThreatFoxFeed,
        }
        for name, cfg in feed_configs.items():
            if cfg.get('enabled', True):
                cls = feed_classes.get(name)
                if cls:
                    feeds.append(cls(name, cfg))
        return feeds

    def _init_parsers(self) -> Dict[str, LogParser]:
        parser_configs = self.config.get('logs', {}).get('parsers', {})
        parsers = {}
        parser_classes = {
            'apache': ApacheLogParser,
            'json': JsonLogParser,
            'csv': CsvLogParser,
        }
        for name, cfg in parser_configs.items():
            cls = parser_classes.get(name)
            if cls:
                parsers[name] = cls(cfg)
        return parsers

    async def _fetch_all_indicators(self):
        all_indicators = []
        async with aiohttp.ClientSession() as session:
            tasks = [feed.fetch(session) for feed in self.feeds]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for result in results:
                if isinstance(result, Exception):
                    logger.error(f"Feed fetch failed: {result}")
                elif isinstance(result, list):
                    all_indicators.extend(result)
        seen = set()
        unique = []
        for ind in all_indicators:
            key = (ind.type, ind.value)
            if key not in seen:
                seen.add(key)
                unique.append(ind)
        self.indicators = unique
        return unique

    def _parse_logs(self):
        log_paths = []
        base_path = Path(self.config.get('logs', {}).get('directory', '.'))
        patterns = self.config.get('logs', {}).get('include_patterns', ['*.log'])
        for pattern in patterns:
            log_paths.extend(base_path.glob(pattern))
        all_events = []
        parser_name = self.config.get('logs', {}).get('parser', 'apache')
        parser = self.parsers.get(parser_name)
        if not parser:
            print(f"Parser '{parser_name}' not configured")
            return []
        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), transient=True) as progress:
            task = progress.add_task("Parsing logs...", total=len(log_paths))
            for path in log_paths:
                if path.is_file():
                    events = parser.parse_file(path)
                    all_events.extend(events)
                progress.advance(task)
        self.events = all_events
        return all_events

    def correlate(self):
        if not self.indicators or not self.events:
            print("No data to correlate. Fetch feeds and parse logs first.")
            return []
        correlator = Correlator(self.indicators)
        self.matches = correlator.correlate(self.events)
        return self.matches

    def run_fetch(self):
        print("Fetching threat intelligence feeds...")
        indicators = asyncio.run(self._fetch_all_indicators())
        print(f"Fetched {len(indicators)} unique indicators.")
        return indicators

    def run_parse(self):
        print("Parsing log files...")
        events = self._parse_logs()
        print(f"Parsed {len(events)} log events.")
        return events

# ========================== Menu Interface ==========================
console = Console()

def print_banner():
    banner = r"""
[bold red]
╦╔═╦ ╦╔═╗╔╦╗
╠╩╗║ ║╚═╗ ║ 
╩ ╩╚═╝╚═╝ ╩ 
[/bold red][bold green]Threat Intelligence Correlation Engine[/bold green]
[bold yellow]v1.0 - Menu Edition[/bold yellow]
"""
    console.print(banner)
    console.print("[cyan]Inspired by BLACKGLASS v11.0-APEX[/cyan]\n")

def print_menu():
    menu_text = """
[bold cyan]MAIN MENU[/bold cyan]

[01] Fetch Threat Feeds
[02] Parse Log Files
[03] Correlate All Evidence
[04] View Matches (Console)
[05] Export Matches to CSV
[06] Export Matches to JSON
[07] View Statistics
[08] Change Config File
[09] Reload Configuration
[10] Exit

[bold yellow]Enter your choice (1-10): [/bold yellow]"""
    console.print(menu_text, end="")

def show_stats(engine):
    console.print("\n[bold]=== STATISTICS ===[/bold]")
    console.print(f"Feeds configured: {len(engine.feeds)}")
    console.print(f"Indicators fetched: {len(engine.indicators)}")
    console.print(f"Log events parsed: {len(engine.events)}")
    console.print(f"Matches found: {len(engine.matches)}")
    input("\nPress Enter to continue...")

def main_menu():
    print_banner()
    config_file = "config.yaml"
    engine = KoreEngine(config_file)
    while True:
        print_menu()
        choice = input().strip()
        if choice == '1':
            engine.run_fetch()
            input("\nPress Enter to continue...")
        elif choice == '2':
            engine.run_parse()
            input("\nPress Enter to continue...")
        elif choice == '3':
            matches = engine.correlate()
            print(f"Correlation complete. Found {len(matches)} matches.")
            input("\nPress Enter to continue...")
        elif choice == '4':
            if not engine.matches:
                print("No matches to display. Run correlation first.")
            else:
                reporter = Reporter(engine.matches)
                reporter.console_report()
            input("\nPress Enter to continue...")
        elif choice == '5':
            if not engine.matches:
                print("No matches to export. Run correlation first.")
            else:
                filename = input("Enter CSV filename (default: report.csv): ").strip()
                if not filename:
                    filename = "report.csv"
                reporter = Reporter(engine.matches)
                reporter.csv_report(filename)
            input("\nPress Enter to continue...")
        elif choice == '6':
            if not engine.matches:
                print("No matches to export. Run correlation first.")
            else:
                filename = input("Enter JSON filename (default: report.json): ").strip()
                if not filename:
                    filename = "report.json"
                reporter = Reporter(engine.matches)
                reporter.json_report(filename)
            input("\nPress Enter to continue...")
        elif choice == '7':
            show_stats(engine)
        elif choice == '8':
            new_config = input("Enter new config file path: ").strip()
            if Path(new_config).exists():
                config_file = new_config
                engine = KoreEngine(config_file)
                print(f"Configuration changed to {config_file}")
            else:
                print("File not found.")
            input("\nPress Enter to continue...")
        elif choice == '9':
            engine = KoreEngine(config_file)
            print("Configuration reloaded.")
            input("\nPress Enter to continue...")
        elif choice == '10':
            console.print("[bold red]Exiting Kore. Goodbye![/bold red]")
            break
        else:
            console.print("[bold red]Invalid choice. Please enter a number 1-10.[/bold red]")
            input("Press Enter to continue...")

if __name__ == "__main__":
    main_menu()