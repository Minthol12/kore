"""
Kore - Threat Intelligence Correlation Engine

A CLI tool that fetches IOCs from multiple threat feeds, parses log files,
and correlates them to identify potential security incidents.

Author: Phoenix/Minthol
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

# Setup Logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger('kore')

# ========================== Data Classes ==========================
@dataclass
class Indicator:
    """Represents a single indicator of compromise."""
    value: str
    type: str  # 'ip', 'domain', 'hash', 'url'
    source: str
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    tags: List[str] = field(default_factory=list)
    confidence: str = 'unknown'  # low, medium, high

@dataclass
class LogEvent:
    """Represents a parsed log entry with extracted indicators."""
    raw: str
    timestamp: Optional[datetime]
    source: str  # file path
    indicators: Dict[str, Set[str]] = field(default_factory=lambda: defaultdict(set))  # type -> set of values

@dataclass
class Match:
    """Represents a correlation match between an IOC and a log event."""
    indicator: Indicator
    event: LogEvent
    matched_value: str
    matched_type: str

# ========================== Feed Fetchers ==========================

class FeedFetcher:
    """Base class for fetching IOCs from a threat feed."""
    def __init__(self, name: str, config: dict):
        self.name = name
        self.config = config
        self.indicators: List[Indicator] = []

    async def fetch(self, session: aiohttp.ClientSession) -> List[Indicator]:
        """Fetch IOCs from the feed. To be overridden."""
        raise NotImplementedError

class DShieldFeed(FeedFetcher):
    """Fetches top attackers from DShield (https://feeds.dshield.org/block.txt)."""
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
                        # Validate IP
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
                logger.info(f"DShield: fetched {len(indicators)} IPs")
                return indicators
        except Exception as e:
            logger.error(f"DShield fetch error: {e}")
            return []

class BlocklistDeFeed(FeedFetcher):
    """Fetches IPs from blocklist.de (https://lists.blocklist.de/lists/all.txt)."""
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
                logger.info(f"blocklist.de: fetched {len(indicators)} IPs")
                return indicators
        except Exception as e:
            logger.error(f"blocklist.de fetch error: {e}")
            return []

class ThreatFoxFeed(FeedFetcher):
    """Fetches recent IOCs from ThreatFox (requires API key)."""
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
                        ioc_type = 'ip'  # We'll extract IP later if needed, but for now treat as ip
                        # Could split on colon to get IP
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
                        confidence='high'  # ThreatFox is reputable
                    ))
                logger.info(f"ThreatFox: fetched {len(indicators)} IOCs")
                return indicators
        except Exception as e:
            logger.error(f"ThreatFox fetch error: {e}")
            return []

# ========================== Log Parsers ==========================

class LogParser:
    """Base class for parsing log files."""
    def __init__(self, config: dict):
        self.config = config

    def parse_file(self, path: Path) -> List[LogEvent]:
        """Parse a single log file and return list of events."""
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
        """Parse a single log line. To be overridden."""
        raise NotImplementedError

class ApacheLogParser(LogParser):
    """Parser for Apache access logs (Common/Combined format)."""
    # Example: 192.168.1.1 - - [10/Mar/2025:12:00:00 +0000] "GET /index.html HTTP/1.1" 200 1234
    # Regex to extract IP and possibly domain from Host header if present
    # This is simplified; a full parser would be more complex.
    def parse_line(self, line: str, source: Path) -> Optional[LogEvent]:
        # Simple extraction: find first IPv4 address
        ip_match = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', line)
        ips = set()
        if ip_match:
            ips.add(ip_match.group())

        # Extract domains (very basic)
        domains = set(re.findall(r'\b([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\b', line))

        # Extract URLs (anything starting with http:// or https://)
        urls = set(re.findall(r'https?://[^\s"<>]+', line))

        if not (ips or domains or urls):
            return None

        # Try to extract timestamp (naive)
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
    """Parser for JSON logs (e.g., from Falco, Sysmon, etc.)."""
    def parse_line(self, line: str, source: Path) -> Optional[LogEvent]:
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            return None

        event = LogEvent(raw=line, timestamp=None, source=str(source))

        # Extract timestamp if present (common fields)
        ts = data.get('timestamp') or data.get('@timestamp') or data.get('time')
        if ts:
            try:
                # Try common formats
                if isinstance(ts, str):
                    if 'T' in ts:
                        event.timestamp = datetime.fromisoformat(ts.replace('Z', '+00:00'))
                    else:
                        event.timestamp = datetime.strptime(ts, '%Y-%m-%d %H:%M:%S')
            except:
                pass

        # Recursively search for IPs, domains, hashes in the JSON
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
            # Check for IP
            try:
                ipaddress.ip_address(obj)
                indicators['ip'].add(obj)
            except ValueError:
                pass
            # Check for domain (simple)
            if re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', obj):
                indicators['domain'].add(obj)
            # Check for URL
            if obj.startswith(('http://', 'https://')):
                indicators['url'].add(obj)
            # Check for hash (MD5, SHA1, SHA256)
            if re.match(r'^[a-fA-F0-9]{32}$', obj):
                indicators['hash'].add(obj)  # MD5
            elif re.match(r'^[a-fA-F0-9]{40}$', obj):
                indicators['hash'].add(obj)  # SHA1
            elif re.match(r'^[a-fA-F0-9]{64}$', obj):
                indicators['hash'].add(obj)  # SHA256

class CsvLogParser(LogParser):
    """Parser for CSV logs where columns are configurable."""
    def __init__(self, config: dict):
        super().__init__(config)
        self.delimiter = config.get('delimiter', ',')
        self.columns = config.get('columns', {})
        # Expected format: columns: {ip: 'src_ip', domain: 'host', hash: 'file_hash', timestamp: 'time'}

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

        # Extract timestamp if column defined
        ts_col = self.columns.get('timestamp')
        if ts_col and ts_col in row:
            try:
                # Try common formats
                ts_str = row[ts_col]
                if 'T' in ts_str:
                    event.timestamp = datetime.fromisoformat(ts_str.replace('Z', '+00:00'))
                else:
                    event.timestamp = datetime.strptime(ts_str, '%Y-%m-%d %H:%M:%S')
            except:
                pass

        # Extract indicators
        for ioc_type, col_name in self.columns.items():
            if ioc_type in ('ip', 'domain', 'hash', 'url') and col_name in row:
                value = row[col_name].strip()
                if value:
                    # Basic validation
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
    """Matches IOCs against log events."""
    def __init__(self, indicators: List[Indicator]):
        # Build lookup tables for efficient matching
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
    """Generates reports from matches."""
    def __init__(self, matches: List[Match]):
        self.matches = matches

    def console_report(self):
        console = Console()
        if not self.matches:
            console.print("[green]No matches found.[/green]")
            return

        # Group by indicator source and type for summary
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

        # Also print a summary count
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
        logger.info(f"CSV report written to {output_file}")

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
        logger.info(f"JSON report written to {output_file}")

# ========================== Main Application ==========================

class KoreApp:
    def __init__(self, config_file: str):
        self.config = self._load_config(config_file)
        self.feeds = self._init_feeds()
        self.parsers = self._init_parsers()

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
            # Add more feeds here
        }
        for name, cfg in feed_configs.items():
            if cfg.get('enabled', True):
                cls = feed_classes.get(name)
                if cls:
                    feeds.append(cls(name, cfg))
                else:
                    logger.warning(f"Unknown feed: {name}")
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
            else:
                logger.warning(f"Unknown parser: {name}")
        return parsers

    async def _fetch_all_indicators(self) -> List[Indicator]:
        all_indicators = []
        async with aiohttp.ClientSession() as session:
            tasks = [feed.fetch(session) for feed in self.feeds]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for result in results:
                if isinstance(result, Exception):
                    logger.error(f"Feed fetch failed: {result}")
                elif isinstance(result, list):
                    all_indicators.extend(result)
        # Deduplicate indicators (keep first occurrence)
        seen = set()
        unique = []
        for ind in all_indicators:
            key = (ind.type, ind.value)
            if key not in seen:
                seen.add(key)
                unique.append(ind)
        return unique

    def _parse_logs(self) -> List[LogEvent]:
        log_paths = []
        base_path = Path(self.config.get('logs', {}).get('directory', '.'))
        patterns = self.config.get('logs', {}).get('include_patterns', ['*.log'])
        for pattern in patterns:
            log_paths.extend(base_path.glob(pattern))

        all_events = []
        parser_name = self.config.get('logs', {}).get('parser', 'apache')  # default parser
        parser = self.parsers.get(parser_name)
        if not parser:
            logger.error(f"Parser '{parser_name}' not configured")
            return []

        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), transient=True) as progress:
            task = progress.add_task("Parsing logs...", total=len(log_paths))
            for path in log_paths:
                if path.is_file():
                    events = parser.parse_file(path)
                    all_events.extend(events)
                progress.advance(task)
        logger.info(f"Parsed {len(all_events)} events from {len(log_paths)} files")
        return all_events

    async def run(self, output_format: str = 'console', output_file: str = None):
        # Fetch IOCs
        logger.info("Fetching threat intelligence feeds...")
        indicators = await self._fetch_all_indicators()
        logger.info(f"Total unique indicators: {len(indicators)}")

        if not indicators:
            logger.warning("No indicators fetched. Check feed configurations.")

        # Parse logs
        logger.info("Parsing log files...")
        events = self._parse_logs()
        logger.info(f"Total events: {len(events)}")

        if not events:
            logger.warning("No log events parsed. Check log directory and patterns.")

        # Correlate
        logger.info("Correlating...")
        correlator = Correlator(indicators)
        matches = correlator.correlate(events)
        logger.info(f"Found {len(matches)} matches.")

        # Report
        reporter = Reporter(matches)
        if output_format == 'console':
            reporter.console_report()
        elif output_format == 'csv' and output_file:
            reporter.csv_report(output_file)
        elif output_format == 'json' and output_file:
            reporter.json_report(output_file)
        else:
            logger.error(f"Unsupported output format or missing output file.")

def main():
    parser = argparse.ArgumentParser(description="Kore - Threat Intelligence Correlation Engine")
    parser.add_argument('-c', '--config', required=True, help='Path to YAML configuration file')
    parser.add_argument('-o', '--output', choices=['console', 'csv', 'json'], default='console',
                        help='Output format (default: console)')
    parser.add_argument('-f', '--file', help='Output file (required for csv/json)')
    args = parser.parse_args()

    if args.output in ('csv', 'json') and not args.file:
        parser.error(f"--file is required when output is {args.output}")

    app = KoreApp(args.config)
    asyncio.run(app.run(output_format=args.output, output_file=args.file))

if __name__ == '__main__':
    main()