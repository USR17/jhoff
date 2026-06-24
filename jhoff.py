#!/usr/bin/env python3
"""
jhoff.py — integrated recon pipeline and knowledge base.

THREE SUBSYSTEMS:

1. KNOWLEDGE BASE (KB)
   - Topic-organized flat files (kb/[topic].kb)
   - Block format: ## blockname, # tags:, # desc:, body
   - Retrieval: --kb-list, --kb-show <key>, --kb-grep <term>
   - Index: built in-memory on each run

2. WEB RECON PIPELINE
   1. Full TCP port discovery (nmap -p-) -> open_ports.txt
   2. Service identification (-sC -sV -A) on discovered ports -> active_services.txt
   3. For each identified web service: gobuster dir (+ vhost if eligible)
   Web detection is service-driven (nmap XML), not port-based.
   Stage 3 dispatches per-service jobs in parallel via ThreadPoolExecutor.

3. UTILITIES (future)
   - Stateless transforms (ip2dec, SSRF payload generator, encoders)

CONFIG:
   Settings resolve with precedence: built-in defaults < jhoff.cfg < CLI.
   CLI flags left unset (None) do not override cfg values.

USAGE:
   KB operations:
     ./jhoff.py --kb-list
     ./jhoff.py --kb-show <block-name-or-tag>
     ./jhoff.py --kb-grep <search-term>

   Web recon:
     sudo ./jhoff.py <target> -w /path/to/dirlist.txt [-W /path/to/vhostlist.txt]
     sudo ./jhoff.py <target> -c jhoff.cfg

   Note: -A in nmap requires root for OS detection / raw socket operations.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import ipaddress
import re
import shutil
import subprocess
import sys
import tomllib
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Set, Optional


# ============================================================================
# KNOWLEDGE BASE SUBSYSTEM
# ============================================================================

@dataclass
class KBBlock:
    """Represents a single KB block."""
    name: str
    topic: str
    tags: Set[str] = field(default_factory=set)
    description: str = ""
    body: str = ""

    def __str__(self) -> str:
        """Return formatted block for display."""
        lines = [
            f"## {self.name}",
            f"# topic: {self.topic}",
            f"# tags: {', '.join(sorted(self.tags)) if self.tags else '(none)'}",
            f"# desc: {self.description}",
            "",
            self.body,
        ]
        return "\n".join(lines)

    @property
    def searchable_text(self) -> str:
        """Combine all searchable fields for grep."""
        return f"{self.name} {self.description} {' '.join(self.tags)} {self.body}".lower()


class KnowledgeBase:
    """KB subsystem: parse, index, and retrieve blocks."""

    def __init__(self, kb_dir: Optional[Path] = None):
        """
        Initialize KB subsystem.

        Args:
            kb_dir: Path to kb/ directory. If None, defaults to ./kb relative to this file.
        """
        if kb_dir is None:
            kb_dir = Path(__file__).parent / "kb"

        self.kb_dir = Path(kb_dir)
        self.blocks: List[KBBlock] = []
        self.index_by_name: Dict[str, KBBlock] = {}  # name -> KBBlock
        self.index_by_tag: Dict[str, List[KBBlock]] = {}  # tag -> [KBBlock, ...]
        self.index_by_topic: Dict[str, List[KBBlock]] = {}  # topic -> [KBBlock, ...]

    def ensure_kb_dir(self) -> None:
        """Create kb/ directory if it doesn't exist."""
        try:
            self.kb_dir.mkdir(parents=True, exist_ok=True)
        except Exception as e:
            print(f"[!] Failed to create kb directory: {e}", file=sys.stderr)
            sys.exit(1)

    def load(self) -> None:
        """
        Parse all .kb files in kb_dir and build indices.
        Creates kb_dir if it doesn't exist.
        """
        self.ensure_kb_dir()

        # Find all .kb files
        kb_files = sorted(self.kb_dir.glob("*.kb"))

        if not kb_files:
            # Empty knowledge base is acceptable; user can populate later
            return

        for kb_file in kb_files:
            topic = kb_file.stem  # filename without .kb extension
            self._parse_kb_file(kb_file, topic)

        # Build indices
        for block in self.blocks:
            self.index_by_name[block.name] = block

            for tag in block.tags:
                if tag not in self.index_by_tag:
                    self.index_by_tag[tag] = []
                self.index_by_tag[tag].append(block)

            if block.topic not in self.index_by_topic:
                self.index_by_topic[block.topic] = []
            self.index_by_topic[block.topic].append(block)

    def _parse_kb_file(self, kb_file: Path, topic: str) -> None:
        """
        Parse a single .kb file and extract blocks.

        Format:
            # topic: <topic>
            # desc: <file description>

            ## blockname
            # tags: tag1, tag2, tag3
            # desc: one-line description

            Block body (commands, payloads, code, etc.)
            Can span multiple lines.
            Raw content, pasteable as-is.

        Args:
            kb_file: Path to .kb file
            topic: Topic name (derived from filename)
        """
        try:
            content = kb_file.read_text(encoding='utf-8')
        except Exception as e:
            print(f"[!] Failed to read {kb_file}: {e}", file=sys.stderr)
            return

        # Split into blocks by ## delimiter
        block_pattern = r"^##\s+(.+)$"
        lines = content.split('\n')

        current_block_name = None
        current_tags: Set[str] = set()
        current_desc = ""
        current_body_lines: List[str] = []

        for i, line in enumerate(lines):
            block_match = re.match(block_pattern, line)

            if block_match:
                # Save previous block if exists
                if current_block_name is not None:
                    self._save_block(
                        current_block_name, topic, current_tags,
                        current_desc, '\n'.join(current_body_lines).strip()
                    )

                # Start new block
                current_block_name = block_match.group(1).strip()
                current_tags = set()
                current_desc = ""
                current_body_lines = []

            elif current_block_name is not None:
                # Parse metadata lines (# tags:, # desc:)
                if line.startswith("# tags:"):
                    tags_str = line.replace("# tags:", "").strip()
                    current_tags = {t.strip() for t in tags_str.split(',') if t.strip()}
                elif line.startswith("# desc:"):
                    current_desc = line.replace("# desc:", "").strip()
                elif not line.startswith("# "):
                    # Body content (skip leading metadata comment lines)
                    current_body_lines.append(line)

        # Save final block
        if current_block_name is not None:
            self._save_block(
                current_block_name, topic, current_tags,
                current_desc, '\n'.join(current_body_lines).strip()
            )

    def _save_block(self, name: str, topic: str, tags: Set[str], desc: str, body: str) -> None:
        """
        Validate and save a block.

        Validation rules:
        - Block name: required, non-empty
        - Tags: optional, but if present must be non-empty after splitting
        - Description: optional, but if present must be non-empty
        - Body: optional

        Invalid blocks are skipped with a warning.
        """
        # Validate block name
        if not name or not name.strip():
            print(f"[!] Skipped block with empty name in {topic}", file=sys.stderr)
            return

        name = name.strip()

        # Warn if duplicate name
        if name in self.index_by_name:
            print(f"[!] Duplicate block name '{name}' in {topic}; keeping first occurrence", file=sys.stderr)
            return

        block = KBBlock(
            name=name,
            topic=topic,
            tags=tags,
            description=desc,
            body=body,
        )
        self.blocks.append(block)

    def list_blocks(self) -> str:
        """
        List all blocks grouped by topic.

        Format:
            [topic]

            blockname (tags: tag1, tag2)
              one-line description
        """
        if not self.blocks:
            return "(No blocks loaded.)"

        output = []

        for topic in sorted(self.index_by_topic.keys()):
            output.append(f"\n[{topic}]")
            output.append("")

            for block in sorted(self.index_by_topic[topic], key=lambda b: b.name):
                tags_str = f"tags: {', '.join(sorted(block.tags))}" if block.tags else ""
                output.append(f"{block.name} ({tags_str})")
                if block.description:
                    output.append(f"  {block.description}")

        return "\n".join(output)

    def show_block(self, key: str) -> Optional[str]:
        """
        Retrieve block(s) by key (exact name first, then by tag).

        Returns:
            Formatted block(s), or None if not found.
        """
        results = []

        # Try exact name match first
        if key in self.index_by_name:
            results.append(self.index_by_name[key])
        # Then try tag match
        elif key in self.index_by_tag:
            results.extend(self.index_by_tag[key])
        else:
            return None

        return "\n\n".join(str(block) for block in results)

    def grep_blocks(self, term: str) -> Optional[str]:
        """
        Full-text search across block names, tags, descriptions, and bodies.

        Returns:
            Matching blocks with topic/name header, or None if no matches.
        """
        term_lower = term.lower()
        matches = []

        for block in self.blocks:
            if term_lower in block.searchable_text:
                matches.append(block)

        if not matches:
            return None

        output = []
        for block in sorted(matches, key=lambda b: (b.topic, b.name)):
            output.append(f"[{block.topic}] {block.name}")
            output.append(f"  tags: {', '.join(sorted(block.tags)) if block.tags else '(none)'}")
            output.append(f"  desc: {block.description}")
            output.append("")
            # Show context: first 300 chars of body
            if block.body:
                context = block.body[:300]
                if len(block.body) > 300:
                    context += "..."
                output.append(f"  context: {context}")
            output.append("")

        return "\n".join(output)


# ============================================================================
# WEB RECON PIPELINE
# ============================================================================

# Service-name and product hints used to classify a port as a web service.
WEB_SERVICE_NAMES = {
    "http", "https", "http-proxy", "http-alt", "https-alt",
    "www", "www-http", "http-rpc-epmap",
}
WEB_PRODUCT_HINTS = (
    "nginx", "apache", "iis", "tomcat", "jetty", "node",
    "lighttpd", "caddy", "httpd", "express", "gunicorn", "kestrel",
)

# Built-in defaults. Overridden by cfg, then by CLI.
DEFAULTS = {
    "outdir": "recon_output",
    "dir_wordlist": None,
    "vhost_wordlist": None,
    "rate": 1000,
    "workers": 4,
    "gobuster_threads": 30,
    "extensions": "",          # e.g. "php,html,txt"
    "skip_vhost": False,
    "gobuster_timeout": 1800,  # seconds, per gobuster invocation
    "max_retries": 3,          # gobuster wildcard-length retry bound
}

# Matches the length gobuster reports in its wildcard/soft-404 abort message.
# Tolerant of dir-mode and vhost-mode phrasings; both surface "Length: N".
_LENGTH_RE = re.compile(r"[Ll]ength:?\s*(\d+)")


@dataclass(frozen=True)
class WebService:
    port: int
    scheme: str  # "http" or "https"
    name: str
    product: str

    def url(self, host: str) -> str:
        return f"{self.scheme}://{host}:{self.port}"


@dataclass(frozen=True)
class Credential:
    """A single known-good credential.

    Exactly one of password / nthash is set (secret). domain is optional;
    empty string means local account (tools receive '.' or the target as
    workgroup depending on the handler — resolved at use site, not here).
    """
    username: str
    password: str | None
    nthash: str | None
    domain: str

    @property
    def is_hash(self) -> bool:
        return self.nthash is not None

    @property
    def secret(self) -> str:
        return self.nthash if self.nthash is not None else (self.password or "")

    def label(self) -> str:
        dom = f"{self.domain}\\" if self.domain else ""
        kind = "hash" if self.is_hash else "pass"
        return f"{dom}{self.username} ({kind})"


# Sentinel for the unauthenticated / null-session case (no creds supplied).
NULL_SESSION: list[Credential] = []


@dataclass
class Settings:
    outdir: str
    dir_wordlist: str | None
    vhost_wordlist: str | None
    rate: int
    workers: int
    gobuster_threads: int
    extensions: str
    skip_vhost: bool
    gobuster_timeout: int
    max_retries: int
    no_web_recon: bool = False
    credentials: list[Credential] = field(default_factory=list)
    exclude_lengths: set[int] = field(default_factory=set)

    @property
    def null_session(self) -> bool:
        return len(self.credentials) == 0


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def check_tool(name: str) -> None:
    if shutil.which(name) is None:
        sys.exit(f"[!] Required tool not found in PATH: {name}")


def run_streamed(cmd: list[str], timeout: int | None = None) -> int:
    """Run a command, stream output live, return exit code. Used for nmap."""
    print(f"[*] {' '.join(cmd)}")
    try:
        proc = subprocess.run(cmd, check=False, timeout=timeout)
        return proc.returncode
    except FileNotFoundError as e:
        print(f"[!] {e}", file=sys.stderr)
        return 127
    except subprocess.TimeoutExpired:
        print(f"[!] Timed out after {timeout}s: {' '.join(cmd)}", file=sys.stderr)
        return 124


def run_captured(cmd: list[str], timeout: int | None = None) -> tuple[int, str]:
    """Run a command, capture combined output, also echo it. Used for gobuster."""
    print(f"[*] {' '.join(cmd)}")
    try:
        proc = subprocess.run(
            cmd, check=False, timeout=timeout,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        )
        if proc.stdout:
            print(proc.stdout, end="")
        return proc.returncode, proc.stdout or ""
    except FileNotFoundError as e:
        print(f"[!] {e}", file=sys.stderr)
        return 127, ""
    except subprocess.TimeoutExpired as e:
        captured = e.stdout or ""
        if isinstance(captured, bytes):
            captured = captured.decode(errors="replace")
        if captured:
            print(captured, end="")
        print(f"[!] Timed out after {timeout}s: {' '.join(cmd)}", file=sys.stderr)
        return 124, captured


def is_ip_literal(target: str) -> bool:
    """True if target is an IPv4 or IPv6 literal (not a hostname)."""
    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        return False


# ---------------------------------------------------------------------------
# Config resolution
# ---------------------------------------------------------------------------

def load_cfg(path: Path) -> tuple[dict, list[Credential]]:
    """Parse the TOML config into (flat settings dict, credential list).

    Returns recognized scalar settings flattened to top-level keys, plus a
    parsed/validated list of Credential objects. Unknown keys are ignored.
    """
    try:
        with path.open("rb") as fh:
            data = tomllib.load(fh)
    except tomllib.TOMLDecodeError as e:
        sys.exit(f"[!] Config TOML parse error: {e}")
    except OSError as e:
        sys.exit(f"[!] Config file not readable: {e}")

    cfg: dict = {}

    def take(section: str, key: str, dest: str | None = None):
        sec = data.get(section, {})
        if isinstance(sec, dict) and key in sec:
            cfg[dest or key] = sec[key]

    take("general", "outdir")
    take("wordlists", "dir_wordlist")
    take("wordlists", "vhost_wordlist")
    take("performance", "rate")
    take("performance", "workers")
    take("performance", "gobuster_threads")
    take("performance", "gobuster_timeout")
    take("gobuster", "extensions")
    take("gobuster", "max_retries")
    take("gobuster", "skip_vhost")

    creds = _parse_credentials(data.get("cred", []))
    return cfg, creds


def _parse_credentials(raw) -> list[Credential]:
    """Validate the [[cred]] array-of-tables into Credential objects.

    Each entry requires username and exactly one of password / nthash.
    domain is optional (defaults to ''). Malformed entries are fatal — a
    silently dropped credential is worse than a hard error on a CTF.
    """
    if not isinstance(raw, list):
        sys.exit("[!] cfg 'cred' must be an array of tables ([[cred]]).")

    creds: list[Credential] = []
    for i, entry in enumerate(raw, 1):
        if not isinstance(entry, dict):
            sys.exit(f"[!] cred #{i}: not a table.")
        user = entry.get("username")
        if not user:
            sys.exit(f"[!] cred #{i}: missing 'username'.")
        pw = entry.get("password")
        nt = entry.get("nthash")
        if (pw is None) == (nt is None):
            sys.exit(f"[!] cred #{i} ({user}): set exactly one of 'password' or 'nthash'.")
        domain = entry.get("domain", "") or ""
        creds.append(Credential(
            username=str(user),
            password=str(pw) if pw is not None else None,
            nthash=str(nt) if nt is not None else None,
            domain=str(domain),
        ))
    return creds


def resolve_settings(args: argparse.Namespace) -> Settings:
    """Merge defaults < cfg < CLI. CLI values left as None do not override."""
    merged = dict(DEFAULTS)
    creds: list[Credential] = []

    if args.config:
        cfg_path = Path(args.config)
        if not cfg_path.is_file():
            sys.exit(f"[!] Config file not found: {cfg_path}")
        cfg_scalars, creds = load_cfg(cfg_path)
        merged.update(cfg_scalars)

    # CLI overrides: only keys explicitly provided (not None / not False-by-absence).
    cli_keys = (
        "outdir", "dir_wordlist", "vhost_wordlist", "rate",
        "workers", "gobuster_threads", "extensions", "gobuster_timeout",
        "max_retries",
    )
    for key in cli_keys:
        val = getattr(args, key, None)
        if val is not None:
            merged[key] = val

    # store_true flags: only override when set.
    if args.skip_vhost:
        merged["skip_vhost"] = True

    s = Settings(
        outdir=merged["outdir"],
        dir_wordlist=merged["dir_wordlist"],
        vhost_wordlist=merged["vhost_wordlist"],
        rate=int(merged["rate"]),
        workers=int(merged["workers"]),
        gobuster_threads=int(merged["gobuster_threads"]),
        extensions=merged["extensions"] or "",
        skip_vhost=bool(merged["skip_vhost"]),
        gobuster_timeout=int(merged["gobuster_timeout"]),
        max_retries=int(merged["max_retries"]),
        no_web_recon=bool(args.no_web_recon),
        credentials=creds,
    )

    # Manual -xl override seeds the exclude set.
    if args.exclude_length:
        s.exclude_lengths.update(args.exclude_length)
    return s


# ---------------------------------------------------------------------------
# Stage 1: port discovery
# ---------------------------------------------------------------------------

def stage_port_discovery(target: str, outdir: Path, rate: int) -> list[int]:
    xml_path = outdir / "discovery.xml"
    cmd = [
        "nmap", "-p-", f"--min-rate={rate}", "-T3", "-Pn",
        "-oX", str(xml_path),
        "-oN", str(outdir / "discovery.nmap"),
        target,
    ]
    if run_streamed(cmd) != 0:
        sys.exit("[!] Port discovery failed.")

    try:
        ports = _parse_open_ports(xml_path)
    except ET.ParseError as e:
        sys.exit(f"[!] Could not parse discovery XML ({e}). nmap may have been interrupted.")
    (outdir / "open_ports.txt").write_text("\n".join(str(p) for p in ports) + "\n")
    print(f"[+] Open ports ({len(ports)}): {ports}")
    return ports


def _parse_open_ports(xml_path: Path) -> list[int]:
    tree = ET.parse(xml_path)
    ports: list[int] = []
    for port in tree.iter("port"):
        state = port.find("state")
        if state is not None and state.get("state") == "open":
            ports.append(int(port.get("portid")))
    return sorted(set(ports))


# ---------------------------------------------------------------------------
# Stage 2: service identification
# ---------------------------------------------------------------------------

def stage_service_id(target: str, ports: list[int], outdir: Path) -> Path:
    xml_path = outdir / "services.xml"
    cmd = [
        "nmap", "-sC", "-sV", "-A", "-Pn",
        "-p", ",".join(str(p) for p in ports),
        "-oX", str(xml_path),
        "-oN", str(outdir / "active_services.txt"),
        target,
    ]
    if run_streamed(cmd) != 0:
        print("[!] Service ID returned non-zero; continuing with whatever was written.", file=sys.stderr)
    return xml_path


def parse_web_services(xml_path: Path) -> list[WebService]:
    try:
        tree = ET.parse(xml_path)
    except (ET.ParseError, FileNotFoundError) as e:
        print(f"[!] Could not parse services XML ({e}); no web services derived.", file=sys.stderr)
        return []

    web: list[WebService] = []
    for port in tree.iter("port"):
        state = port.find("state")
        if state is None or state.get("state") != "open":
            continue
        portid = int(port.get("portid"))
        service = port.find("service")
        if service is None:
            continue

        name = (service.get("name") or "").lower()
        product = (service.get("product") or "").lower()
        tunnel = (service.get("tunnel") or "").lower()

        is_web = (
            name in WEB_SERVICE_NAMES
            or name.startswith("http")
            or any(hint in product for hint in WEB_PRODUCT_HINTS)
        )
        if not is_web:
            continue

        scheme = "https" if (tunnel == "ssl" or "https" in name or "ssl" in name) else "http"
        web.append(WebService(port=portid, scheme=scheme, name=name, product=product))
    return web


# ---------------------------------------------------------------------------
# Stage 3: web enumeration
# ---------------------------------------------------------------------------

def _parse_wildcard_length(output: str) -> int | None:
    """Extract the wildcard/soft-404 length gobuster reports on abort."""
    # Only inspect lines that indicate the wildcard abort, to avoid grabbing
    # a length from an ordinary result row.
    for line in output.splitlines():
        low = line.lower()
        if "wildcard" in low or "please exclude" in low or "to continue" in low:
            m = _LENGTH_RE.search(line)
            if m:
                return int(m.group(1))
    # Fallback: any Length token in the tail of the output.
    m = _LENGTH_RE.search(output)
    return int(m.group(1)) if m else None


def _build_gobuster_cmd(
    mode: str, target: str, ws: WebService, wordlist: Path,
    out: Path, threads: int, exclude: set[int], extensions: str,
) -> list[str]:
    cmd = [
        "gobuster", mode,
        "-u", ws.url(target),
        "-w", str(wordlist),
        "-t", str(threads),
        "-o", str(out),
        "--no-error",
    ]
    if mode == "dir" and extensions:
        cmd += ["-x", extensions]
    if mode == "vhost":
        cmd.append("--append-domain")
    if ws.scheme == "https":
        cmd.append("-k")
    if exclude:
        cmd += ["--exclude-length", ",".join(str(n) for n in sorted(exclude))]
    return cmd


def run_gobuster(
    mode: str, target: str, ws: WebService, wordlist: Path,
    outdir: Path, s: Settings,
) -> None:
    """Run gobuster, auto-retrying with an accumulating exclude-length set."""
    out = outdir / f"gobuster_{mode}_{ws.port}_{ws.scheme}.txt"
    exclude = set(s.exclude_lengths)  # seed from manual -xl, per-job copy
    attempts = 0

    while attempts <= s.max_retries:
        attempts += 1
        cmd = _build_gobuster_cmd(
            mode, target, ws, wordlist, out, s.gobuster_threads,
            exclude, s.extensions,
        )
        rc, output = run_captured(cmd, timeout=s.gobuster_timeout)

        if rc == 0:
            return
        if rc == 124:  # timeout — don't loop on a tarpit
            print(f"[!] gobuster {mode} :{ws.port} timed out; leaving partial output.", file=sys.stderr)
            return

        length = _parse_wildcard_length(output)
        if length is None:
            print(f"[!] gobuster {mode} :{ws.port} failed (rc={rc}), no wildcard length found; not retrying.", file=sys.stderr)
            return
        if length in exclude:
            print(f"[!] gobuster {mode} :{ws.port} re-reported length {length} already excluded; aborting retry loop.", file=sys.stderr)
            return

        exclude.add(length)
        print(f"[~] gobuster {mode} :{ws.port} wildcard length {length}; retrying with exclude set {sorted(exclude)} (attempt {attempts}/{s.max_retries}).")

    print(f"[!] gobuster {mode} :{ws.port} exhausted {s.max_retries} retries; exclude set {sorted(exclude)}.", file=sys.stderr)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="jhoff — integrated recon pipeline and knowledge base",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
EXAMPLES:
  KB operations:
    %(prog)s --kb-list
    %(prog)s --kb-show ssrf
    %(prog)s --kb-grep "aws credential"

  Web recon (requires target):
    sudo %(prog)s 10.0.0.1 -w /path/to/dirlist.txt
    sudo %(prog)s 10.0.0.1 -c jhoff.cfg
        """
    )

    # KB operations (mutually exclusive with recon)
    kb_group = p.add_argument_group("knowledge base operations")
    kb_group.add_argument("--kb-list", action="store_true", help="List all KB blocks grouped by topic")
    kb_group.add_argument("--kb-show", metavar="<key>", help="Retrieve block by exact name or tag")
    kb_group.add_argument("--kb-grep", metavar="<term>", help="Full-text search in KB blocks")
    kb_group.add_argument("--kb-dir", default=None, help="Path to kb/ directory (default: ./kb)")

    # Recon operations (requires target)
    p.add_argument("target", nargs="?", help="Target IP or hostname (must be in engagement scope)")
    p.add_argument("-c", "--config", help="Path to jhoff.cfg")

    # Defaults are None so we can distinguish 'user set it' from 'use cfg/default'.
    p.add_argument("-o", "--outdir", default=None, help="Base output directory")
    p.add_argument("-w", "--dir-wordlist", dest="dir_wordlist", default=None, help="Wordlist for gobuster dir")
    p.add_argument("-W", "--vhost-wordlist", dest="vhost_wordlist", default=None, help="Wordlist for gobuster vhost")
    p.add_argument("-x", "--extensions", default=None, help="gobuster dir extensions, e.g. php,html,txt")
    p.add_argument("-xl", "--exclude-length", type=_csv_ints, default=None,
                   help="Seed gobuster --exclude-length (comma-separated ints)")
    p.add_argument("--skip-vhost", action="store_true", help="Skip vhost scanning even if eligible")
    p.add_argument("--no-web-recon", "-NWR", dest="no_web_recon", action="store_true",
                   help="Skip the entire web enumeration stage (stage 3). For re-runs that "
                        "test newly-found creds against services without repeating gobuster.")
    p.add_argument("--rate", type=int, default=None, help="nmap --min-rate for stage 1")
    p.add_argument("--workers", type=int, default=None, help="Parallel web scans")
    p.add_argument("--gobuster-threads", dest="gobuster_threads", type=int, default=None, help="gobuster -t value")
    p.add_argument("--gobuster-timeout", dest="gobuster_timeout", type=int, default=None, help="Per-gobuster timeout (s)")
    p.add_argument("--max-retries", dest="max_retries", type=int, default=None, help="Gobuster wildcard retry bound")

    return p.parse_args()


def _csv_ints(raw: str) -> set[int]:
    try:
        return {int(x) for x in raw.split(",") if x.strip()}
    except ValueError:
        raise argparse.ArgumentTypeError("expected comma-separated integers")


def main() -> None:
    args = parse_args()

    # =========================================================================
    # KB OPERATIONS
    # =========================================================================
    if args.kb_list or args.kb_show or args.kb_grep:
        kb_dir = Path(args.kb_dir) if args.kb_dir else None
        kb = KnowledgeBase(kb_dir=kb_dir)
        kb.load()

        if args.kb_list:
            print(kb.list_blocks())
        elif args.kb_show:
            result = kb.show_block(args.kb_show)
            if result:
                print(result)
            else:
                print(f"[!] Block or tag not found: {args.kb_show}", file=sys.stderr)
                sys.exit(1)
        elif args.kb_grep:
            result = kb.grep_blocks(args.kb_grep)
            if result:
                print(result)
            else:
                print(f"[!] No matches for: {args.kb_grep}", file=sys.stderr)
                sys.exit(1)
        return

    # =========================================================================
    # WEB RECON PIPELINE
    # =========================================================================
    if not args.target:
        print("[!] target required for web recon (or use --kb-* for knowledge base operations)", file=sys.stderr)
        sys.exit(1)

    s = resolve_settings(args)

    for tool in ("nmap", "gobuster"):
        check_tool(tool)

    target = args.target
    outdir = Path(s.outdir) / target.replace("/", "_")
    outdir.mkdir(parents=True, exist_ok=True)

    # Wordlists are only required if the web stage will actually run.
    dir_wl: Path | None = None
    vhost_wl: Path | None = None
    if not s.no_web_recon:
        if not s.dir_wordlist:
            sys.exit("[!] No dir wordlist set (use -w or set wordlists.dir_wordlist in cfg).")
        dir_wl = Path(s.dir_wordlist)
        if not dir_wl.is_file():
            sys.exit(f"[!] Directory wordlist not found: {dir_wl}")
        if s.vhost_wordlist:
            vhost_wl = Path(s.vhost_wordlist)
            if not vhost_wl.is_file():
                sys.exit(f"[!] Vhost wordlist not found: {vhost_wl}")

    # Credential / session-mode summary.
    if s.null_session:
        print("[*] No credentials supplied — NULL/unauthenticated session.")
    else:
        print(f"[*] {len(s.credentials)} credential(s) loaded: {[c.label() for c in s.credentials]}")

    print(f"[*] Stage 1: port discovery -> {outdir}")
    ports = stage_port_discovery(target, outdir, s.rate)
    if not ports:
        sys.exit("[!] No open ports discovered. Halting.")

    print(f"[*] Stage 2: service identification on {len(ports)} ports")
    services_xml = stage_service_id(target, ports, outdir)

    if s.no_web_recon:
        print("[*] --no-web-recon set; skipping web enumeration (stage 3).")
        print(f"[+] Pipeline complete. Output: {outdir}")
        return

    print("[*] Stage 3: parsing web services from nmap XML")
    web_services = parse_web_services(services_xml)
    if not web_services:
        print("[+] No web services identified. Pipeline complete.")
        return

    print(f"[+] Web services identified: {[(ws.scheme, ws.port, ws.product or ws.name) for ws in web_services]}")

    web_outdir = outdir / "web"
    web_outdir.mkdir(exist_ok=True)

    # NOTE: vhost remains gated on a hostname target. On an IP-only HTB start
    # this stays inactive until a domain is derived/added. Unchanged by request.
    do_vhost = (
        not s.skip_vhost
        and vhost_wl is not None
        and not is_ip_literal(target)
    )
    if s.vhost_wordlist and not do_vhost and not s.skip_vhost and is_ip_literal(target):
        print("[!] vhost wordlist provided but target is an IP literal; skipping vhost stage.")

    with concurrent.futures.ThreadPoolExecutor(max_workers=s.workers) as pool:
        futures = []
        for ws in web_services:
            futures.append(pool.submit(run_gobuster, "dir", target, ws, dir_wl, web_outdir, s))
            if do_vhost:
                futures.append(pool.submit(run_gobuster, "vhost", target, ws, vhost_wl, web_outdir, s))

        for f in concurrent.futures.as_completed(futures):
            exc = f.exception()
            if exc is not None:
                print(f"[!] Worker error: {exc}", file=sys.stderr)

    print(f"[+] Pipeline complete. Output: {outdir}")


if __name__ == "__main__":
    main()
