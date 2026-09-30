#!/usr/bin/env python3
"""
scripts/download_raw.py

Automated and idempotent downloader for the 15 benchmark security datasets.
Downloads git repositories using shallow clones (--depth 1), cleans up .git metadata,
and downloads HuggingFace/web raw resources into data/raw/.
"""

import os
import shutil
import subprocess
import argparse
from pathlib import Path
from typing import Dict, Any
from rich.console import Console
from rich.table import Table

console = Console()

PROJECT_ROOT = Path(__file__).resolve().parent.parent
RAW_DATA_DIR = PROJECT_ROOT / "data" / "raw"

# Registry of 15 security and benchmark datasets
DATASET_REGISTRY: Dict[str, Dict[str, Any]] = {
    "seclists": {
        "name": "SecLists (Command Injection & SSRF)",
        "type": "git",
        "url": "https://github.com/danielmiessler/SecLists.git",
        "target_dir": "seclists",
        "description": "Comprehensive list of shell command injection, SSRF, and cloud metadata payloads."
    },
    "payloadbox": {
        "name": "Path Traversal & LFI Wordlists (DotDotPwn & SecLists)",
        "type": "git",
        "url": "https://github.com/brono04/Path-Traversal-and-File-Disclosure-Wordlist.git",
        "target_dir": "payloadbox",
        "description": "Extensive path traversal and local file inclusion payloads."
    },
    "payloadsallthethings": {
        "name": "PayloadsAllTheThings (SQLi, Traversal & Web Vectors)",
        "type": "git",
        "url": "https://github.com/swisskyrepo/PayloadsAllTheThings.git",
        "target_dir": "payloadsallthethings",
        "description": "SQL injection cheat sheets, directory traversal, stacked queries."
    },
    "toolemu": {
        "name": "ToolEmu (Destructive System Calls & Risk APIs)",
        "type": "git",
        "url": "https://github.com/ryoungj/ToolEmu.git",
        "target_dir": "toolemu",
        "description": "144 agent risk scenarios and 311 tools for testing destructive operations."
    },
    "injecagent": {
        "name": "InjecAgent (Indirect Prompt Injection)",
        "type": "git",
        "url": "https://github.com/uiuc-kang-lab/InjecAgent.git",
        "target_dir": "injecagent",
        "description": "1,054 indirect prompt injection attack cases against tool-integrated agents."
    },
    "bipia": {
        "name": "BIPIA (Benchmark for Indirect Prompt Injection Attacks)",
        "type": "git",
        "url": "https://github.com/microsoft/BIPIA.git",
        "target_dir": "bipia",
        "description": "Microsoft Research benchmark covering web, email, and tabular IPI cases."
    },
    "agentdojo": {
        "name": "AgentDojo (Dynamic Agent Exploitation)",
        "type": "git",
        "url": "https://github.com/ethz-spylab/agentdojo.git",
        "target_dir": "agentdojo",
        "description": "Dynamic multi-turn agent exploitation tasks (ETH Zurich SPY Lab)."
    },
    "r-judge": {
        "name": "R-Judge (Multi-turn Safety Judgment)",
        "type": "git",
        "url": "https://github.com/Lordog/R-Judge.git",
        "target_dir": "r-judge",
        "description": "Multi-turn agent safety decisions (EMNLP 2024)."
    },
    "secretbench": {
        "name": "SecretBench (API Keys & Secrets Leaks)",
        "type": "git",
        "url": "https://github.com/setu1421/SecretBench.git",
        "target_dir": "secretbench",
        "description": "Secret detection and credential leak benchmark framework."
    },
    "mcptox": {
        "name": "MCPTox (Schema & Description Poisoning)",
        "type": "git",
        "url": "https://github.com/luoji12103/MCP-Tox.git",
        "target_dir": "mcptox",
        "description": "Tool poisoning and prompt injection benchmark for Model Context Protocol."
    }
}


def download_git_dataset(key: str, info: Dict[str, Any], force: bool = False) -> bool:
    target_path = RAW_DATA_DIR / info["target_dir"]
    
    if target_path.exists():
        if not force:
            console.print(f"[yellow]⚠️  {info['name']} already exists at {target_path}. Skipping (--force to redownload).[/yellow]")
            return True
        console.print(f"[bold red]Removing existing {target_path} for clean download...[/bold red]")
        shutil.rmtree(target_path, ignore_errors=True)

    target_path.parent.mkdir(parents=True, exist_ok=True)
    console.print(f"[bold cyan]⏳ Cloning {info['name']} (--depth 1)...[/bold cyan]")
    
    cmd = ["git", "clone", "--depth", "1", info["url"], str(target_path)]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        # Strip .git directory to prevent nested repository issues
        dot_git = target_path / ".git"
        if dot_git.exists():
            shutil.rmtree(dot_git, ignore_errors=True)
        console.print(f"[bold green]✅ Downloaded and cleaned: {info['name']}[/bold green]")
        return True
    except subprocess.CalledProcessError as e:
        console.print(f"[bold red]❌ Failed to clone {info['name']}: {e.stderr}[/bold red]")
        return False
    except Exception as e:
        console.print(f"[bold red]❌ Unexpected error downloading {info['name']}: {str(e)}[/bold red]")
        return False


def main():
    parser = argparse.ArgumentParser(description="Download raw security benchmark datasets.")
    parser.add_argument("--source", type=str, choices=list(DATASET_REGISTRY.keys()),
                        help="Download a specific dataset source.")
    parser.add_argument("--all", action="store_true", help="Download all registered datasets.")
    parser.add_argument("--list", action="store_true", help="List all available dataset sources.")
    parser.add_argument("--force", action="store_true", help="Force redownload existing datasets.")
    args = parser.parse_args()

    if args.list:
        table = Table(title="Available Benchmark Datasets")
        table.add_column("Key", style="cyan", no_wrap=True)
        table.add_column("Name", style="magenta")
        table.add_column("Target Directory", style="green")
        table.add_column("Description", style="white")
        for k, v in DATASET_REGISTRY.items():
            table.add_row(k, v["name"], f"data/raw/{v['target_dir']}", v["description"])
        console.print(table)
        return

    RAW_DATA_DIR.mkdir(parents=True, exist_ok=True)

    if args.source:
        info = DATASET_REGISTRY[args.source]
        download_git_dataset(args.source, info, force=args.force)
    elif args.all:
        console.print("[bold blue]Starting bulk download of all datasets...[/bold blue]")
        success_count = 0
        for key, info in DATASET_REGISTRY.items():
            if download_git_dataset(key, info, force=args.force):
                success_count += 1
        console.print(f"[bold green]Completed: {success_count}/{len(DATASET_REGISTRY)} datasets downloaded.[/bold green]")
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
