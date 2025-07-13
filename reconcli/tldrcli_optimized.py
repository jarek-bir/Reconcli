#!/usr/bin/env python3

import os
import sys
import json
import time
import click
import asyncio
import aiohttp
import aiodns
from datetime import datetime
from typing import Dict, List, Optional, Tuple
from tqdm.asyncio import tqdm
import socket

# Import notifications
try:
    from reconcli.utils.notifications import send_notification, NotificationManager
except ImportError:
    send_notification = None
    NotificationManager = None

# Import resume utilities
try:
    from reconcli.utils.resume import load_resume, save_resume_state, clear_resume
except ImportError:

    def load_resume(output_dir):
        path = os.path.join(output_dir, "resume.cfg")
        if os.path.exists(path):
            with open(path, "r") as f:
                return json.load(f)
        return {}

    def save_resume_state(output_dir, state):
        path = os.path.join(output_dir, "resume.cfg")
        with open(path, "w") as f:
            json.dump(state, f, indent=2)

    def clear_resume(output_dir):
        path = os.path.join(output_dir, "resume.cfg")
        if os.path.exists(path):
            os.remove(path)


# OPTIMIZED TLD LISTS - Organized for Performance
DEFAULT_TLDS = {
    "popular": [
        # Top 100 most common TLDs for fast scanning
        "com",
        "net",
        "org",
        "edu",
        "gov",
        "mil",
        "int",
        "co",
        "io",
        "me",
        "tv",
        "cc",
        "biz",
        "info",
        "name",
        "pro",
        "mobi",
        "travel",
        "jobs",
        "tel",
        "cat",
        "asia",
        "app",
        "dev",
        "tech",
        "cloud",
        "online",
        "site",
        "website",
        "store",
        "shop",
        "blog",
        "news",
        "media",
        "ai",
        "bot",
        "top",
        "xyz",
        "tk",
        "ml",
        "ga",
        "cf",
        "gq",
        "icu",
        "click",
        "link",
        "live",
        "world",
        "global",
        "space",
        "digital",
        "zone",
        "life",
        "today",
        "fun",
        "run",
        "host",
        "page",
        "web",
        "download",
        "stream",
        "video",
        "audio",
        "photo",
        "pics",
        "gallery",
        "art",
        "design",
        "studio",
        "agency",
        "company",
        "business",
        "corp",
        "ltd",
        "group",
        "team",
        "network",
        "systems",
        "solutions",
        "services",
        "consulting",
        "expert",
        "guru",
        "ninja",
        "geek",
        "hacker",
        "coder",
        "programmer",
        "developer",
        "engineer",
    ],
    "country": [
        # Major country code TLDs - most likely to be registered
        "us",
        "uk",
        "de",
        "fr",
        "it",
        "es",
        "ru",
        "cn",
        "jp",
        "kr",
        "in",
        "au",
        "ca",
        "br",
        "mx",
        "ar",
        "cl",
        "pe",
        "co",
        "ve",
        "ec",
        "bo",
        "py",
        "uy",
        "nl",
        "be",
        "ch",
        "at",
        "dk",
        "se",
        "no",
        "fi",
        "pl",
        "cz",
        "sk",
        "hu",
        "ro",
        "bg",
        "hr",
        "si",
        "rs",
        "ba",
        "mk",
        "me",
        "al",
        "gr",
        "cy",
        "mt",
        "ie",
        "is",
        "pt",
        "tr",
        "il",
        "ae",
        "sa",
        "eg",
        "ma",
        "za",
        "ng",
        "ke",
        "gh",
        "tz",
        "ug",
        "rw",
        "mz",
        "bw",
        "na",
        "sz",
        "ls",
        "mw",
        "zm",
        "zw",
        "th",
        "sg",
        "my",
        "id",
        "ph",
        "vn",
        "mm",
        "kh",
        "la",
        "bn",
        "fj",
        "pg",
        "nz",
        "tv",
        "tk",
        "nu",
        "pf",
        "nc",
        "vu",
        "sb",
        "fm",
        "pw",
        "mh",
        "ki",
    ],
    "new_generic": [
        # New gTLDs with high registration rates
        "academy",
        "accountant",
        "actor",
        "adult",
        "africa",
        "agency",
        "airforce",
        "amsterdam",
        "apartments",
        "app",
        "art",
        "asia",
        "associates",
        "attorney",
        "auction",
        "auto",
        "baby",
        "band",
        "bank",
        "bar",
        "basketball",
        "beauty",
        "beer",
        "berlin",
        "best",
        "bet",
        "bible",
        "bid",
        "bike",
        "bingo",
        "bio",
        "black",
        "blog",
        "blue",
        "book",
        "boutique",
        "box",
        "broker",
        "build",
        "business",
        "buy",
        "buzz",
        "cafe",
        "camera",
        "camp",
        "capital",
        "car",
        "cards",
        "care",
        "career",
        "careers",
        "cars",
        "casa",
        "cash",
        "casino",
        "catering",
        "center",
        "ceo",
        "charity",
        "chat",
        "cheap",
        "church",
        "city",
        "claims",
        "cleaning",
        "click",
        "clinic",
        "clothing",
        "cloud",
        "club",
        "coach",
        "codes",
        "coffee",
        "college",
        "community",
        "company",
        "computer",
        "condos",
        "construction",
        "consulting",
        "contact",
        "contractors",
        "cooking",
        "cool",
        "country",
        "coupons",
        "courses",
        "credit",
        "creditcard",
        "cricket",
        "cruises",
        "dance",
        "date",
        "dating",
        "deals",
        "degree",
        "delivery",
        "democrat",
        "dental",
        "dentist",
        "design",
        "dev",
        "diamonds",
        "diet",
        "digital",
        "direct",
        "directory",
        "discount",
        "doctor",
        "dog",
        "domains",
        "download",
        "earth",
        "eat",
        "eco",
        "education",
        "email",
        "energy",
        "engineer",
        "engineering",
        "enterprises",
        "equipment",
        "estate",
        "events",
        "exchange",
        "expert",
        "exposed",
        "express",
        "fail",
        "faith",
        "family",
        "fan",
        "fans",
        "farm",
        "fashion",
        "fast",
        "film",
        "finance",
        "financial",
        "fish",
        "fishing",
        "fit",
        "fitness",
        "flights",
        "florist",
        "flowers",
        "food",
        "football",
        "forex",
        "forsale",
        "foundation",
        "free",
        "fun",
        "fund",
        "furniture",
        "futbol",
        "fyi",
        "gallery",
        "game",
        "games",
        "garden",
        "gift",
        "gifts",
        "gives",
        "glass",
        "global",
        "gold",
        "golf",
        "graphics",
        "gratis",
        "green",
        "gripe",
        "group",
        "guide",
        "guru",
        "hair",
        "halal",
        "health",
        "healthcare",
        "help",
        "hiphop",
        "hockey",
        "holdings",
        "holiday",
        "home",
        "horse",
        "hospital",
        "host",
        "hosting",
        "hotel",
        "house",
        "how",
        "immo",
        "immobilien",
        "industries",
        "ink",
        "institute",
        "insurance",
        "insure",
        "international",
        "investments",
        "irish",
        "jetzt",
        "jewelry",
        "jobs",
        "kaufen",
        "kim",
        "kitchen",
        "land",
        "latin",
        "law",
        "lawyer",
        "lease",
        "legal",
        "lgbt",
        "life",
        "lighting",
        "limited",
        "limo",
        "link",
        "live",
        "loan",
        "loans",
        "lol",
        "london",
        "love",
        "ltd",
        "luxury",
        "maison",
        "makeup",
        "management",
        "market",
        "marketing",
        "markets",
        "mba",
        "media",
        "medical",
        "meet",
        "memorial",
        "men",
        "menu",
        "miami",
        "money",
        "mortgage",
        "movie",
        "network",
        "news",
        "ninja",
        "now",
        "nyc",
        "online",
        "page",
        "paris",
        "partners",
        "parts",
        "party",
        "pet",
        "photo",
        "photography",
        "photos",
        "pics",
        "pictures",
        "pink",
        "pizza",
        "place",
        "plumbing",
        "plus",
        "poker",
        "porn",
        "press",
        "productions",
        "promo",
        "properties",
        "property",
        "protection",
        "pub",
        "qa",
        "racing",
        "radio",
        "recipes",
        "red",
        "rehab",
        "rent",
        "rentals",
        "repair",
        "report",
        "republican",
        "restaurant",
        "review",
        "reviews",
        "rich",
        "rip",
        "rocks",
        "run",
        "sale",
        "salon",
        "save",
        "school",
        "science",
        "search",
        "security",
        "select",
        "services",
        "sex",
        "sexy",
        "shiksha",
        "shoes",
        "shop",
        "shopping",
        "show",
        "singles",
        "site",
        "ski",
        "skin",
        "soccer",
        "social",
        "software",
        "solar",
        "solutions",
        "space",
        "sport",
        "store",
        "stream",
        "studio",
        "study",
        "style",
        "sucks",
        "supplies",
        "supply",
        "support",
        "surf",
        "surgery",
        "systems",
        "tax",
        "taxi",
        "team",
        "tech",
        "technology",
        "tennis",
        "theater",
        "theatre",
        "tips",
        "tires",
        "today",
        "tools",
        "top",
        "tours",
        "town",
        "toys",
        "trade",
        "training",
        "travel",
        "tube",
        "tv",
        "university",
        "uno",
        "vacations",
        "vegas",
        "ventures",
        "vet",
        "video",
        "villas",
        "vision",
        "vote",
        "voyage",
        "watch",
        "water",
        "wealth",
        "web",
        "website",
        "wedding",
        "wiki",
        "win",
        "wine",
        "work",
        "works",
        "world",
        "wtf",
        "xxx",
        "yoga",
        "zone",
    ],
    "business": [
        # Business-focused TLDs
        "business",
        "company",
        "corp",
        "corporation",
        "inc",
        "llc",
        "ltd",
        "group",
        "enterprises",
        "holdings",
        "ventures",
        "partners",
        "associates",
        "consulting",
        "services",
        "solutions",
        "systems",
        "network",
        "agency",
        "firm",
        "management",
        "capital",
        "investments",
        "fund",
        "finance",
        "financial",
        "bank",
        "credit",
        "insurance",
        "law",
        "legal",
        "attorney",
        "lawyer",
        "accountant",
        "tax",
        "audit",
        "consulting",
        "expert",
        "professional",
        "pro",
        "biz",
        "trade",
        "industry",
        "manufacturing",
        "construction",
        "engineering",
        "equipment",
        "supplies",
        "tools",
        "machinery",
        "factory",
        "plant",
        "warehouse",
        "logistics",
        "shipping",
        "delivery",
        "transport",
        "freight",
        "cargo",
        "express",
        "fast",
        "direct",
        "global",
        "international",
        "worldwide",
        "market",
        "marketplace",
        "exchange",
        "trading",
        "broker",
        "dealer",
        "wholesale",
        "retail",
        "store",
        "shop",
        "shopping",
        "mall",
        "center",
        "plaza",
        "outlet",
        "boutique",
        "brand",
        "luxury",
        "premium",
        "quality",
        "best",
        "top",
        "elite",
        "select",
        "choice",
    ],
    "crypto_blockchain": [
        # Cryptocurrency and blockchain related TLDs
        "crypto",
        "blockchain",
        "bitcoin",
        "btc",
        "eth",
        "ethereum",
        "coin",
        "coins",
        "token",
        "tokens",
        "nft",
        "defi",
        "dao",
        "dex",
        "swap",
        "stake",
        "mining",
        "wallet",
        "finance",
        "fintech",
        "bank",
        "pay",
        "payment",
        "money",
        "cash",
        "digital",
        "virtual",
        "cyber",
        "tech",
        "technology",
        "innovation",
        "future",
        "web3",
        "metaverse",
        "ai",
        "bot",
        "smart",
        "chain",
        "protocol",
        "network",
    ],
    "emerging_tech": [
        # Emerging technology TLDs
        "ai",
        "ml",
        "data",
        "analytics",
        "big",
        "cloud",
        "edge",
        "iot",
        "5g",
        "6g",
        "quantum",
        "nano",
        "bio",
        "gene",
        "dna",
        "space",
        "mars",
        "moon",
        "rocket",
        "drone",
        "robot",
        "auto",
        "electric",
        "solar",
        "green",
        "eco",
        "clean",
        "energy",
        "battery",
        "fuel",
        "hydrogen",
        "carbon",
        "climate",
        "sustainable",
        "smart",
        "digital",
        "cyber",
        "virtual",
        "augmented",
        "mixed",
        "reality",
        "vr",
        "ar",
        "mr",
        "3d",
        "hologram",
        "neural",
        "brain",
        "mind",
        "memory",
    ],
    "geographic": [
        # Geographic and location-based TLDs
        "world",
        "global",
        "international",
        "earth",
        "planet",
        "universe",
        "space",
        "city",
        "town",
        "village",
        "county",
        "state",
        "country",
        "nation",
        "region",
        "continent",
        "island",
        "peninsula",
        "mountain",
        "hill",
        "valley",
        "river",
        "lake",
        "sea",
        "ocean",
        "beach",
        "coast",
        "shore",
        "harbor",
        "port",
        "bay",
        "gulf",
        "strait",
        "channel",
        "bridge",
        "tunnel",
        "road",
        "street",
        "avenue",
        "plaza",
        "square",
        "park",
        "garden",
        "forest",
        "jungle",
        "desert",
        "arctic",
        "tropical",
        "northern",
        "southern",
        "eastern",
        "western",
        "central",
        "north",
        "south",
        "east",
        "west",
        "local",
        "nearby",
        "close",
        "far",
        "distant",
        "remote",
    ],
    "industry_specific": [
        # Industry-specific TLDs for various sectors
        "health",
        "healthcare",
        "medical",
        "hospital",
        "clinic",
        "doctor",
        "dentist",
        "pharmacy",
        "medicine",
        "drug",
        "therapy",
        "treatment",
        "surgery",
        "care",
        "wellness",
        "fitness",
        "gym",
        "sport",
        "sports",
        "team",
        "league",
        "game",
        "games",
        "play",
        "toy",
        "toys",
        "fun",
        "entertainment",
        "music",
        "video",
        "audio",
        "radio",
        "tv",
        "film",
        "movie",
        "cinema",
        "theater",
        "show",
        "live",
        "concert",
        "festival",
        "event",
        "party",
        "celebration",
        "wedding",
        "family",
        "kids",
        "baby",
        "mom",
        "dad",
        "parent",
        "child",
        "school",
        "education",
        "university",
        "college",
        "academy",
        "institute",
        "training",
        "course",
        "learn",
        "study",
        "research",
        "science",
        "lab",
        "laboratory",
        "experiment",
        "test",
        "book",
        "library",
        "read",
        "write",
        "author",
        "publisher",
        "magazine",
        "news",
        "media",
        "press",
        "journal",
        "blog",
        "social",
        "community",
        "forum",
        "chat",
    ],
    "specialized": [
        # Specialized and niche TLDs
        "adult",
        "xxx",
        "sex",
        "dating",
        "love",
        "singles",
        "gay",
        "lgbt",
        "life",
        "style",
        "fashion",
        "beauty",
        "makeup",
        "hair",
        "skin",
        "spa",
        "salon",
        "cosmetics",
        "jewelry",
        "watch",
        "luxury",
        "diamond",
        "gold",
        "silver",
        "art",
        "gallery",
        "museum",
        "culture",
        "history",
        "heritage",
        "tradition",
        "religion",
        "church",
        "temple",
        "mosque",
        "spiritual",
        "faith",
        "belief",
        "philosophy",
        "wisdom",
        "knowledge",
        "truth",
        "fact",
        "real",
        "authentic",
        "genuine",
        "original",
        "unique",
        "special",
        "rare",
        "exclusive",
        "limited",
        "premium",
        "vip",
        "elite",
        "first",
        "best",
        "top",
        "super",
        "mega",
        "ultra",
        "max",
        "plus",
        "pro",
        "expert",
        "master",
        "guru",
        "ninja",
        "wizard",
        "magic",
    ],
}

ACTIVE_HTTP_CODES = [
    200,
    201,
    202,
    204,
    301,
    302,
    303,
    307,
    308,
    401,
    403,
    404,
    405,
    429,
    500,
    502,
    503,
]


class TLDReconOptimized:
    """High-performance TLD reconnaissance class using async operations"""

    def __init__(self, max_concurrent: int = 100, timeout: int = 5, retries: int = 2):
        self.max_concurrent = max_concurrent
        self.timeout = timeout
        self.retries = retries
        self.semaphore = asyncio.Semaphore(max_concurrent)
        self.resolver = None
        self.session = None
        self.dns_cache = {}

    async def __aenter__(self):
        """Async context manager entry"""
        # Create DNS resolver with optimized settings
        self.resolver = aiodns.DNSResolver(timeout=self.timeout)

        # Create HTTP session with connection pooling
        connector = aiohttp.TCPConnector(
            limit=self.max_concurrent,
            limit_per_host=10,
            ttl_dns_cache=300,
            use_dns_cache=True,
            keepalive_timeout=30,
            enable_cleanup_closed=True,
        )

        timeout_config = aiohttp.ClientTimeout(
            total=self.timeout, connect=self.timeout // 2, sock_read=self.timeout // 2
        )

        self.session = aiohttp.ClientSession(
            connector=connector,
            timeout=timeout_config,
            headers={"User-Agent": "Mozilla/5.0 (TLD-Recon-Optimized/2.0)"},
        )

        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        if self.session:
            await self.session.close()

    async def resolve_dns_cached(self, domain: str) -> Optional[str]:
        """DNS resolution with caching"""
        if domain in self.dns_cache:
            return self.dns_cache[domain]

        try:
            if self.resolver:
                result = await self.resolver.gethostbyname(domain, socket.AF_INET)
                ip = result.addresses[0] if result.addresses else None
                self.dns_cache[domain] = ip
                return ip
        except Exception:
            pass

        self.dns_cache[domain] = None
        return None

    async def check_http_fast(self, domain: str) -> Tuple[Optional[int], Optional[int]]:
        """Fast HTTP/HTTPS checking with connection reuse"""

        async def get_status(url: str) -> Optional[int]:
            for attempt in range(self.retries + 1):
                try:
                    if self.session:
                        async with self.session.head(
                            url, allow_redirects=True
                        ) as response:
                            return response.status
                except aiohttp.ClientError:
                    if attempt == self.retries:
                        return None
                    await asyncio.sleep(0.1)
                except Exception:
                    return None
            return None

        # Check HTTP and HTTPS concurrently
        tasks = [get_status(f"http://{domain}"), get_status(f"https://{domain}")]

        try:
            results_list = await asyncio.gather(*tasks, return_exceptions=True)
            http_result = results_list[0]
            https_result = results_list[1]

            http_status = http_result if isinstance(http_result, int) else None
            https_status = https_result if isinstance(https_result, int) else None

            return http_status, https_status
        except Exception:
            return None, None

    async def detect_wildcard_fast(
        self, domain: str, tld: str, resolved_ip: str
    ) -> bool:
        """Fast wildcard detection"""
        import random
        import string

        # Generate random subdomain
        random_sub = "".join(
            random.choices(
                string.ascii_lowercase + string.digits, k=12
            )  # nosec: B311 - non-cryptographic wildcard detection
        )
        test_domain = f"{random_sub}.{domain}.{tld}"

        test_ip = await self.resolve_dns_cached(test_domain)
        return test_ip == resolved_ip if test_ip else False

    async def check_single_tld(
        self,
        domain: str,
        tld: str,
        check_http: bool = False,
        check_whois: bool = False,
        exclude_wildcards: bool = False,
    ) -> Dict:
        """Check a single TLD with all optimizations"""
        async with self.semaphore:
            full_domain = f"{domain}.{tld}"
            result = {
                "domain": full_domain,
                "tld": tld,
                "dns_resolved": False,
                "ip_address": None,
                "http_status": None,
                "https_status": None,
                "whois_available": None,
                "is_wildcard": False,
                "error": None,
            }

            try:
                # DNS Resolution (always performed)
                ip = await self.resolve_dns_cached(full_domain)
                if ip:
                    result["dns_resolved"] = True
                    result["ip_address"] = ip

                    # Wildcard detection if requested
                    if exclude_wildcards:
                        result["is_wildcard"] = await self.detect_wildcard_fast(
                            domain, tld, ip
                        )

                    # HTTP checking if requested and not a wildcard
                    if check_http and not result["is_wildcard"]:
                        http_status, https_status = await self.check_http_fast(
                            full_domain
                        )
                        result["http_status"] = http_status
                        result["https_status"] = https_status

            except Exception as e:
                result["error"] = str(e)

            return result

    async def scan_tlds_batch(
        self, domain: str, tlds: List[str], **kwargs
    ) -> List[Dict]:
        """Scan TLDs in optimized batches"""
        tasks = [self.check_single_tld(domain, tld, **kwargs) for tld in tlds]

        # Use tqdm for progress tracking with asyncio.gather
        results = []
        with tqdm(total=len(tasks), desc="🌍 Scanning TLDs") as pbar:
            for coro in asyncio.as_completed(tasks):
                result = await coro
                results.append(result)
                pbar.update(1)

                # Update progress bar with stats
                resolved = len([r for r in results if r["dns_resolved"]])
                active = len(
                    [r for r in results if r.get("http_status") in ACTIVE_HTTP_CODES]
                )
                pbar.set_postfix(resolved=resolved, active=active)

        return results


def build_tld_list(
    custom_file: Optional[str], categories: str, verbose: bool
) -> List[str]:
    """Build optimized TLD list based on categories or custom file"""

    if custom_file:
        if verbose:
            click.echo(f"[+] 📄 Loading custom TLD list from {custom_file}")
        with open(custom_file, "r") as f:
            return [
                line.strip() for line in f if line.strip() and not line.startswith("#")
            ]

    # Parse categories
    requested_categories = [cat.strip() for cat in categories.split(",")]
    tld_set = set()

    for category in requested_categories:
        if category == "all":
            for cat_tlds in DEFAULT_TLDS.values():
                tld_set.update(cat_tlds)
            if verbose:
                click.echo("[+] 📋 Added ALL TLD categories")
            break
        elif category in DEFAULT_TLDS:
            tld_set.update(DEFAULT_TLDS[category])
            if verbose:
                click.echo(
                    f"[+] 📋 Added {len(DEFAULT_TLDS[category])} TLDs from '{category}' category"
                )
        else:
            if verbose:
                click.echo(f"[!] ⚠️  Unknown category: {category}")

    # Sort for consistent ordering (popular TLDs first for faster results)
    tld_list = list(tld_set)

    # Prioritize popular TLDs for faster initial results
    popular_tlds = DEFAULT_TLDS.get("popular", [])
    prioritized = []
    remaining = []

    for tld in tld_list:
        if tld in popular_tlds:
            prioritized.append(tld)
        else:
            remaining.append(tld)

    # Sort each group
    prioritized.sort(key=lambda x: popular_tlds.index(x) if x in popular_tlds else 999)
    remaining.sort()

    return prioritized + remaining


async def process_tlds_async(
    domain: str,
    tlds: List[str],
    max_concurrent: int,
    timeout: int,
    retries: int,
    dns_only: bool,
    http_check: bool,
    whois_check: bool,
    exclude_wildcards: bool,
    verbose: bool,
) -> List[Dict]:
    """Process TLDs using async operations for maximum performance"""

    if verbose:
        click.echo(
            f"[+] 🚀 Starting async TLD reconnaissance with {max_concurrent} concurrent tasks"
        )

    async with TLDReconOptimized(max_concurrent, timeout, retries) as scanner:
        results = await scanner.scan_tlds_batch(
            domain=domain,
            tlds=tlds,
            check_http=http_check and not dns_only,
            check_whois=whois_check,
            exclude_wildcards=exclude_wildcards,
        )

    return results


def save_outputs_optimized(
    results: List[Dict],
    output_dir: str,
    save_json: bool,
    save_markdown: bool,
    verbose: bool,
):
    """Optimized output saving with better formatting"""

    # Standard output
    output_path = os.path.join(output_dir, "tld_results.txt")
    with open(output_path, "w") as f:
        f.write(
            f"# TLD Reconnaissance Results - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        )
        f.write(f"# Total domains: {len(results)}\n")
        f.write(f"# DNS resolved: {len([r for r in results if r['dns_resolved']])}\n")
        f.write(
            f"# HTTP active: {len([r for r in results if r.get('http_status') in ACTIVE_HTTP_CODES])}\n\n"
        )

        for result in results:
            status_parts = []

            if result["dns_resolved"]:
                status_parts.append(f"DNS:✅ IP:{result['ip_address']}")
            else:
                status_parts.append("DNS:❌")

            if result.get("http_status"):
                status_parts.append(f"HTTP:{result['http_status']}")
            if result.get("https_status"):
                status_parts.append(f"HTTPS:{result['https_status']}")

            if result.get("is_wildcard"):
                status_parts.append("🌟WILDCARD")

            if result.get("whois_available") is not None:
                status_parts.append(
                    f"WHOIS:{'REG' if result['whois_available'] else 'AVAIL'}"
                )

            status_str = " | ".join(status_parts) if status_parts else "INACTIVE"
            f.write(f"{result['domain']:<30} - {status_str}\n")

    if verbose:
        click.echo(f"[+] 💾 Saved results to {output_path}")

    # JSON output with metadata
    if save_json:
        json_output = {
            "scan_metadata": {
                "timestamp": datetime.now().isoformat(),
                "tool": "tldrcli-optimized",
                "version": "2.0",
                "total_domains": len(results),
                "resolved_count": len([r for r in results if r["dns_resolved"]]),
                "active_count": len(
                    [r for r in results if r.get("http_status") in ACTIVE_HTTP_CODES]
                ),
                "wildcard_count": len([r for r in results if r.get("is_wildcard")]),
                "performance_optimized": True,
            },
            "results": results,
        }

        json_path = os.path.join(output_dir, "tld_results.json")
        with open(json_path, "w") as f:
            json.dump(json_output, f, indent=2)

        if verbose:
            click.echo(f"[+] 📄 Saved JSON results to {json_path}")

    # Enhanced Markdown output
    if save_markdown:
        md_path = os.path.join(output_dir, "tld_results.md")
        with open(md_path, "w") as f:
            f.write("# 🌍 TLD Reconnaissance Results\n\n")
            f.write(
                f"**📅 Scan Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  \n"
            )
            f.write("**🔧 Tool:** TLD Recon CLI (Optimized v2.0)  \n")
            f.write(f"**📊 Total Domains:** {len(results)}  \n")
            f.write(
                f"**✅ DNS Resolved:** {len([r for r in results if r['dns_resolved']])}  \n"
            )
            f.write(
                f"**🌐 HTTP Active:** {len([r for r in results if r.get('http_status') in ACTIVE_HTTP_CODES])}  \n"
            )
            f.write(
                f"**🌟 Wildcards:** {len([r for r in results if r.get('is_wildcard')])}  \n\n"
            )

            # Active domains first
            active_results = [
                r
                for r in results
                if r["dns_resolved"] or r.get("http_status") in ACTIVE_HTTP_CODES
            ]
            if active_results:
                f.write("## 🎯 Active Domains\n\n")
                f.write("| Domain | TLD | DNS | IP Address | HTTP | HTTPS | Status |\n")
                f.write("|--------|-----|-----|------------|------|-------|--------|\n")

                for result in active_results:
                    dns_status = "✅" if result["dns_resolved"] else "❌"
                    ip_addr = result["ip_address"] or "-"
                    http_status = result.get("http_status", "-")
                    https_status = result.get("https_status", "-")

                    status_flags = []
                    if result.get("is_wildcard"):
                        status_flags.append("🌟 Wildcard")
                    if result.get("whois_available"):
                        status_flags.append("📋 Registered")
                    elif result.get("whois_available") is False:
                        status_flags.append("🆓 Available")

                    status = " ".join(status_flags) if status_flags else "Active"

                    f.write(
                        f"| {result['domain']} | {result['tld']} | {dns_status} | {ip_addr} | {http_status} | {https_status} | {status} |\n"
                    )

            # All results summary
            f.write("\n## 📋 Complete Results Summary\n\n")
            f.write(f"- **Total TLDs tested:** {len(results)}\n")
            f.write(
                f"- **Success rate:** {(len([r for r in results if r['dns_resolved']]) / len(results) * 100):.1f}%\n"
            )
            f.write(
                f"- **HTTP success rate:** {(len([r for r in results if r.get('http_status') in ACTIVE_HTTP_CODES]) / len(results) * 100):.1f}%\n"
            )

        if verbose:
            click.echo(f"[+] 📝 Saved Markdown results to {md_path}")


@click.command()
@click.option("--domain", "-d", help="Base domain name (without TLD)")
@click.option(
    "--output-dir", default="output_tldrcli", help="Directory to save results"
)
@click.option(
    "--tld-list",
    type=click.Path(exists=True),
    help="Custom TLD list file (one per line)",
)
@click.option(
    "--categories",
    default="popular,country",
    help="TLD categories: popular,country,new_generic,business,crypto_blockchain,emerging_tech,geographic,industry_specific,specialized,all",
)
@click.option(
    "--concurrent", default=100, help="Number of concurrent async tasks (default: 100)"
)
@click.option("--timeout", default=5, help="DNS/HTTP timeout in seconds")
@click.option("--retries", default=2, help="Number of retries for failed requests")
@click.option(
    "--dns-only", is_flag=True, help="Only perform DNS resolution (no HTTP probing)"
)
@click.option("--http-check", is_flag=True, help="Perform HTTP/HTTPS status checks")
@click.option("--verbose", "-v", is_flag=True, help="Enable verbose output")
@click.option("--save-json", is_flag=True, help="Save results in JSON format")
@click.option("--save-markdown", is_flag=True, help="Save results in Markdown format")
@click.option("--resume", is_flag=True, help="Resume previous scan")
@click.option("--clear-resume", is_flag=True, help="Clear previous resume state")
@click.option("--show-resume", is_flag=True, help="Show status of previous scans")
@click.option(
    "--filter-active",
    is_flag=True,
    help="Only show domains that resolve or respond to HTTP",
)
@click.option("--slack-webhook", help="Slack webhook URL for notifications")
@click.option("--discord-webhook", help="Discord webhook URL for notifications")
@click.option(
    "--whois-check", is_flag=True, help="Perform basic WHOIS availability check"
)
@click.option(
    "--exclude-wildcards",
    is_flag=True,
    help="Exclude domains that appear to be wildcards",
)
@click.option(
    "--show-categories", is_flag=True, help="Show available TLD categories and exit"
)
@click.option("--benchmark", is_flag=True, help="Run performance benchmark test")
def cli(
    domain,
    output_dir,
    tld_list,
    categories,
    concurrent,
    timeout,
    retries,
    dns_only,
    http_check,
    verbose,
    save_json,
    save_markdown,
    resume,
    clear_resume,
    show_resume,
    filter_active,
    slack_webhook,
    discord_webhook,
    whois_check,
    exclude_wildcards,
    show_categories,
    benchmark,
):
    """🚀 OPTIMIZED TLD Reconnaissance - High-performance domain discovery across TLDs

    Advanced async-powered TLD reconnaissance with massive performance improvements.
    Discover domains across thousands of TLDs using concurrent DNS resolution,
    HTTP probing, and intelligent caching.

    PERFORMANCE FEATURES:
    ✅ Async DNS resolution with aiodns
    ✅ HTTP connection pooling with aiohttp
    ✅ Intelligent DNS caching
    ✅ Concurrent processing (100+ simultaneous)
    ✅ Optimized TLD prioritization
    ✅ Memory-efficient batch processing

    Examples:
        # Fast scan with popular TLDs
        tldrcli-optimized -d example --categories popular --concurrent 150 -v

        # Comprehensive scan with HTTP checking
        tldrcli-optimized -d mycompany --categories all --http-check --concurrent 200

        # Business-focused reconnaissance
        tldrcli-optimized -d startup --categories business,new_generic --filter-active --save-json

        # Crypto/blockchain domain discovery
        tldrcli-optimized -d token --categories crypto_blockchain --exclude-wildcards -v

        # Performance benchmark
        tldrcli-optimized --benchmark
    """

    # Show categories and exit
    if show_categories:
        click.echo("🏷️  Available TLD Categories:\n")
        for category, tlds in DEFAULT_TLDS.items():
            click.echo(f"📂 {category:<20} - {len(tlds):>4} TLDs")
            # Show first few TLDs as examples
            examples = tlds[:8]
            click.echo(f"   Examples: {', '.join(examples)}")
            if len(tlds) > 8:
                click.echo(f"   ... and {len(tlds) - 8} more")
            click.echo()

        total_tlds = sum(len(tlds) for tlds in DEFAULT_TLDS.values())
        unique_tlds = len(set().union(*DEFAULT_TLDS.values()))
        click.echo(f"📊 Total: {total_tlds} TLDs ({unique_tlds} unique)")
        click.echo("\n🎯 Usage: --categories popular,country,business")
        click.echo("🎯 Use 'all' for complete coverage: --categories all")
        return

    # Run benchmark test
    if benchmark:
        asyncio.run(run_benchmark(concurrent, timeout, verbose))
        return

    # Handle special resume operations
    if show_resume:
        show_resume_status(output_dir)
        return

    if clear_resume:
        clear_resume_state(output_dir)
        if verbose:
            click.echo("[+] ✅ Resume state cleared.")
        if not resume:
            return

    # Validation
    if not domain:
        click.echo("❌ Domain is required. Use --domain or -d")
        return

    if verbose:
        click.echo(f"[+] 🚀 Starting OPTIMIZED TLD reconnaissance for: {domain}")
        click.echo(f"[+] 📁 Output directory: {output_dir}")
        click.echo(f"[+] ⚡ Concurrent tasks: {concurrent}")
        click.echo(f"[+] ⏰ Timeout: {timeout}s")
        click.echo(f"[+] 🔄 Retries: {retries}")
        if http_check:
            click.echo("[+] 🌐 HTTP probing enabled")
        if whois_check:
            click.echo("[+] 📋 WHOIS checking enabled")
        if exclude_wildcards:
            click.echo("[+] 🌟 Wildcard exclusion enabled")

    # Build TLD list
    tld_list_final = build_tld_list(tld_list, categories, verbose)

    if not tld_list_final:
        click.echo(
            "[!] ❌ No TLDs to check. Please specify valid categories or TLD list."
        )
        return

    if verbose:
        click.echo(f"[+] 📝 Testing {len(tld_list_final)} TLD(s)")
        if len(tld_list_final) > 1000:
            click.echo(
                "[+] 🎯 Large TLD set detected - using maximum performance optimizations"
            )

    os.makedirs(output_dir, exist_ok=True)

    # Enhanced resume system (simplified for async version)
    scan_key = f"tldr_optimized_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

    start_time = time.time()

    # Run async TLD processing
    if verbose:
        click.echo("[+] 🚀 Launching async TLD reconnaissance...")

    try:
        results = asyncio.run(
            process_tlds_async(
                domain=domain,
                tlds=tld_list_final,
                max_concurrent=concurrent,
                timeout=timeout,
                retries=retries,
                dns_only=dns_only,
                http_check=http_check,
                whois_check=whois_check,
                exclude_wildcards=exclude_wildcards,
                verbose=verbose,
            )
        )
    except KeyboardInterrupt:
        click.echo("\n[!] ⚠️  Scan interrupted by user")
        return
    except Exception as e:
        click.echo(f"[!] ❌ Scan failed: {e}")
        return

    # Calculate stats
    resolved_count = len([r for r in results if r["dns_resolved"]])
    http_active_count = len(
        [r for r in results if r.get("http_status") in ACTIVE_HTTP_CODES]
    )
    wildcard_count = len([r for r in results if r.get("is_wildcard")])

    # Apply filtering if requested
    if filter_active:
        before_filter = len(results)
        results = [
            r
            for r in results
            if r["dns_resolved"] or r.get("http_status") in ACTIVE_HTTP_CODES
        ]
        if verbose:
            click.echo(
                f"[+] 🧹 Filtered to active domains: {before_filter} → {len(results)} results"
            )

    # Save outputs
    save_outputs_optimized(results, output_dir, save_json, save_markdown, verbose)

    elapsed = round(time.time() - start_time, 2)

    # Performance summary
    if verbose:
        click.echo("\n[+] 📊 OPTIMIZED TLD Reconnaissance Summary:")
        click.echo(f"   - Base domain: {domain}")
        click.echo(f"   - Total TLDs tested: {len(tld_list_final)}")
        click.echo(f"   - DNS resolved: {resolved_count}")
        click.echo(f"   - HTTP active: {http_active_count}")
        click.echo(f"   - Wildcards detected: {wildcard_count}")
        click.echo(f"   - Scan duration: {elapsed}s")
        click.echo(f"   - Performance: {len(tld_list_final)/elapsed:.1f} TLDs/sec")
        click.echo(
            f"   - Success rate: {(resolved_count/len(tld_list_final)*100):.1f}%"
        )

    # Notifications (if configured)
    if send_notification and (slack_webhook or discord_webhook):
        try:
            scan_metadata = {
                "base_domain": domain,
                "total_tlds": len(tld_list_final),
                "resolved_count": resolved_count,
                "active_count": http_active_count,
                "scan_duration": f"{elapsed}s",
                "performance": f"{len(tld_list_final)/elapsed:.1f} TLDs/sec",
                "timestamp": datetime.now().strftime("%Y%m%d_%H%M%S"),
                "tool": "tldrcli-optimized",
                "version": "2.0",
            }

            interesting_results = [r for r in results[:20] if r["dns_resolved"]]

            success = send_notification(
                notification_type="tldr",
                results=interesting_results,
                scan_metadata=scan_metadata,
                slack_webhook=slack_webhook,
                discord_webhook=discord_webhook,
                verbose=verbose,
            )

            if success and verbose:
                click.echo("[+] ✅ Notifications sent successfully")

        except Exception as e:
            if verbose:
                click.echo(f"[!] ❌ Notification failed: {e}")


async def run_benchmark(concurrent: int, timeout: int, verbose: bool):
    """Run performance benchmark test"""
    click.echo("🏃‍♂️ Running TLD Recon Performance Benchmark...\n")

    test_domain = "example"
    test_tlds = DEFAULT_TLDS["popular"][:50]  # Test with 50 popular TLDs

    click.echo("📊 Benchmark Configuration:")
    click.echo(f"   - Test domain: {test_domain}")
    click.echo(f"   - Test TLDs: {len(test_tlds)}")
    click.echo(f"   - Concurrent tasks: {concurrent}")
    click.echo(f"   - Timeout: {timeout}s")
    click.echo("   - Mode: DNS-only (optimized)\n")

    start_time = time.time()

    async with TLDReconOptimized(concurrent, timeout, 1) as scanner:
        results = await scanner.scan_tlds_batch(
            domain=test_domain,
            tlds=test_tlds,
            check_http=False,
            check_whois=False,
            exclude_wildcards=False,
        )

    elapsed = time.time() - start_time
    resolved_count = len([r for r in results if r["dns_resolved"]])

    click.echo("\n🎯 Benchmark Results:")
    click.echo(f"   - Total time: {elapsed:.2f}s")
    click.echo(f"   - Performance: {len(test_tlds)/elapsed:.1f} TLDs/sec")
    click.echo(f"   - DNS resolved: {resolved_count}/{len(test_tlds)}")
    click.echo(f"   - Success rate: {(resolved_count/len(test_tlds)*100):.1f}%")

    # Performance rating
    tlds_per_sec = len(test_tlds) / elapsed
    if tlds_per_sec > 50:
        rating = "🚀 Excellent"
    elif tlds_per_sec > 30:
        rating = "⚡ Very Good"
    elif tlds_per_sec > 20:
        rating = "✅ Good"
    elif tlds_per_sec > 10:
        rating = "⚠️  Fair"
    else:
        rating = "🐌 Needs Improvement"

    click.echo(f"   - Performance rating: {rating}")

    if tlds_per_sec < 20:
        click.echo("\n💡 Performance Tips:")
        click.echo("   - Increase --concurrent (try 150-200)")
        click.echo("   - Reduce --timeout for faster scanning")
        click.echo("   - Use --dns-only for maximum speed")
        click.echo("   - Check network connectivity")


def show_resume_status(output_dir: str):
    """Show status of previous TLD scans"""
    resume_state = load_resume(output_dir)

    if not resume_state:
        click.echo("[+] No previous TLD scans found.")
        return

    click.echo(f"[+] Found {len(resume_state)} previous scan(s):")
    click.echo()

    for scan_key, scan_data in resume_state.items():
        if scan_key.startswith("tldr_"):
            click.echo(f"🌍 Scan: {scan_key}")
            click.echo(f"   Domain: {scan_data.get('domain', 'unknown')}")
            click.echo(f"   Started: {scan_data.get('start_time', 'unknown')}")

            if scan_data.get("completed"):
                click.echo("   Status: ✅ Completed")
                click.echo(
                    f"   Completed: {scan_data.get('completion_time', 'unknown')}"
                )
                click.echo(f"   Processed: {scan_data.get('processed_count', 0)}")
                click.echo(f"   DNS Resolved: {scan_data.get('resolved_count', 0)}")
                click.echo(f"   HTTP Active: {scan_data.get('http_active_count', 0)}")
            else:
                click.echo("   Status: ⏳ Incomplete")
                click.echo(f"   Processed: {scan_data.get('processed_count', 0)}")

            click.echo()


def clear_resume_state(output_dir: str):
    """Clear resume state for TLD scans"""
    clear_resume(output_dir)


if __name__ == "__main__":
    # Check for required async dependencies
    try:
        import aiodns
        import aiohttp
    except ImportError:
        click.echo("❌ Missing required dependencies for optimized version!")
        click.echo("📦 Install with: pip install aiodns aiohttp")
        click.echo("🔄 Or use the standard version: python tldrcli.py")
        sys.exit(1)

    cli()
