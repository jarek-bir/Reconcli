#!/usr/bin/env python3

import concurrent.futures
import json
import os
import shutil
import socket
import time
import hashlib
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
from pathlib import Path

import click
from tqdm import tqdm

# Import notifications
try:
    from reconcli.utils.notifications import NotificationManager, send_notification
except ImportError:
    send_notification = None
    NotificationManager = None


def find_executable(name):
    """Helper function to find executable path securely"""
    path = shutil.which(name)
    if path is None:
        raise FileNotFoundError(f"Executable '{name}' not found in PATH")
    return path


# Import resume utilities
try:
    from reconcli.utils.resume import clear_resume, load_resume, save_resume_state
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


class TLDRCacheManager:
    """Intelligent caching system for TLD enumeration and DNS lookup results with performance optimization."""

    def __init__(self, cache_dir: str = "tldr_cache", max_age_hours: int = 24):
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.max_age = timedelta(hours=max_age_hours)
        self.cache_index_file = self.cache_dir / "tldr_cache_index.json"
        self.cache_index = self._load_cache_index()
        self.hits = 0
        self.misses = 0

    def _load_cache_index(self) -> dict:
        """Load cache index from disk."""
        if self.cache_index_file.exists():
            try:
                with open(self.cache_index_file, "r") as f:
                    return json.load(f)
            except (json.JSONDecodeError, IOError):
                return {}
        return {}

    def _save_cache_index(self):
        """Save cache index to disk."""
        try:
            with open(self.cache_index_file, "w") as f:
                json.dump(self.cache_index, f, indent=2)
        except IOError as e:
            click.echo(f"Warning: Failed to save cache index: {e}", err=True)

    def _generate_cache_key(
        self,
        domain: str,
        tlds: list,
        dns_servers: list = None,
        operation: str = "enumerate",
        **kwargs,
    ) -> str:
        """Generate a unique cache key for TLD enumeration parameters."""
        # Create deterministic key from enumeration parameters
        key_data = {
            "domain": domain,
            "tlds": sorted(tlds) if tlds else [],
            "dns_servers": sorted(dns_servers) if dns_servers else [],
            "operation": operation,
            "kwargs": sorted(kwargs.items()),
        }

        key_string = json.dumps(key_data, sort_keys=True)
        return hashlib.sha256(key_string.encode()).hexdigest()

    def _is_cache_valid(self, timestamp: str) -> bool:
        """Check if cache entry is still valid based on timestamp."""
        try:
            cache_time = datetime.fromisoformat(timestamp)
            return datetime.now() - cache_time < self.max_age
        except (ValueError, TypeError):
            return False

    def get_cached_result(
        self,
        domain: str,
        tlds: list,
        dns_servers: list = None,
        operation: str = "enumerate",
        **kwargs,
    ) -> dict:
        """Retrieve cached TLD enumeration results if available and valid."""
        cache_key = self._generate_cache_key(
            domain, tlds, dns_servers, operation, **kwargs
        )

        if cache_key in self.cache_index:
            cache_entry = self.cache_index[cache_key]
            if self._is_cache_valid(cache_entry["timestamp"]):
                cache_file = self.cache_dir / f"{cache_key}.json"
                if cache_file.exists():
                    try:
                        with open(cache_file, "r") as f:
                            result = json.load(f)
                        self.hits += 1
                        click.echo(
                            f"✅ Cache HIT for TLD enumeration: {domain} ({len(tlds)} TLDs)",
                            err=True,
                        )
                        return result
                    except (json.JSONDecodeError, IOError):
                        # Cache file corrupted, remove from index
                        del self.cache_index[cache_key]
                        self._save_cache_index()

        self.misses += 1
        click.echo(
            f"❌ Cache MISS for TLD enumeration: {domain} ({len(tlds)} TLDs)", err=True
        )
        return None

    def save_result(
        self,
        domain: str,
        tlds: list,
        result: dict,
        dns_servers: list = None,
        operation: str = "enumerate",
        **kwargs,
    ):
        """Save TLD enumeration results to cache."""
        cache_key = self._generate_cache_key(
            domain, tlds, dns_servers, operation, **kwargs
        )

        # Add metadata to result
        cached_result = {
            "metadata": {
                "domain": domain,
                "operation": operation,
                "tlds_count": len(tlds) if tlds else 0,
                "dns_servers_count": len(dns_servers) if dns_servers else 0,
                "timestamp": datetime.now().isoformat(),
                "cache_key": cache_key,
            },
            "result": result,
        }

        # Save result to file
        cache_file = self.cache_dir / f"{cache_key}.json"
        try:
            with open(cache_file, "w") as f:
                json.dump(cached_result, f, indent=2)

            # Update cache index
            self.cache_index[cache_key] = {
                "domain": domain,
                "timestamp": datetime.now().isoformat(),
                "file": f"{cache_key}.json",
                "tlds_count": len(tlds) if tlds else 0,
                "operation": operation,
            }
            self._save_cache_index()

        except IOError as e:
            click.echo(f"Warning: Failed to save cache: {e}", err=True)

    def clear_cache(self) -> int:
        """Clear all cached results and return count of removed files."""
        removed_count = 0

        # Remove cache files
        for cache_file in self.cache_dir.glob("*.json"):
            if cache_file.name != "tldr_cache_index.json":
                try:
                    cache_file.unlink()
                    removed_count += 1
                except OSError:
                    pass

        # Clear cache index
        self.cache_index.clear()
        self._save_cache_index()

        return removed_count

    def get_cache_stats(self) -> dict:
        """Get cache performance statistics."""
        total_requests = self.hits + self.misses
        hit_rate = (self.hits / total_requests * 100) if total_requests > 0 else 0

        # Count cache files
        cache_files = len(
            [
                f
                for f in self.cache_dir.glob("*.json")
                if f.name != "tldr_cache_index.json"
            ]
        )

        # Calculate cache size
        cache_size = sum(f.stat().st_size for f in self.cache_dir.glob("*.json")) / (
            1024 * 1024
        )

        return {
            "total_requests": total_requests,
            "cache_hits": self.hits,
            "cache_misses": self.misses,
            "hit_rate": round(hit_rate, 2),
            "cached_results": cache_files,
            "cache_size_mb": round(cache_size, 2),
            "cache_dir": str(self.cache_dir),
        }

    def cleanup_expired_cache(self) -> int:
        """Remove expired cache entries and return count of removed files."""
        removed_count = 0
        current_time = datetime.now()

        expired_keys = []
        for cache_key, cache_entry in self.cache_index.items():
            if not self._is_cache_valid(cache_entry["timestamp"]):
                expired_keys.append(cache_key)

        # Remove expired entries
        for cache_key in expired_keys:
            cache_file = self.cache_dir / f"{cache_key}.json"
            try:
                if cache_file.exists():
                    cache_file.unlink()
                    removed_count += 1
                del self.cache_index[cache_key]
            except OSError:
                pass

        if removed_count > 0:
            self._save_cache_index()

        return removed_count


# SUPER COMPREHENSIVE TLD lists for different categories - MASSIVE EXPANSION
DEFAULT_TLDS = {
    "popular": [
        # Classic TLDs
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
        "xxx",
        "post",
        "arpa",
        "coop",
        "museum",
        "aero",
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
        "life",
        "love",
        "today",
        "now",
        "cool",
        "fun",
        "run",
        "fit",
        "win",
        "best",
        "new",
        "hot",
        "plus",
        "max",
        "ultra",
        "super",
        "mega",
        "micro",
        "mini",
        "big",
        "huge",
        "fast",
        "quick",
        "instant",
        "smart",
        "easy",
        "simple",
        "free",
    ],
    "country": [
        # Europe (complete list)
        "ad",
        "al",
        "at",
        "ba",
        "be",
        "bg",
        "by",
        "ch",
        "cy",
        "cz",
        "de",
        "dk",
        "ee",
        "es",
        "fi",
        "fo",
        "fr",
        "gb",
        "gi",
        "gl",
        "gr",
        "hr",
        "hu",
        "ie",
        "im",
        "is",
        "it",
        "je",
        "li",
        "lt",
        "lu",
        "lv",
        "mc",
        "md",
        "me",
        "mk",
        "mt",
        "nl",
        "no",
        "pl",
        "pt",
        "ro",
        "rs",
        "ru",
        "se",
        "si",
        "sk",
        "sm",
        "ua",
        "uk",
        "va",
        "xk",
        # North America
        "us",
        "ca",
        "mx",
        "gt",
        "bz",
        "sv",
        "hn",
        "ni",
        "cr",
        "pa",
        "cu",
        "do",
        "ht",
        "jm",
        "tt",
        "bb",
        "gd",
        "lc",
        "vc",
        "ag",
        "dm",
        "kn",
        "bs",
        "pr",
        "vi",
        "ky",
        "bm",
        "tc",
        "vg",
        "ai",
        "ms",
        "gp",
        "mq",
        "bl",
        "mf",
        "pm",
        "gl",
        "as",
        "gu",
        # South America
        "ar",
        "bo",
        "br",
        "cl",
        "co",
        "ec",
        "fk",
        "gf",
        "gy",
        "pe",
        "py",
        "sr",
        "uy",
        "ve",
        "aw",
        "cw",
        "sx",
        "bq",
        "tc",
        "gp",
        "mq",
        "pf",
        "nc",
        "wf",
        "pm",
        # Asia (complete list)
        "af",
        "am",
        "az",
        "bh",
        "bd",
        "bt",
        "bn",
        "kh",
        "cn",
        "cy",
        "ge",
        "in",
        "id",
        "ir",
        "iq",
        "il",
        "jp",
        "jo",
        "kz",
        "kw",
        "kg",
        "la",
        "lb",
        "my",
        "mv",
        "mn",
        "mm",
        "np",
        "kp",
        "om",
        "pk",
        "ps",
        "ph",
        "qa",
        "sa",
        "sg",
        "kr",
        "lk",
        "sy",
        "tw",
        "tj",
        "th",
        "tl",
        "tr",
        "tm",
        "ae",
        "uz",
        "vn",
        "ye",
        "hk",
        "mo",
        # Africa (complete list)
        "dz",
        "ao",
        "bj",
        "bw",
        "bf",
        "bi",
        "cm",
        "cv",
        "cf",
        "td",
        "km",
        "cg",
        "cd",
        "ci",
        "dj",
        "eg",
        "gq",
        "er",
        "et",
        "ga",
        "gm",
        "gh",
        "gn",
        "gw",
        "ke",
        "ls",
        "lr",
        "ly",
        "mg",
        "mw",
        "ml",
        "mr",
        "mu",
        "ma",
        "mz",
        "na",
        "ne",
        "ng",
        "rw",
        "st",
        "sn",
        "sc",
        "sl",
        "so",
        "za",
        "ss",
        "sd",
        "sz",
        "tz",
        "tg",
        "tn",
        "ug",
        "zm",
        "zw",
        "eh",
        "yt",
        "re",
        "sh",
        "io",
        "tf",
        # Oceania (complete list)
        "au",
        "fj",
        "ki",
        "mh",
        "fm",
        "nr",
        "nz",
        "pw",
        "pg",
        "ws",
        "sb",
        "to",
        "tv",
        "vu",
        "ck",
        "nu",
        "pn",
        "tk",
        "nf",
        "cx",
        "cc",
        "hm",
        "aq",
        "gs",
        "bv",
        "sj",
    ],
    "new_generic": [
        # Technology & Digital (MASSIVE expansion)
        "app",
        "dev",
        "tech",
        "cloud",
        "online",
        "site",
        "website",
        "digital",
        "web",
        "data",
        "software",
        "mobile",
        "ai",
        "bot",
        "codes",
        "computer",
        "systems",
        "network",
        "server",
        "hosting",
        "domain",
        "email",
        "chat",
        "social",
        "stream",
        "video",
        "audio",
        "media",
        "photo",
        "pics",
        "camera",
        "studio",
        "design",
        "graphics",
        "art",
        "creative",
        "maker",
        "build",
        "tools",
        "game",
        "games",
        "casino",
        "poker",
        "bet",
        "sport",
        "team",
        "play",
        "fun",
        "toys",
        "kids",
        "cyber",
        "security",
        "blockchain",
        "crypto",
        "bitcoin",
        "ethereum",
        "nft",
        "defi",
        "dao",
        "token",
        "wallet",
        "mining",
        "trading",
        "exchange",
        "fintech",
        "machine",
        "learning",
        "neural",
        "quantum",
        "robotics",
        "automation",
        "iot",
        "virtual",
        "reality",
        "augmented",
        "metaverse",
        "3d",
        "printing",
        "drone",
        # Business & Commerce (HUGE expansion)
        "store",
        "shop",
        "buy",
        "sale",
        "sales",
        "market",
        "shopping",
        "deal",
        "deals",
        "discount",
        "price",
        "money",
        "cash",
        "pay",
        "payment",
        "card",
        "credit",
        "loan",
        "bank",
        "finance",
        "invest",
        "trading",
        "forex",
        "crypto",
        "bitcoin",
        "exchange",
        "wallet",
        "rich",
        "gold",
        "diamond",
        "luxury",
        "vip",
        "premium",
        "pro",
        "expert",
        "guru",
        "coach",
        "mentor",
        "advisor",
        "consulting",
        "services",
        "agency",
        "company",
        "business",
        "corp",
        "group",
        "team",
        "office",
        "work",
        "enterprise",
        "startup",
        "ventures",
        "capital",
        "equity",
        "fund",
        "wealth",
        "asset",
        "portfolio",
        "insurance",
        "stocks",
        "bonds",
        "securities",
        "pension",
        "retirement",
        "investment",
        "broker",
        "banking",
        "financial",
        "commerce",
        "ecommerce",
        "marketplace",
        "retail",
        "wholesale",
        "distribution",
        "supply",
        "chain",
        "logistics",
        "shipping",
        "delivery",
        "courier",
        "express",
        "freight",
        # Lifestyle & Entertainment (MASSIVE)
        "life",
        "live",
        "today",
        "now",
        "love",
        "family",
        "home",
        "house",
        "garden",
        "style",
        "fashion",
        "beauty",
        "spa",
        "salon",
        "fitness",
        "gym",
        "health",
        "medical",
        "doctor",
        "clinic",
        "hospital",
        "dental",
        "vet",
        "care",
        "wellness",
        "yoga",
        "diet",
        "food",
        "recipes",
        "cooking",
        "kitchen",
        "restaurant",
        "cafe",
        "bar",
        "wine",
        "beer",
        "drink",
        "coffee",
        "tea",
        "pizza",
        "burger",
        "sushi",
        "music",
        "dance",
        "party",
        "club",
        "pub",
        "concert",
        "festival",
        "show",
        "theater",
        "cinema",
        "movie",
        "film",
        "tv",
        "radio",
        "podcast",
        "streaming",
        "entertainment",
        "celebrity",
        "star",
        "fame",
        "glamour",
        "red",
        "carpet",
        "award",
        "oscar",
        "grammy",
        "emmy",
        "golden",
        "globe",
        "cannes",
        "sundance",
        # Travel & Places (HUGE)
        "travel",
        "trip",
        "tour",
        "tours",
        "hotel",
        "hotels",
        "resort",
        "vacation",
        "holiday",
        "flights",
        "airline",
        "cruise",
        "taxi",
        "car",
        "cars",
        "auto",
        "bike",
        "motorcycles",
        "boat",
        "yacht",
        "train",
        "bus",
        "city",
        "town",
        "place",
        "map",
        "guide",
        "beach",
        "mountain",
        "park",
        "nature",
        "outdoor",
        "adventure",
        "hiking",
        "camping",
        "safari",
        "jungle",
        "desert",
        "forest",
        "ocean",
        "sea",
        "lake",
        "river",
        "island",
        "paradise",
        "tropical",
        "exotic",
        "luxury",
        "boutique",
        "spa",
        "wellness",
        "retreat",
        "zen",
        "meditation",
        "backpacking",
        "hostel",
        "airbnb",
        "rental",
        "accommodation",
        "booking",
        "reservation",
        "itinerary",
        "passport",
        "visa",
        "customs",
        "airport",
        # Education & Culture (MASSIVE)
        "education",
        "school",
        "college",
        "university",
        "academy",
        "institute",
        "training",
        "course",
        "courses",
        "learn",
        "study",
        "tutor",
        "teacher",
        "student",
        "exam",
        "test",
        "book",
        "books",
        "library",
        "read",
        "wiki",
        "science",
        "research",
        "lab",
        "museum",
        "gallery",
        "art",
        "culture",
        "history",
        "heritage",
        "tradition",
        "custom",
        "folklore",
        "mythology",
        "philosophy",
        "psychology",
        "sociology",
        "anthropology",
        "archaeology",
        "literature",
        "poetry",
        "prose",
        "novel",
        "short",
        "story",
        "essay",
        "journalism",
        "newspaper",
        "magazine",
        "publication",
        "press",
        "media",
        "documentary",
        "biography",
        "autobiography",
        "memoir",
        "diary",
        "journal",
        "encyclopedia",
        "dictionary",
        "reference",
        "manual",
        "handbook",
        "guide",
        # Community & Social (HUGE)
        "community",
        "social",
        "network",
        "forum",
        "blog",
        "news",
        "media",
        "press",
        "magazine",
        "newspaper",
        "journal",
        "review",
        "rating",
        "vote",
        "poll",
        "survey",
        "feedback",
        "contact",
        "support",
        "help",
        "faq",
        "info",
        "about",
        "profile",
        "user",
        "member",
        "friend",
        "dating",
        "match",
        "meet",
        "single",
        "wedding",
        "baby",
        "mom",
        "dad",
        "pet",
        "dog",
        "cat",
        "animal",
        "farm",
        "volunteer",
        "charity",
        "foundation",
        "nonprofit",
        "donation",
        "fundraising",
        "activism",
        "cause",
        "movement",
        "campaign",
        "petition",
        "protest",
        "rally",
        "demonstration",
        "march",
        "strike",
        "boycott",
        "human",
        "rights",
        "equality",
        "justice",
        "peace",
        "freedom",
        "democracy",
        "liberty",
        "civil",
        "society",
        # Industry Specific (MASSIVE)
        "real",
        "estate",
        "property",
        "rent",
        "lease",
        "build",
        "construction",
        "repair",
        "maintenance",
        "clean",
        "security",
        "insurance",
        "legal",
        "law",
        "attorney",
        "lawyer",
        "court",
        "justice",
        "government",
        "public",
        "civil",
        "military",
        "police",
        "fire",
        "emergency",
        "rescue",
        "charity",
        "foundation",
        "church",
        "religion",
        "temple",
        "mosque",
        "synagogue",
        "faith",
        "spiritual",
        "manufacturing",
        "production",
        "factory",
        "industrial",
        "machinery",
        "equipment",
        "tools",
        "instruments",
        "components",
        "materials",
        "supplies",
        "parts",
        "automotive",
        "aerospace",
        "defense",
        "electronics",
        "semiconductor",
        "chemical",
        "pharmaceutical",
        "biotech",
        "medical",
        "devices",
        "precision",
        # Modern & Trendy (HUGE)
        "cool",
        "hot",
        "new",
        "fresh",
        "modern",
        "trendy",
        "style",
        "vogue",
        "chic",
        "sexy",
        "wow",
        "amazing",
        "awesome",
        "best",
        "top",
        "max",
        "plus",
        "ultra",
        "super",
        "mega",
        "micro",
        "mini",
        "big",
        "huge",
        "giant",
        "fast",
        "quick",
        "instant",
        "rapid",
        "speed",
        "turbo",
        "boost",
        "power",
        "energy",
        "force",
        "strong",
        "tough",
        "hard",
        "soft",
        "smooth",
        "easy",
        "simple",
        "smart",
        "clever",
        "genius",
        "bright",
        "shine",
        "glow",
        "spark",
        "flash",
        "bolt",
        "storm",
        "thunder",
        "lightning",
        "fire",
        "flame",
        "ice",
        "snow",
        "cold",
        "winter",
        "summer",
        "spring",
        "autumn",
        "sun",
        "moon",
        "star",
        "sky",
        "earth",
        "world",
        "global",
        "international",
        "worldwide",
        "universal",
        "infinite",
        "eternal",
        "forever",
        "everlasting",
        "timeless",
        "classic",
        "vintage",
        "retro",
        "antique",
        "rare",
        "unique",
        "special",
        "exclusive",
        "limited",
        "premium",
        "deluxe",
        "elite",
        "first",
        "class",
        "luxury",
    ],
    "business": [
        # Corporate Structure (EXPANDED)
        "ltd",
        "llc",
        "inc",
        "corp",
        "company",
        "co",
        "business",
        "enterprise",
        "group",
        "holdings",
        "ventures",
        "capital",
        "invest",
        "fund",
        "funds",
        "equity",
        "finance",
        "financial",
        "bank",
        "banking",
        "credit",
        "loan",
        "mortgage",
        "insurance",
        "trading",
        "securities",
        "mutual",
        "pension",
        "trust",
        "asset",
        "wealth",
        "management",
        "advisory",
        "consulting",
        "firm",
        "partners",
        "associates",
        "international",
        "global",
        "worldwide",
        "solutions",
        "services",
        "systems",
        "technologies",
        "innovations",
        "development",
        "research",
        "laboratory",
        # Professional Services (MASSIVE)
        "law",
        "legal",
        "attorney",
        "lawyer",
        "consulting",
        "consultant",
        "advisory",
        "advisor",
        "accountant",
        "accounting",
        "audit",
        "tax",
        "cpa",
        "marketing",
        "advertising",
        "promotion",
        "pr",
        "relations",
        "communications",
        "media",
        "publishing",
        "print",
        "design",
        "creative",
        "agency",
        "studio",
        "solutions",
        "strategy",
        "planning",
        "execution",
        "implementation",
        "optimization",
        "branding",
        "identity",
        "logo",
        "graphic",
        "visual",
        "digital",
        "social",
        "content",
        "copywriting",
        "seo",
        "sem",
        "ppc",
        "analytics",
        "research",
        # Technology & Innovation (HUGE)
        "tech",
        "technology",
        "software",
        "hardware",
        "systems",
        "solutions",
        "services",
        "support",
        "maintenance",
        "development",
        "programming",
        "coding",
        "web",
        "internet",
        "digital",
        "cyber",
        "security",
        "cloud",
        "data",
        "analytics",
        "artificial",
        "intelligence",
        "machine",
        "learning",
        "robotics",
        "automation",
        "blockchain",
        "cryptocurrency",
        "fintech",
        "edtech",
        "healthtech",
        "cleantech",
        "biotech",
        "nanotech",
        "quantum",
        "computing",
        "supercomputing",
        "networking",
        "infrastructure",
        "platform",
        "architecture",
        "framework",
        "database",
        "algorithm",
        "protocol",
        "api",
        "integration",
        "deployment",
        "migration",
        # Manufacturing & Industry (MASSIVE)
        "manufacturing",
        "production",
        "factory",
        "industrial",
        "machinery",
        "equipment",
        "tools",
        "instruments",
        "components",
        "materials",
        "supplies",
        "parts",
        "automotive",
        "aerospace",
        "defense",
        "electronics",
        "semiconductor",
        "chemical",
        "pharmaceutical",
        "biotech",
        "medical",
        "devices",
        "precision",
        "quality",
        "control",
        "testing",
        "inspection",
        "certification",
        "compliance",
        "safety",
        "standards",
        "regulations",
        "iso",
        "lean",
        "six",
        "sigma",
        "assembly",
        "packaging",
        "shipping",
        "logistics",
        "supply",
        "chain",
        # Construction & Real Estate (HUGE)
        "construction",
        "building",
        "development",
        "real",
        "estate",
        "property",
        "residential",
        "commercial",
        "industrial",
        "retail",
        "office",
        "warehouse",
        "logistics",
        "distribution",
        "supply",
        "chain",
        "transportation",
        "shipping",
        "freight",
        "cargo",
        "delivery",
        "courier",
        "express",
        "international",
        "architecture",
        "engineering",
        "design",
        "planning",
        "permits",
        "zoning",
        "contracting",
        "subcontracting",
        "renovation",
        "remodeling",
        "restoration",
        "maintenance",
        "repairs",
        "inspection",
        "appraisal",
        "surveying",
        "mapping",
        # Energy & Resources (MASSIVE)
        "energy",
        "power",
        "electric",
        "utilities",
        "gas",
        "oil",
        "petroleum",
        "renewable",
        "solar",
        "wind",
        "hydro",
        "nuclear",
        "coal",
        "mining",
        "metals",
        "steel",
        "aluminum",
        "copper",
        "gold",
        "silver",
        "commodities",
        "agriculture",
        "farming",
        "food",
        "beverage",
        "processing",
        "packaging",
        "sustainability",
        "green",
        "clean",
        "carbon",
        "neutral",
        "emission",
        "environmental",
        "recycling",
        "waste",
        "management",
        "conservation",
        "efficiency",
        "smart",
        "grid",
        "storage",
        "battery",
        "fuel",
        "cell",
        # Healthcare & Life Sciences (HUGE)
        "healthcare",
        "medical",
        "hospital",
        "clinic",
        "pharmaceutical",
        "pharma",
        "biotech",
        "life",
        "sciences",
        "research",
        "laboratory",
        "diagnostic",
        "therapeutic",
        "devices",
        "equipment",
        "supplies",
        "dental",
        "veterinary",
        "wellness",
        "fitness",
        "nutrition",
        "supplements",
        "cosmetic",
        "beauty",
        "telemedicine",
        "digital",
        "health",
        "personalized",
        "medicine",
        "genomics",
        "proteomics",
        "immunology",
        "oncology",
        "cardiology",
        "neurology",
        "psychiatry",
        "radiology",
        "pathology",
        "surgery",
        "anesthesia",
        "emergency",
        "pediatric",
        # Retail & Consumer (MASSIVE)
        "retail",
        "wholesale",
        "distribution",
        "consumer",
        "goods",
        "products",
        "brands",
        "fashion",
        "apparel",
        "clothing",
        "footwear",
        "accessories",
        "jewelry",
        "watches",
        "luxury",
        "premium",
        "discount",
        "outlet",
        "mart",
        "supermarket",
        "grocery",
        "convenience",
        "department",
        "specialty",
        "boutique",
        "ecommerce",
        "online",
        "marketplace",
        "platform",
        "shopping",
        "cart",
        "checkout",
        "payment",
        "fulfillment",
        "customer",
        "service",
        "experience",
        # Entertainment & Media (MASSIVE)
        "entertainment",
        "media",
        "broadcasting",
        "television",
        "radio",
        "music",
        "recording",
        "film",
        "movie",
        "production",
        "studio",
        "theater",
        "gaming",
        "casino",
        "resort",
        "hospitality",
        "hotel",
        "restaurant",
        "catering",
        "events",
        "wedding",
        "conference",
        "exhibition",
        "sports",
        "recreation",
        "streaming",
        "content",
        "digital",
        "platform",
        "distribution",
        "licensing",
        "intellectual",
        "property",
        "copyright",
        "trademark",
        "patent",
        "royalty",
        # Education & Training (MASSIVE)
        "education",
        "training",
        "learning",
        "development",
        "school",
        "college",
        "university",
        "institute",
        "academy",
        "certification",
        "professional",
        "corporate",
        "executive",
        "leadership",
        "management",
        "coaching",
        "mentoring",
        "skills",
        "talent",
        "human",
        "resources",
        "recruitment",
        "staffing",
        "employment",
        "online",
        "distance",
        "elearning",
        "mooc",
        "certification",
        "continuing",
        "vocational",
        "technical",
        "trade",
        "apprenticeship",
        "internship",
        "fellowship",
    ],
    "crypto_blockchain": [
        # Cryptocurrency & Blockchain (MASSIVE)
        "crypto",
        "bitcoin",
        "btc",
        "ethereum",
        "eth",
        "blockchain",
        "defi",
        "nft",
        "dao",
        "dex",
        "cefi",
        "yield",
        "stake",
        "mining",
        "wallet",
        "token",
        "coin",
        "swap",
        "bridge",
        "protocol",
        "smart",
        "contract",
        "web3",
        "metaverse",
        "gamefi",
        "altcoin",
        "stablecoin",
        "memecoin",
        "shitcoin",
        "hodl",
        "fomo",
        "fud",
        "moon",
        "lambo",
        "diamond",
        "hands",
        "paper",
        "ape",
        "bull",
        "bear",
        "whale",
        "pump",
        "dump",
        "rekt",
        "dyor",
        "not",
        "financial",
        "advice",
        "to",
        "the",
        "mars",
        "satoshi",
        "nakamoto",
        "binance",
        "coinbase",
        "kraken",
        "uniswap",
        "pancakeswap",
        "opensea",
        "metamask",
        "ledger",
        "trezor",
        "cold",
        "storage",
        "hot",
        "private",
        "public",
        "key",
        "seed",
        "phrase",
        "recovery",
        "hash",
        "proof",
        "work",
        "consensus",
        "validator",
        "node",
        "fork",
        "mainnet",
        "testnet",
        "layer",
        "scaling",
        "sidechain",
        "rollup",
        "plasma",
        "lightning",
        "atomic",
        "cross",
        "chain",
        "interoperability",
        "oracle",
        "governance",
        "treasury",
        "hedge",
        "arbitrage",
        "liquidation",
        "leverage",
        "margin",
        "futures",
        "options",
        "derivatives",
        "spot",
        "p2p",
        "peer",
        "decentralized",
        "centralized",
    ],
    "emerging_tech": [
        # AI & Machine Learning (HUGE)
        "ai",
        "artificial",
        "intelligence",
        "machine",
        "learning",
        "deep",
        "neural",
        "network",
        "algorithm",
        "model",
        "training",
        "inference",
        "prediction",
        "automation",
        "robotics",
        "drone",
        "autonomous",
        "self",
        "driving",
        "iot",
        "internet",
        "things",
        "sensor",
        "smart",
        "connected",
        "edge",
        "fog",
        "quantum",
        "computing",
        "qubit",
        "superposition",
        "entanglement",
        "virtual",
        "reality",
        "augmented",
        "mixed",
        "immersive",
        "metaverse",
        "avatar",
        "digital",
        "twin",
        "simulation",
        "3d",
        "printing",
        "additive",
        "manufacturing",
        "bioprinting",
        "nanotechnology",
        "nanoparticle",
        "molecular",
        "genetic",
        "engineering",
        "crispr",
        "gene",
        "therapy",
        "personalized",
        "medicine",
        "telemedicine",
        "wearable",
        "biometric",
        "health",
        "monitoring",
        "precision",
        "agriculture",
        "vertical",
        "farming",
        "hydroponics",
        "aquaponics",
        "sustainable",
        "renewable",
        "carbon",
        "neutral",
        "zero",
        "emission",
        "clean",
        "green",
        "circular",
        "economy",
        "chatgpt",
        "openai",
        "midjourney",
        "stable",
        "diffusion",
        "gpt",
        "llm",
        "nlp",
        "computer",
        "vision",
        "speech",
        "recognition",
        "voice",
        "assistant",
        "alexa",
        "siri",
        "google",
        "assistant",
        "chatbot",
        "conversational",
        "ai",
        "sentiment",
        "analysis",
        "recommendation",
        "engine",
        "predictive",
        "analytics",
        "big",
        "data",
    ],
    "geographic": [
        # Major Cities (MASSIVE expansion)
        "london",
        "paris",
        "berlin",
        "madrid",
        "rome",
        "amsterdam",
        "brussels",
        "vienna",
        "prague",
        "warsaw",
        "stockholm",
        "oslo",
        "copenhagen",
        "helsinki",
        "dublin",
        "lisbon",
        "athens",
        "budapest",
        "zurich",
        "geneva",
        "milan",
        "barcelona",
        "istanbul",
        "moscow",
        "kyiv",
        "bucharest",
        "sofia",
        "zagreb",
        "belgrade",
        "sarajevo",
        "skopje",
        "tirana",
        "podgorica",
        "pristina",
        "newyork",
        "losangeles",
        "chicago",
        "houston",
        "philadelphia",
        "phoenix",
        "sanantonio",
        "sandiego",
        "dallas",
        "sanjose",
        "austin",
        "jacksonville",
        "fortworth",
        "columbus",
        "charlotte",
        "sanfrancisco",
        "indianapolis",
        "seattle",
        "denver",
        "washington",
        "boston",
        "elpaso",
        "detroit",
        "nashville",
        "portland",
        "oklahoma",
        "lasvegas",
        "louisville",
        "baltimore",
        "milwaukee",
        "albuquerque",
        "tucson",
        "fresno",
        "sacramento",
        "longbeach",
        "kansas",
        "mesa",
        "virginia",
        "atlanta",
        "colorado",
        "omaha",
        "raleigh",
        "miami",
        "oakland",
        "minneapolis",
        "tulsa",
        "cleveland",
        "wichita",
        "arlington",
        "toronto",
        "montreal",
        "vancouver",
        "calgary",
        "edmonton",
        "ottawa",
        "winnipeg",
        "quebec",
        "hamilton",
        "kitchener",
        "london",
        "victoria",
        "halifax",
        "oshawa",
        "windsor",
        "saskatoon",
        "regina",
        "sherbrooke",
        "barrie",
        "kelowna",
        "abbotsford",
        "kingston",
        "sudbury",
        "trois",
        "mexico",
        "guadalajara",
        "monterrey",
        "puebla",
        "tijuana",
        "leon",
        "juarez",
        "torreon",
        "queretaro",
        "san",
        "luis",
        "potosi",
        "merida",
        "mexicali",
        "aguascalientes",
        "cuernavaca",
        "saltillo",
        "hermosillo",
        "cancun",
        "veracruz",
        "villahermosa",
        "tampico",
        "morelia",
        "reynosa",
        "tokyo",
        "osaka",
        "yokohama",
        "nagoya",
        "sapporo",
        "fukuoka",
        "kobe",
        "kawasaki",
        "kyoto",
        "saitama",
        "hiroshima",
        "sendai",
        "kitakyushu",
        "chiba",
        "sakai",
        "niigata",
        "hamamatsu",
        "okayama",
        "sagamihara",
        "kumamoto",
        "shizuoka",
        "kagoshima",
        "matsuyama",
        "hachioji",
        "utsunomiya",
        "beijing",
        "shanghai",
        "guangzhou",
        "shenzhen",
        "tianjin",
        "wuhan",
        "dongguan",
        "chengdu",
        "foshan",
        "nanjing",
        "shenyang",
        "hangzhou",
        "xian",
        "harbin",
        "suzhou",
        "qingdao",
        "dalian",
        "zhengzhou",
        "jinan",
        "kunming",
        "changchun",
        "changsha",
        "shijiazhuang",
        "hefei",
        "urumqi",
        "fuzhou",
        "wuxi",
        "zhongshan",
        "taiyuan",
        "zibo",
        "yantai",
        "guiyang",
        "mumbai",
        "delhi",
        "bangalore",
        "hyderabad",
        "ahmedabad",
        "chennai",
        "kolkata",
        "surat",
        "pune",
        "jaipur",
        "lucknow",
        "kanpur",
        "nagpur",
        "indore",
        "thane",
        "bhopal",
        "visakhapatnam",
        "pimpri",
        "patna",
        "vadodara",
        "ghaziabad",
        "ludhiana",
        "agra",
        "nashik",
        "faridabad",
        "meerut",
        "rajkot",
        "kalyan",
        "vasai",
        "varanasi",
        "srinagar",
        "aurangabad",
        "sydney",
        "melbourne",
        "brisbane",
        "perth",
        "adelaide",
        "gold",
        "coast",
        "newcastle",
        "canberra",
        "sunshine",
        "coast",
        "wollongong",
        "hobart",
        "geelong",
        "townsville",
        "cairns",
        "darwin",
        "toowoomba",
        "ballarat",
        "bendigo",
        "albury",
        "wodonga",
        "launceston",
        "mackay",
        "rockhampton",
        # Regions & States (MASSIVE)
        "california",
        "texas",
        "florida",
        "newyork",
        "pennsylvania",
        "illinois",
        "ohio",
        "georgia",
        "northcarolina",
        "michigan",
        "newjersey",
        "virginia",
        "washington",
        "arizona",
        "massachusetts",
        "tennessee",
        "indiana",
        "maryland",
        "missouri",
        "wisconsin",
        "colorado",
        "minnesota",
        "southcarolina",
        "alabama",
        "louisiana",
        "kentucky",
        "oregon",
        "oklahoma",
        "connecticut",
        "utah",
        "iowa",
        "nevada",
        "arkansas",
        "mississippi",
        "kansas",
        "newmexico",
        "nebraska",
        "westvirginia",
        "idaho",
        "hawaii",
        "newhampshire",
        "maine",
        "montana",
        "rhodeisland",
        "delaware",
        "southdakota",
        "northdakota",
        "alaska",
        "vermont",
        "wyoming",
        "ontario",
        "quebec",
        "britishcolumbia",
        "alberta",
        "manitoba",
        "saskatchewan",
        "novascotia",
        "newbrunswick",
        "newfoundland",
        "labrador",
        "princeedward",
        "island",
        "northwest",
        "territories",
        "yukon",
        "nunavut",
        "europe",
        "asia",
        "africa",
        "northamerica",
        "southamerica",
        "oceania",
        "antarctica",
        "middleeast",
        "fareast",
        "southeast",
        "central",
        "eastern",
        "western",
        "northern",
        "southern",
        "arctic",
        "pacific",
        "atlantic",
        "indian",
        "mediterranean",
        "caribbean",
        "scandinavia",
        "balkans",
        "iberia",
        "caucasus",
        "anatolia",
        "mesopotamia",
        "levant",
        "maghreb",
        "sahara",
        "sahel",
        "subsaharan",
        "eastafrica",
        "westafrica",
        "centralafrica",
        "southafrica",
        "madagascar",
        "polynesia",
        "melanesia",
        "micronesia",
    ],
    "industry_specific": [
        # Automotive (MASSIVE)
        "auto",
        "automotive",
        "car",
        "cars",
        "vehicle",
        "vehicles",
        "motor",
        "motors",
        "engine",
        "engines",
        "parts",
        "repair",
        "service",
        "garage",
        "dealer",
        "dealership",
        "rental",
        "lease",
        "insurance",
        "accident",
        "collision",
        "body",
        "paint",
        "tire",
        "tires",
        "wheel",
        "wheels",
        "brake",
        "brakes",
        "transmission",
        "battery",
        "oil",
        "gas",
        "fuel",
        "hybrid",
        "electric",
        "tesla",
        "ford",
        "gm",
        "toyota",
        "honda",
        "nissan",
        "bmw",
        "mercedes",
        "audi",
        "volkswagen",
        "porsche",
        "ferrari",
        "lamborghini",
        "maserati",
        "bugatti",
        "mclaren",
        "aston",
        "martin",
        "bentley",
        "rolls",
        "royce",
        "jaguar",
        "land",
        "rover",
        "volvo",
        "saab",
        "peugeot",
        "citroen",
        "renault",
        "fiat",
        "alfa",
        "romeo",
        "lancia",
        "skoda",
        "seat",
        "hyundai",
        "kia",
        "mazda",
        "subaru",
        "mitsubishi",
        "suzuki",
        "isuzu",
        "daihatsu",
        "acura",
        "infiniti",
        "lexus",
        "genesis",
        "lincoln",
        "cadillac",
        "buick",
        "chevrolet",
        "dodge",
        "chrysler",
        "jeep",
        "ram",
        "gmc",
        "hummer",
        "saturn",
        "pontiac",
        # Real Estate (MASSIVE)
        "real",
        "estate",
        "property",
        "properties",
        "home",
        "homes",
        "house",
        "houses",
        "apartment",
        "apartments",
        "condo",
        "condos",
        "townhouse",
        "villa",
        "mansion",
        "penthouse",
        "studio",
        "loft",
        "duplex",
        "triplex",
        "commercial",
        "office",
        "retail",
        "warehouse",
        "industrial",
        "land",
        "lot",
        "acreage",
        "development",
        "construction",
        "renovation",
        "remodel",
        "interior",
        "design",
        "architecture",
        "mortgage",
        "loan",
        "refinance",
        "appraisal",
        "inspection",
        "title",
        "escrow",
        "closing",
        "realtor",
        "agent",
        "broker",
        "mls",
        "listing",
        "sale",
        "rent",
        "lease",
        "tenant",
        "landlord",
        "property",
        "management",
        "maintenance",
        "repairs",
        "utilities",
        "homeowners",
        "association",
        "hoa",
        "coop",
        "investment",
        "flip",
        "wholesale",
        # Food & Beverage (MASSIVE)
        "food",
        "foods",
        "restaurant",
        "restaurants",
        "cafe",
        "cafes",
        "bar",
        "bars",
        "pub",
        "pubs",
        "grill",
        "grills",
        "bistro",
        "diner",
        "eatery",
        "kitchen",
        "chef",
        "cook",
        "cooking",
        "recipe",
        "recipes",
        "menu",
        "catering",
        "delivery",
        "takeout",
        "pizza",
        "burger",
        "burgers",
        "sushi",
        "chinese",
        "italian",
        "mexican",
        "indian",
        "thai",
        "japanese",
        "korean",
        "mediterranean",
        "french",
        "american",
        "bbq",
        "seafood",
        "steakhouse",
        "vegetarian",
        "vegan",
        "organic",
        "healthy",
        "diet",
        "nutrition",
        "coffee",
        "tea",
        "juice",
        "smoothie",
        "wine",
        "beer",
        "cocktail",
        "spirits",
        "liquor",
        "brewery",
        "winery",
        "distillery",
        "vineyard",
        "farm",
        "table",
        "fresh",
        "local",
        "seasonal",
        "gourmet",
        "artisan",
        "craft",
        "homemade",
        "traditional",
        "authentic",
        "fusion",
        "molecular",
        # Healthcare (MASSIVE)
        "health",
        "healthcare",
        "medical",
        "medicine",
        "doctor",
        "doctors",
        "physician",
        "clinic",
        "hospital",
        "emergency",
        "urgent",
        "care",
        "family",
        "practice",
        "pediatric",
        "cardiology",
        "dermatology",
        "neurology",
        "orthopedic",
        "surgery",
        "surgical",
        "radiology",
        "pathology",
        "oncology",
        "psychiatry",
        "psychology",
        "therapy",
        "physical",
        "occupational",
        "pharmacy",
        "pharmaceutical",
        "drug",
        "drugs",
        "prescription",
        "medication",
        "dental",
        "dentist",
        "orthodontic",
        "oral",
        "surgery",
        "veterinary",
        "vet",
        "animal",
        "pet",
        "wellness",
        "fitness",
        "gym",
        "yoga",
        "massage",
        "chiropractic",
        "acupuncture",
        "nutrition",
        "supplement",
        "vitamin",
        "alternative",
        "holistic",
        "natural",
        "herbal",
        "homeopathic",
        "ayurvedic",
        # Legal (MASSIVE)
        "law",
        "legal",
        "attorney",
        "lawyer",
        "attorneys",
        "lawyers",
        "firm",
        "practice",
        "court",
        "trial",
        "litigation",
        "settlement",
        "contract",
        "corporate",
        "business",
        "commercial",
        "real",
        "estate",
        "personal",
        "injury",
        "criminal",
        "defense",
        "family",
        "divorce",
        "custody",
        "adoption",
        "immigration",
        "bankruptcy",
        "tax",
        "estate",
        "planning",
        "will",
        "trust",
        "probate",
        "intellectual",
        "property",
        "patent",
        "trademark",
        "copyright",
        "employment",
        "labor",
        "workers",
        "compensation",
        "social",
        "security",
        "disability",
        "medical",
        "malpractice",
        "product",
        "liability",
        "class",
        "action",
        "arbitration",
        "mediation",
        "paralegal",
        "legal",
        "assistant",
        "notary",
        "public",
        "legal",
        "aid",
        "pro",
        "bono",
        "consultation",
        "advice",
        # Financial Services (MASSIVE)
        "finance",
        "financial",
        "bank",
        "banking",
        "credit",
        "union",
        "investment",
        "investments",
        "wealth",
        "management",
        "advisor",
        "planning",
        "retirement",
        "401k",
        "ira",
        "pension",
        "insurance",
        "life",
        "health",
        "auto",
        "home",
        "business",
        "liability",
        "workers",
        "compensation",
        "disability",
        "annuity",
        "mutual",
        "fund",
        "etf",
        "stock",
        "stocks",
        "bond",
        "bonds",
        "trading",
        "broker",
        "brokerage",
        "portfolio",
        "asset",
        "allocation",
        "diversification",
        "risk",
        "return",
        "dividend",
        "yield",
        "capital",
        "gains",
        "tax",
        "shelter",
        "estate",
        "trust",
        "loan",
        "mortgage",
        "refinance",
        "equity",
        "line",
        "credit",
        "personal",
        "student",
        "business",
        "commercial",
        "real",
        "estate",
        "accounting",
        "bookkeeping",
        "payroll",
        "audit",
        "tax",
        "preparation",
        # Technology Services (MASSIVE)
        "tech",
        "technology",
        "it",
        "information",
        "technology",
        "computer",
        "computers",
        "software",
        "hardware",
        "network",
        "networking",
        "security",
        "cybersecurity",
        "cloud",
        "hosting",
        "server",
        "servers",
        "database",
        "web",
        "development",
        "programming",
        "coding",
        "app",
        "application",
        "mobile",
        "ios",
        "android",
        "website",
        "ecommerce",
        "digital",
        "marketing",
        "seo",
        "sem",
        "social",
        "media",
        "email",
        "automation",
        "crm",
        "erp",
        "saas",
        "paas",
        "iaas",
        "devops",
        "agile",
        "scrum",
        "project",
        "management",
        "consulting",
        "support",
        "maintenance",
        "backup",
        "recovery",
        "migration",
        "integration",
        "api",
        "artificial",
        "intelligence",
        "machine",
        "learning",
        "blockchain",
        "cryptocurrency",
        "fintech",
        "edtech",
        "healthtech",
        "insurtech",
        # Education (MASSIVE)
        "education",
        "school",
        "schools",
        "elementary",
        "middle",
        "high",
        "college",
        "university",
        "academy",
        "institute",
        "learning",
        "center",
        "tutor",
        "tutoring",
        "test",
        "prep",
        "sat",
        "act",
        "gmat",
        "gre",
        "lsat",
        "mcat",
        "online",
        "distance",
        "continuing",
        "professional",
        "development",
        "training",
        "certification",
        "course",
        "courses",
        "class",
        "classes",
        "workshop",
        "seminar",
        "conference",
        "degree",
        "bachelor",
        "master",
        "doctorate",
        "phd",
        "student",
        "teacher",
        "professor",
        "faculty",
        "staff",
        "administration",
        "admissions",
        "financial",
        "aid",
        "scholarship",
        "grant",
        "loan",
        "tuition",
        "campus",
        "dormitory",
        "library",
        "laboratory",
        "research",
        "thesis",
        "dissertation",
        "academic",
        "curriculum",
        "syllabus",
        "exam",
        "grade",
    ],
    "specialized": [
        # Adult content (for security research)
        "xxx",
        "sex",
        "adult",
        "porn",
        "sexy",
        "nude",
        "erotic",
        "dating",
        "singles",
        "escort",
        "massage",
        "cam",
        "live",
        "video",
        "chat",
        "webcam",
        "model",
        "amateur",
        "professional",
        "hardcore",
        "softcore",
        "fetish",
        "bdsm",
        "mature",
        "milf",
        "teen",
        "young",
        "old",
        "gay",
        "lesbian",
        "trans",
        "straight",
        "bi",
        "couple",
        "group",
        "orgy",
        "swing",
        "hookup",
        "affair",
        # Alternative/suspicious (for security research)
        "tor",
        "onion",
        "dark",
        "underground",
        "anonymous",
        "private",
        "secure",
        "hidden",
        "secret",
        "stealth",
        "proxy",
        "vpn",
        "encrypted",
        "protected",
        "safe",
        "trust",
        "leaked",
        "dump",
        "breach",
        "hack",
        "hacked",
        "exploit",
        "vulnerability",
        "zero",
        "day",
        "malware",
        "virus",
        "trojan",
        "ransomware",
        "phishing",
        "scam",
        "fraud",
        "fake",
        "counterfeit",
        "piracy",
        "illegal",
        "black",
        "market",
        "drugs",
        "weapons",
        "money",
        "laundering",
        "offshore",
        "tax",
        "haven",
        "shell",
        "company",
        "ponzi",
        "scheme",
        "pyramid",
        "mlm",
        # Typos and variations of common TLDs (for typosquatting research)
        "con",
        "comm",
        "ner",
        "nett",
        "ogr",
        "orgr",
        "vom",
        "cmo",
        "ocm",
        "nt",
        "te",
        "nte",
        "gro",
        "rog",
        "gor",
        "cm",
        "co",
        "om",
        "or",
        "og",
        "cm",
        "ne",
        "nt",
        "coom",
        "neet",
        "orgg",
        "coim",
        "comn",
        "coma",
        "como",
        "comi",
        "comr",
        "nert",
        "neto",
        "netu",
        "neta",
        "neti",
        "netr",
        "nets",
        "netw",
        "nety",
        "oorg",
        "orga",
        "orgi",
        "orgo",
        "orgu",
        "orgp",
        "orgs",
        "orgt",
        "orgy",
        # Internationalized domain names (for research)
        "xn--",
        "punycode",
        "idn",
        "international",
        "unicode",
        "utf8",
        "ascii",
        "latin",
        "cyrillic",
        "arabic",
        "chinese",
        "japanese",
        "korean",
        "hindi",
        "thai",
        "vietnamese",
        "russian",
        "greek",
        "hebrew",
        "persian",
        "urdu",
        # Blockchain & DeFi specific (for comprehensive coverage)
        "defi",
        "dao",
        "dex",
        "nft",
        "gamefi",
        "socialfi",
        "refi",
        "cefi",
        "tradfi",
        "yield",
        "farming",
        "liquidity",
        "mining",
        "staking",
        "validator",
        "node",
        "masternode",
        "consensus",
        "pow",
        "pos",
        "dpos",
        "hybrid",
        "sharding",
        "layer1",
        "layer2",
        "sidechain",
        "rollup",
        "plasma",
        "state",
        "channel",
        "atomic",
        "swap",
        "cross",
        "chain",
        "bridge",
        "wrapper",
        "synthetic",
        "derivative",
        "perpetual",
        "future",
        "option",
        "margin",
        "leverage",
        "liquidation",
        "slippage",
        "impermanent",
        "loss",
        "rugpull",
        "honeypot",
    ],
}

# HTTP status codes that indicate a potential active domain
ACTIVE_HTTP_CODES = [200, 301, 302, 303, 307, 308, 403, 404, 405, 429, 500, 502, 503]


@click.command()
@click.option("--domain", "-d", required=True, help="Base domain name (without TLD)")
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
    help="TLD categories to use: popular,country,new_generic,business,all",
)
@click.option("--threads", default=50, help="Number of concurrent threads")
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
    "--cache",
    is_flag=True,
    help="Enable intelligent caching for TLD enumeration results",
)
@click.option("--cache-dir", default="tldr_cache", help="Directory for cache storage")
@click.option(
    "--cache-max-age", default=24, type=int, help="Maximum cache age in hours"
)
@click.option(
    "--cache-stats", is_flag=True, help="Display cache performance statistics"
)
@click.option(
    "--clear-cache", is_flag=True, help="Clear all cached TLD enumeration results"
)
@click.option(
    "--ai", is_flag=True, help="Enable AI-powered analysis of TLD enumeration results"
)
@click.option(
    "--ai-provider",
    type=click.Choice(["openai", "anthropic", "gemini"]),
    help="AI provider for analysis",
)
@click.option("--ai-model", help="Specific AI model to use for analysis")
@click.option("--ai-context", help="Additional context for AI analysis")
def cli(
    domain,
    output_dir,
    tld_list,
    categories,
    threads,
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
    cache,
    cache_dir,
    cache_max_age,
    cache_stats,
    clear_cache,
    ai,
    ai_provider,
    ai_model,
    ai_context,
):
    """Advanced TLD reconnaissance - discover domains across alternative TLDs

    Systematically checks if a domain exists across different top-level domains,
    performs DNS resolution, HTTP probing, and basic availability analysis.

    Examples:
        tldrcli -d example --categories popular,country --http-check --verbose
        tldrcli -d mycompany --tld-list custom_tlds.txt --filter-active
        tldrcli -d brand --categories all --whois-check --save-json
    """

    # Initialize cache manager
    cache_manager = None
    if cache:
        cache_manager = TLDRCacheManager(
            cache_dir=cache_dir, max_age_hours=cache_max_age
        )

        # Handle cache management operations
        if clear_cache:
            removed = cache_manager.clear_cache()
            click.echo(f"✅ Cleared {removed} cached TLD enumeration results")
            return

        if cache_stats:
            stats = cache_manager.get_cache_stats()
            click.echo("\n📊 TLD Cache Statistics:")
            click.echo(f"  Total requests: {stats['total_requests']}")
            click.echo(f"  Cache hits: {stats['cache_hits']}")
            click.echo(f"  Cache misses: {stats['cache_misses']}")
            click.echo(f"  Hit rate: {stats['hit_rate']}%")
            click.echo(f"  Cached results: {stats['cached_results']}")
            click.echo(f"  Cache size: {stats['cache_size_mb']} MB")
            click.echo(f"  Cache directory: {stats['cache_dir']}")

            # Show performance improvement
            if stats["cache_hits"] > 0:
                improvement = (
                    stats["cache_hits"] * 50
                )  # Assume 50x average improvement for DNS
                click.echo(f"  🚀 Estimated speed improvement: {improvement}x faster")
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

    if verbose:
        click.echo(f"[+] 🌍 Starting TLD reconnaissance for: {domain}")
        click.echo(f"[+] 📁 Output directory: {output_dir}")
        click.echo(f"[+] 🧵 Threads: {threads}")
        click.echo(f"[+] ⏰ Timeout: {timeout}s")
        click.echo(f"[+] 🔄 Retries: {retries}")
        if http_check:
            click.echo("[+] 🌐 HTTP probing enabled")
        if whois_check:
            click.echo("[+] 📋 WHOIS checking enabled")
        if ai:
            provider_info = f" ({ai_provider})" if ai_provider else ""
            model_info = f" using {ai_model}" if ai_model else ""
            click.echo(f"[+] 🧠 AI analysis enabled{provider_info}{model_info}")

    # Build TLD list
    tld_list_final = build_tld_list(tld_list, categories, verbose)

    if not tld_list_final:
        click.echo(
            "[!] ❌ No TLDs to check. Please specify valid categories or TLD list."
        )
        return

    if verbose:
        click.echo(f"[+] 📝 Testing {len(tld_list_final)} TLD(s)")

    # Check cache first
    if cache_manager:
        cached_result = cache_manager.get_cached_result(
            domain=domain, tlds=tld_list_final, operation="enumerate"
        )
        if cached_result:
            cached_data = cached_result.get("result", {})
            if verbose:
                click.echo(
                    f"✅ Using cached results for {domain} with {len(tld_list_final)} TLDs"
                )

            # Process cached results
            results = cached_data.get("results", [])
            active_domains = [
                r for r in results if r.get("dns_resolved") or r.get("http_status")
            ]

            if verbose:
                click.echo(f"[+] Found {len(active_domains)} active domains from cache")

            # Generate reports from cached data if requested
            if save_json or save_markdown:
                generate_reports(
                    results, domain, output_dir, save_json, save_markdown, verbose
                )

            # AI analysis if requested
            if ai and results:
                perform_ai_analysis(
                    results, domain, ai_provider, ai_model, ai_context, verbose
                )

            return

    os.makedirs(output_dir, exist_ok=True)

    # Enhanced resume system
    scan_key = f"tldr_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    resume_state = load_resume(output_dir)

    if resume and resume_state:
        if verbose:
            click.echo(
                f"[+] 📁 Loading resume state with {len(resume_state)} previous scan(s)"
            )
        # Find the most recent incomplete scan
        for key, data in sorted(
            resume_state.items(), key=lambda x: x[1].get("start_time", ""), reverse=True
        ):
            if key.startswith("tldr_") and not data.get("completed", False):
                scan_key = key
                if verbose:
                    click.echo(f"[+] 🔄 Resuming scan: {scan_key}")
                break
    else:
        # Initialize new scan
        resume_state[scan_key] = {
            "domain": domain,
            "start_time": datetime.now().isoformat(),
            "completed": False,
            "processed_count": 0,
            "resolved_count": 0,
            "http_active_count": 0,
            "configuration": {
                "threads": threads,
                "timeout": timeout,
                "retries": retries,
                "dns_only": dns_only,
                "http_check": http_check,
                "whois_check": whois_check,
                "categories": categories,
            },
        }
        save_resume_state(output_dir, resume_state)

    current_scan = resume_state[scan_key]
    processed_count = current_scan.get("processed_count", 0)

    if verbose and processed_count > 0:
        click.echo(f"[+] 📁 Resume: {processed_count} TLDs already processed")

    start_time = time.time()

    # Process TLDs with concurrent checking
    results = process_tlds_concurrent(
        domain,
        tld_list_final[processed_count:],
        threads,
        timeout,
        retries,
        dns_only,
        http_check,
        whois_check,
        exclude_wildcards,
        verbose,
    )

    # Update counts
    resolved_count = len([r for r in results if r["dns_resolved"]])
    http_active_count = len(
        [r for r in results if r.get("http_status") in ACTIVE_HTTP_CODES]
    )

    current_scan["processed_count"] = len(tld_list_final)
    current_scan["resolved_count"] = (
        current_scan.get("resolved_count", 0) + resolved_count
    )
    current_scan["http_active_count"] = (
        current_scan.get("http_active_count", 0) + http_active_count
    )
    current_scan["completed"] = True
    current_scan["completion_time"] = datetime.now().isoformat()

    save_resume_state(output_dir, resume_state)

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

    # Save outputs in multiple formats
    save_outputs(results, output_dir, save_json, save_markdown, verbose)

    elapsed = round(time.time() - start_time, 2)

    if verbose:
        click.echo("\n[+] 📊 TLD Reconnaissance Summary:")
        click.echo(f"   - Base domain: {domain}")
        click.echo(f"   - Total TLDs tested: {len(tld_list_final)}")
        click.echo(f"   - DNS resolved: {resolved_count}")
        click.echo(f"   - HTTP active: {http_active_count}")
        click.echo(f"   - Scan duration: {elapsed}s")
        click.echo(
            f"   - Success rate: {resolved_count / len(tld_list_final) * 100:.1f}%"
        )

    # Generate statistics
    stats = generate_statistics(results, verbose)

    # Send notifications if configured
    if (slack_webhook or discord_webhook) and send_notification:
        send_tldr_notifications(
            results,
            stats,
            domain,
            len(tld_list_final),
            resolved_count,
            http_active_count,
            elapsed,
            slack_webhook,
            discord_webhook,
            verbose,
        )

    click.echo("\n[+] ✅ TLD reconnaissance completed!")
    click.echo(f"[+] 📁 Results saved to: {output_dir}")


def build_tld_list(
    tld_file: Optional[str], categories: str, verbose: bool
) -> List[str]:
    """Build comprehensive TLD list from file or categories"""
    tlds = set()

    # Load from file if provided
    if tld_file:
        try:
            with open(tld_file, "r") as f:
                file_tlds = [
                    line.strip().lstrip(".")
                    for line in f
                    if line.strip() and not line.startswith("#")
                ]
                tlds.update(file_tlds)
            if verbose:
                click.echo(f"[+] 📄 Loaded {len(file_tlds)} TLDs from file")
        except Exception as e:
            if verbose:
                click.echo(f"[!] ❌ Failed to load TLD file: {e}")

    # Add from categories
    if categories:
        category_list = [cat.strip() for cat in categories.split(",")]

        for category in category_list:
            if category == "all":
                for cat_tlds in DEFAULT_TLDS.values():
                    tlds.update(cat_tlds)
            elif category in DEFAULT_TLDS:
                tlds.update(DEFAULT_TLDS[category])
            else:
                if verbose:
                    click.echo(f"[!] ⚠️  Unknown category: {category}")

        if verbose:
            click.echo(f"[+] 📋 Added TLDs from categories: {', '.join(category_list)}")

    return sorted(list(tlds))


def process_tlds_concurrent(
    domain: str,
    tlds: List[str],
    threads: int,
    timeout: int,
    retries: int,
    dns_only: bool,
    http_check: bool,
    whois_check: bool,
    exclude_wildcards: bool,
    verbose: bool,
) -> List[Dict]:
    """Process TLD list with concurrent checking"""
    results = []

    def check_domain_tld(tld: str) -> Dict:
        """Check a single domain.tld combination"""
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
            # DNS Resolution
            socket.setdefaulttimeout(timeout)
            try:
                ip = socket.gethostbyname(full_domain)
                result["dns_resolved"] = True
                result["ip_address"] = ip
            except socket.gaierror:
                result["dns_resolved"] = False

            # Wildcard detection
            if exclude_wildcards and result["dns_resolved"]:
                result["is_wildcard"] = detect_wildcard(domain, tld, ip, timeout)

            # HTTP/HTTPS checking
            if http_check and result["dns_resolved"] and not result["is_wildcard"]:
                http_status, https_status = check_http_status(
                    full_domain, timeout, retries
                )
                result["http_status"] = http_status
                result["https_status"] = https_status

            # Basic WHOIS checking (simplified)
            if whois_check:
                result["whois_available"] = simple_whois_check(full_domain, timeout)

        except Exception as e:
            result["error"] = str(e)

        return result

    # Use ThreadPoolExecutor for concurrent processing
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        # Create progress bar
        with tqdm(
            total=len(tlds),
            desc="🌍 Checking TLDs",
            disable=not verbose,
            ncols=100,
        ) as pbar:
            # Submit all tasks
            future_to_tld = {
                executor.submit(check_domain_tld, tld): tld for tld in tlds
            }

            # Collect results as they complete
            for future in concurrent.futures.as_completed(future_to_tld):
                result = future.result()
                results.append(result)
                pbar.update(1)

                # Update progress bar with stats
                resolved = len([r for r in results if r["dns_resolved"]])
                active = len(
                    [r for r in results if r.get("http_status") in ACTIVE_HTTP_CODES]
                )
                pbar.set_postfix(resolved=resolved, active=active)

    return results


def detect_wildcard(domain: str, tld: str, resolved_ip: str, timeout: int) -> bool:
    """Simple wildcard detection by testing random subdomain"""
    import random
    import string

    try:
        # Generate random subdomain
        random_sub = "".join(
            random.choices(
                string.ascii_lowercase + string.digits, k=15
            )  # nosec: B311 - non-cryptographic wildcard detection
        )
        test_domain = f"{random_sub}.{domain}.{tld}"

        socket.setdefaulttimeout(timeout)
        test_ip = socket.gethostbyname(test_domain)

        # If random subdomain resolves to same IP, likely wildcard
        return test_ip == resolved_ip
    except:
        return False


def check_http_status(
    domain: str, timeout: int, retries: int
) -> Tuple[Optional[int], Optional[int]]:
    """Check HTTP and HTTPS status codes"""
    import ssl

    def get_status(url: str) -> Optional[int]:
        # Validate URL scheme for security
        import urllib.parse

        parsed_url = urllib.parse.urlparse(url)
        if parsed_url.scheme not in ("http", "https"):
            return None

        for attempt in range(retries + 1):
            try:
                # Create SSL context that doesn't verify certificates
                ssl_context = ssl.create_default_context()
                ssl_context.check_hostname = False
                ssl_context.verify_mode = ssl.CERT_NONE

                req = urllib.request.Request(
                    url, headers={"User-Agent": "Mozilla/5.0 (TLD-Recon/1.0)"}
                )

                with urllib.request.urlopen(  # nosec: B310 - URL scheme validated above
                    req, timeout=timeout, context=ssl_context
                ) as response:
                    return response.getcode()
            except urllib.error.HTTPError as e:
                return e.code
            except Exception:
                if attempt == retries:
                    return None
                time.sleep(0.1)
        return None

    http_status = get_status(f"http://{domain}")
    https_status = get_status(f"https://{domain}")

    return http_status, https_status


def simple_whois_check(domain: str, timeout: int) -> Optional[bool]:
    """Simple WHOIS availability check (placeholder)"""
    # This is a simplified placeholder
    # In production, you might want to use python-whois library
    # or integrate with WHOIS APIs
    try:
        import subprocess

        result = subprocess.run(
            [find_executable("whois"), domain],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        # Simple heuristic: if whois returns info, domain might be registered
        return "No match" not in result.stdout and "NOT FOUND" not in result.stdout
    except:
        return None


def save_outputs(
    results: List[Dict],
    output_dir: str,
    save_json: bool,
    save_markdown: bool,
    verbose: bool,
):
    """Save results in multiple formats"""

    # Standard output
    output_path = os.path.join(output_dir, "tld_results.txt")
    with open(output_path, "w") as f:
        for result in results:
            status_parts = []

            if result["dns_resolved"]:
                status_parts.append(f"IP:{result['ip_address']}")
            else:
                status_parts.append("DNS:FAIL")

            if result.get("http_status"):
                status_parts.append(f"HTTP:{result['http_status']}")
            if result.get("https_status"):
                status_parts.append(f"HTTPS:{result['https_status']}")

            if result.get("is_wildcard"):
                status_parts.append("WILDCARD")

            if result.get("whois_available") is not None:
                status_parts.append(
                    f"WHOIS:{'REG' if result['whois_available'] else 'AVAIL'}"
                )

            status_str = " | ".join(status_parts) if status_parts else "INACTIVE"
            f.write(f"{result['domain']} - {status_str}\n")

    if verbose:
        click.echo(f"[+] 💾 Saved results to {output_path}")

    # JSON output
    if save_json:
        json_output = {
            "scan_metadata": {
                "timestamp": datetime.now().isoformat(),
                "total_domains": len(results),
                "resolved_count": len([r for r in results if r["dns_resolved"]]),
                "active_count": len(
                    [r for r in results if r.get("http_status") in ACTIVE_HTTP_CODES]
                ),
                "tool": "tldrcli",
            },
            "results": results,
        }

        json_path = os.path.join(output_dir, "tld_results.json")
        with open(json_path, "w") as f:
            json.dump(json_output, f, indent=2)

        if verbose:
            click.echo(f"[+] 📄 Saved JSON results to {json_path}")

    # Markdown output
    if save_markdown:
        md_path = os.path.join(output_dir, "tld_results.md")
        with open(md_path, "w") as f:
            f.write("# TLD Reconnaissance Results\n\n")
            f.write(f"**Scan Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"**Total Domains:** {len(results)}\n")
            f.write(
                f"**DNS Resolved:** {len([r for r in results if r['dns_resolved']])}\n"
            )
            f.write(
                f"**HTTP Active:** {len([r for r in results if r.get('http_status') in ACTIVE_HTTP_CODES])}\n\n"
            )

            f.write("## Results\n\n")
            f.write("| Domain | TLD | DNS | IP Address | HTTP | HTTPS | Status |\n")
            f.write("|--------|-----|-----|------------|------|-------|--------|\n")

            for result in results:
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

                status = " ".join(status_flags) if status_flags else "-"

                f.write(
                    f"| {result['domain']} | {result['tld']} | {dns_status} | {ip_addr} | {http_status} | {https_status} | {status} |\n"
                )

        if verbose:
            click.echo(f"[+] 📝 Saved Markdown results to {md_path}")


def generate_statistics(results: List[Dict], verbose: bool) -> Dict:
    """Generate comprehensive statistics"""
    stats = {
        "total_domains": len(results),
        "dns_resolved": len([r for r in results if r["dns_resolved"]]),
        "http_active": len(
            [r for r in results if r.get("http_status") in ACTIVE_HTTP_CODES]
        ),
        "https_active": len(
            [r for r in results if r.get("https_status") in ACTIVE_HTTP_CODES]
        ),
        "wildcards": len([r for r in results if r.get("is_wildcard")]),
        "registered": len([r for r in results if r.get("whois_available")]),
        "available": len([r for r in results if r.get("whois_available") is False]),
    }

    if verbose:
        click.echo("\n[+] 📊 Detailed Statistics:")
        click.echo(f"   - Total domains tested: {stats['total_domains']}")
        click.echo(f"   - DNS resolved: {stats['dns_resolved']}")
        click.echo(f"   - HTTP active: {stats['http_active']}")
        click.echo(f"   - HTTPS active: {stats['https_active']}")
        if stats["wildcards"] > 0:
            click.echo(f"   - Wildcards detected: {stats['wildcards']}")
        if stats["registered"] > 0:
            click.echo(f"   - Registered domains: {stats['registered']}")
        if stats["available"] > 0:
            click.echo(f"   - Available domains: {stats['available']}")

    return stats


def send_tldr_notifications(
    results: List[Dict],
    stats: Dict,
    domain: str,
    total: int,
    resolved: int,
    active: int,
    elapsed: float,
    slack_webhook: str,
    discord_webhook: str,
    verbose: bool,
):
    """Send TLD reconnaissance notifications"""
    if not (send_notification and (slack_webhook or discord_webhook)):
        return

    try:
        scan_metadata = {
            "base_domain": domain,
            "total_tlds": total,
            "resolved_count": resolved,
            "active_count": active,
            "scan_duration": f"{elapsed}s",
            "timestamp": datetime.now().strftime("%Y%m%d_%H%M%S"),
            "tool": "tldrcli",
            "statistics": stats,
        }

        # Prepare interesting results for notification
        interesting_results = []
        for result in results[:20]:  # First 20 results
            if result["dns_resolved"] or result.get("http_status") in ACTIVE_HTTP_CODES:
                interesting_results.append(result)

        if verbose:
            click.echo("[+] 📱 Sending TLD reconnaissance notifications...")

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


def generate_reports(results, domain, output_dir, save_json, save_markdown, verbose):
    """Generate reports from TLD enumeration results."""
    if save_json:
        json_file = os.path.join(output_dir, f"{domain}_tlds.json")
        with open(json_file, "w") as f:
            json.dump(results, f, indent=2)
        if verbose:
            click.echo(f"[+] 💾 Saved JSON report: {json_file}")

    if save_markdown:
        md_file = os.path.join(output_dir, f"{domain}_tlds.md")
        with open(md_file, "w") as f:
            f.write(f"# TLD Enumeration Report for {domain}\n\n")
            f.write(f"Generated: {datetime.now().isoformat()}\n\n")
            f.write(f"## Summary\n")
            f.write(f"- Total TLDs tested: {len(results)}\n")
            active_count = len(
                [r for r in results if r.get("dns_resolved") or r.get("http_status")]
            )
            f.write(f"- Active domains found: {active_count}\n\n")
            f.write(f"## Results\n\n")
            for result in results:
                if result.get("dns_resolved") or result.get("http_status"):
                    f.write(f"### {result['domain']}\n")
                    f.write(f"- DNS Resolved: {result.get('dns_resolved', False)}\n")
                    if result.get("http_status"):
                        f.write(f"- HTTP Status: {result['http_status']}\n")
                    f.write("\n")
        if verbose:
            click.echo(f"[+] 📋 Saved Markdown report: {md_file}")


def perform_ai_analysis(results, domain, ai_provider, ai_model, ai_context, verbose):
    """Perform AI analysis on TLD enumeration results."""
    try:
        # Import AI here to avoid dependency issues
        from reconcli.aicli import AIReconAssistant

        ai_assistant = AIReconAssistant()

        # Build analysis prompt
        active_domains = [
            r for r in results if r.get("dns_resolved") or r.get("http_status")
        ]

        analysis_prompt = f"""
        Analyze TLD enumeration results for domain: {domain}
        
        Summary:
        - Total TLDs tested: {len(results)}
        - Active domains found: {len(active_domains)}
        
        Active domains:
        {json.dumps(active_domains[:10], indent=2)}
        
        Context: {ai_context or "TLD enumeration security analysis"}
        
        Please provide:
        1. Security implications of found domains
        2. Potential attack vectors
        3. Brand protection recommendations
        4. Monitoring suggestions
        """

        if verbose:
            click.echo(f"[+] 🧠 Performing AI analysis...")

        ai_response = ai_assistant.ask_ai(
            analysis_prompt, provider=ai_provider, context="recon"
        )

        if ai_response:
            click.echo(f"\n{'='*60}")
            click.echo(f"🧠 AI ANALYSIS RESULTS")
            click.echo(f"{'='*60}")
            click.echo(ai_response)
            click.echo(f"{'='*60}")

    except ImportError:
        if verbose:
            click.echo("[!] ⚠️ AI module not available for analysis")
    except Exception as e:
        if verbose:
            click.echo(f"[!] ⚠️ AI analysis failed: {e}")


if __name__ == "__main__":
    cli()
