import click
import subprocess
import itertools
import tempfile
import json
import requests
import re
import os
import hashlib
from pathlib import Path
from urllib.parse import urlparse, urljoin
import time
import random
from collections import Counter
from difflib import SequenceMatcher

# Enhanced patterns for advanced wordlist generation
PATTERN_TEMPLATES = {
    "credential": [
        "{word}admin",
        "{word}user",
        "{word}pass",
        "{word}login",
        "admin{word}",
        "user{word}",
    ],
    "subdomain": [
        "{word}.{domain}",
        "www.{word}.{domain}",
        "api.{word}.{domain}",
        "dev.{word}.{domain}",
    ],
    "directory": ["/{word}/", "/{word}/admin/", "/{word}/api/", "/{word}/backup/"],
    "filename": [
        "{word}.txt",
        "{word}.log",
        "{word}.bak",
        "{word}.config",
        "{word}.sql",
    ],
    "parameter": ["?{word}=", "&{word}=", "{word}[]", "{word}_id"],
    "endpoint": ["/api/{word}", "/v1/{word}", "/admin/{word}", "/{word}/list"],
}

# Rule-based transformations (inspired by hashcat rules)
TRANSFORMATION_RULES = {
    "caps": lambda w: w.upper(),
    "lower": lambda w: w.lower(),
    "title": lambda w: w.title(),
    "reverse": lambda w: w[::-1],
    "duplicate": lambda w: w + w,
    "append_num": lambda w: w + str(random.randint(1, 999)),
    "prepend_num": lambda w: str(random.randint(1, 999)) + w,
    "toggle_case": lambda w: "".join(
        c.lower() if c.isupper() else c.upper() for c in w
    ),
    "remove_vowels": lambda w: re.sub(r"[aeiouAEIOU]", "", w),
    "substitute_similar": lambda w: w.replace("o", "0")
    .replace("i", "1")
    .replace("s", "$")
    .replace("a", "@"),
}

# Enhanced OSINT sources
OSINT_SOURCES = {
    "github": "https://api.github.com/search/repositories?q={query}",
    "pastebin": "https://psbdmp.ws/api/search/{query}",
    "haveibeenpwned": "https://haveibeenpwned.com/api/v3/breachedaccount/{email}",
}

# Common file extensions by category
FILE_EXTENSIONS = {
    "web": ["html", "htm", "php", "asp", "aspx", "jsp", "js", "css"],
    "config": ["conf", "config", "cfg", "ini", "xml", "yaml", "yml", "json"],
    "backup": ["bak", "backup", "old", "orig", "save", "tmp", "temp"],
    "database": ["sql", "db", "sqlite", "mdb", "accdb"],
    "archive": ["zip", "rar", "tar", "gz", "7z", "bz2"],
    "log": ["log", "logs", "txt", "out", "err"],
}

# Keyboard patterns for pattern-based attacks
KEYBOARD_PATTERNS = {
    "qwerty_row1": "qwertyuiop",
    "qwerty_row2": "asdfghjkl",
    "qwerty_row3": "zxcvbnm",
    "numeric": "1234567890",
    "symbols": "!@#$%^&*()",
}

# Common password patterns
PASSWORD_PATTERNS = [
    "{word}123!",
    "{word}@2024",
    "{word}2024!",
    "123{word}",
    "{word}#{year}",
    "{word}_{word}",
    "{word}.{word}",
]

POSTFIXES = [
    "123",
    "!",
    "01",
    "admin",
    "2024",
    "2025",
    "_dev",
    "_test",
    "_prod",
    "_staging",
    "_backup",
    "_old",
    "_new",
    "_v1",
    "_v2",
    "api",
    "www",
]

PREFIXES = [
    "dev",
    "test",
    "prod",
    "staging",
    "backup",
    "old",
    "new",
    "api",
    "www",
    "admin",
    "secure",
    "internal",
    "private",
]

YEARS = ["2020", "2021", "2022", "2023", "2024", "2025"]
NUMBERS = ["1", "01", "001", "123", "12345", "0"]
COMMON_PASSWORDS = ["password", "admin", "123456", "qwerty", "letmein"]

# Technology-specific wordlists
TECH_STACKS = {
    "web": [
        "index",
        "default",
        "home",
        "main",
        "app",
        "site",
        "web",
        "www",
        "public",
        "assets",
    ],
    "api": [
        "api",
        "rest",
        "graphql",
        "endpoint",
        "service",
        "micro",
        "gateway",
        "webhook",
        "callback",
    ],
    "database": [
        "db",
        "database",
        "sql",
        "mysql",
        "postgres",
        "mongo",
        "redis",
        "elastic",
        "influx",
    ],
    "cloud": [
        "aws",
        "azure",
        "gcp",
        "docker",
        "k8s",
        "kubernetes",
        "terraform",
        "helm",
        "istio",
    ],
    "security": [
        "auth",
        "oauth",
        "jwt",
        "token",
        "key",
        "cert",
        "ssl",
        "tls",
        "vault",
        "secrets",
    ],
    "mobile": [
        "mobile",
        "android",
        "ios",
        "app",
        "apk",
        "ipa",
        "react",
        "flutter",
        "cordova",
    ],
    "media": [
        "images",
        "photos",
        "videos",
        "media",
        "upload",
        "download",
        "stream",
        "cdn",
    ],
}

PROFILES = {
    "corp": [
        "intranet",
        "portal",
        "secure",
        "employee",
        "dashboard",
        "files",
        "hr",
        "finance",
        "accounting",
        "sales",
        "marketing",
        "support",
    ],
    "login": [
        "admin",
        "login",
        "signin",
        "auth",
        "access",
        "account",
        "user",
        "member",
        "guest",
        "root",
        "administrator",
    ],
    "devops": [
        "grafana",
        "jenkins",
        "prometheus",
        "ci",
        "dev",
        "staging",
        "docker",
        "kubernetes",
        "gitlab",
        "github",
        "bitbucket",
    ],
    "cloud": [
        "s3",
        "bucket",
        "blob",
        "storage",
        "cdn",
        "gcp",
        "azure",
        "aws",
        "lambda",
        "ec2",
        "rds",
        "vpc",
        "iam",
    ],
    "ecommerce": [
        "shop",
        "store",
        "cart",
        "checkout",
        "payment",
        "order",
        "product",
        "catalog",
        "inventory",
        "customer",
    ],
    "social": [
        "user",
        "profile",
        "friend",
        "message",
        "chat",
        "post",
        "comment",
        "like",
        "share",
        "follow",
    ],
    "healthcare": [
        "patient",
        "doctor",
        "medical",
        "hospital",
        "clinic",
        "health",
        "pharmacy",
        "prescription",
        "appointment",
        "record",
    ],
    "education": [
        "student",
        "teacher",
        "course",
        "class",
        "lesson",
        "exam",
        "grade",
        "school",
        "university",
        "learning",
    ],
    "finance": [
        "bank",
        "account",
        "transaction",
        "payment",
        "invoice",
        "credit",
        "debit",
        "balance",
        "loan",
        "investment",
    ],
}


def run_cewl(url):
    """Run CeWL to extract words from website"""
    try:
        with tempfile.NamedTemporaryFile(delete=False) as temp:
            result = subprocess.run(
                ["cewl", url, "-w", temp.name],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=60,
            )
            if result.returncode == 0:
                with open(temp.name) as f:
                    return [line.strip() for line in f if line.strip()]
        return []
    except Exception:
        return []


def run_pydictor(words, minlen, maxlen):
    """Run pydictor to generate word combinations"""
    try:
        import tempfile
        import os
        import glob

        # Pydictor has maxlen limit of 20
        pydictor_maxlen = min(maxlen, 20)

        # Create output directory
        output_dir = tempfile.mkdtemp()

        # Use chunk mode instead of combiner
        cmd = ["pydictor", "-chunk"] + words[
            :6
        ]  # Limit to 6 words to avoid huge combinations

        cmd.extend(["--len", str(minlen), str(pydictor_maxlen), "-o", output_dir])

        result = subprocess.run(
            cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=120
        )

        generated_words = []
        if result.returncode == 0:
            # Find generated files
            pattern = os.path.join(output_dir, "chunk_*.txt")
            for output_file in glob.glob(pattern):
                with open(output_file, "r") as f:
                    generated_words.extend([line.strip() for line in f if line.strip()])

        # Cleanup
        import shutil

        shutil.rmtree(output_dir, ignore_errors=True)

        return generated_words

    except Exception as e:
        return []


def run_crunch(minlen, maxlen):
    """Run crunch to generate character combinations"""
    try:
        tmp = tempfile.NamedTemporaryFile(delete=False).name
        cmd = ["crunch", str(minlen), str(maxlen), "-o", tmp]
        result = subprocess.run(
            cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=180
        )
        if result.returncode == 0:
            with open(tmp) as f:
                return [line.strip() for line in f if line.strip()]
        return []
    except Exception:
        return []


def run_kitrunner(kit_path):
    """Run kitrunner to generate words from kit"""
    try:
        tmp = tempfile.NamedTemporaryFile(delete=False).name
        cmd = ["kitrunner", "generate", "-kit", kit_path, "-output", tmp]
        result = subprocess.run(
            cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=60
        )
        if result.returncode == 0:
            with open(tmp) as f:
                return [line.strip() for line in f if line.strip()]
        return []
    except Exception:
        return []


def extract_words_from_domain(domain):
    """Extract meaningful words from domain name"""
    # Remove common TLDs and subdomains
    clean_domain = domain.replace("www.", "").split(".")[0]

    # Split on common separators
    words = re.split(r"[-_.]", clean_domain)

    # Add variations
    result = set(words)
    for word in words:
        if len(word) > 3:
            result.add(word.lower())
            result.add(word.capitalize())
            result.add(word.upper())

    return list(result)


def generate_mutations(word):
    """Generate common mutations of a word"""
    mutations = set([word])

    # Leet speak substitutions
    leet_map = {"a": "@", "e": "3", "i": "1", "o": "0", "s": "$", "t": "7"}

    leet_word = word.lower()
    for char, replacement in leet_map.items():
        leet_word = leet_word.replace(char, replacement)
    mutations.add(leet_word)

    # Common variations
    mutations.add(word + "123")
    mutations.add(word + "!")
    mutations.add(word + "2024")
    mutations.add(word + "2025")
    mutations.add("admin" + word)
    mutations.add(word + "admin")

    return list(mutations)


def crawl_website_words(url, max_pages=5):
    """Crawl website to extract words from content"""
    words = set()
    visited = set()
    to_visit = [url]

    for _ in range(max_pages):
        if not to_visit:
            break

        current_url = to_visit.pop(0)
        if current_url in visited:
            continue

        try:
            response = requests.get(current_url, timeout=10, verify=True)
            visited.add(current_url)

            # Extract words from content
            text_content = re.sub(r"<[^>]+>", " ", response.text)
            page_words = re.findall(r"\b[a-zA-Z]{3,}\b", text_content)
            words.update([w.lower() for w in page_words if len(w) > 3])

            # Find internal links
            links = re.findall(r'href=["\'](.*?)["\']', response.text)
            for link in links[:5]:  # Limit links per page
                if link.startswith("/"):
                    full_link = urljoin(current_url, link)
                    if full_link not in visited and full_link not in to_visit:
                        to_visit.append(full_link)

        except Exception as e:
            click.secho(f"[!] Error crawling {current_url}: {e}", fg="red")

    return list(words)


def generate_date_variations(year=None, month=None, day=None):
    """Generate date-based wordlist variations"""
    dates = set()

    if not year:
        year = time.strftime("%Y")
    if not month:
        month = time.strftime("%m")
    if not day:
        day = time.strftime("%d")

    # Various date formats
    dates.add(f"{year}")
    dates.add(f"{year}{month}")
    dates.add(f"{year}{month}{day}")
    dates.add(f"{month}{day}{year}")
    dates.add(f"{day}{month}{year}")
    dates.add(f"{year}-{month}-{day}")
    dates.add(f"{month}/{day}/{year}")

    return list(dates)


def load_external_wordlist(wordlist_path):
    """Load words from external wordlist file"""
    try:
        with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
            words = [
                line.strip() for line in f if line.strip() and not line.startswith("#")
            ]
        return words
    except Exception as e:
        click.secho(f"[!] Error loading wordlist {wordlist_path}: {e}", fg="red")
        return []


def smart_wordlist_filter(words, min_length=3, max_length=50, remove_duplicates=True):
    """Intelligent filtering of wordlist"""
    if remove_duplicates:
        words = list(set(words))

    # Filter by length
    filtered = [w for w in words if min_length <= len(w) <= max_length]

    # Remove obviously bad words
    bad_patterns = [
        r"^[0-9]+$",  # Only numbers
        r"^[^a-zA-Z0-9]+$",  # Only special chars
        r"(.)\1{4,}",  # Repeated chars (aaaaa)
    ]

    clean_words = []
    for word in filtered:
        is_bad = False
        for pattern in bad_patterns:
            if re.match(pattern, word):
                is_bad = True
                break
        if not is_bad:
            clean_words.append(word)

    return clean_words


def generate_pattern_wordlist(words, pattern_type="credential", custom_patterns=None):
    """Generate wordlist based on specific patterns"""
    result = set()
    patterns = custom_patterns or PATTERN_TEMPLATES.get(pattern_type, [])

    for word in words:
        for pattern in patterns:
            try:
                generated = pattern.format(word=word, domain="example.com", year="2024")
                result.add(generated)
            except:
                continue

    return list(result)


def frequency_analysis(wordlist, top_n=100):
    """Analyze word frequency and return most common patterns"""
    word_counter = Counter(wordlist)

    # Character frequency analysis
    char_freq = Counter()
    for word in wordlist:
        char_freq.update(word.lower())

    # Length distribution
    length_dist = Counter(len(word) for word in wordlist)

    # Pattern analysis (first/last chars, etc.)
    first_chars = Counter(word[0].lower() if word else "" for word in wordlist)
    last_chars = Counter(word[-1].lower() if word else "" for word in wordlist)

    return {
        "most_common_words": word_counter.most_common(top_n),
        "char_frequency": char_freq.most_common(26),
        "length_distribution": dict(length_dist),
        "first_char_freq": dict(first_chars),
        "last_char_freq": dict(last_chars),
    }


def apply_transformation_rules(words, rules=None, max_per_word=5):
    """Apply hashcat-style transformation rules to words"""
    if not rules:
        rules = list(TRANSFORMATION_RULES.keys())

    result = set()
    for word in words[:1000]:  # Limit to prevent explosion
        transformations = random.sample(rules, min(len(rules), max_per_word))
        for rule in transformations:
            if rule in TRANSFORMATION_RULES:
                try:
                    transformed = TRANSFORMATION_RULES[rule](word)
                    if transformed and len(transformed) <= 50:
                        result.add(transformed)
                except:
                    continue

    return list(result)


def generate_hybrid_wordlist(base_words, additional_sources=None):
    """Generate hybrid wordlist combining multiple intelligent sources"""
    result = set(base_words)

    # Markov chain-like generation based on existing words
    for word1, word2 in itertools.combinations(base_words[:20], 2):
        # Find common substrings
        matcher = SequenceMatcher(None, word1, word2)
        match = matcher.find_longest_match(0, len(word1), 0, len(word2))
        if match.size >= 3:
            common_part = word1[match.a : match.a + match.size]
            result.add(word1.replace(common_part, word2[:3]))
            result.add(word2.replace(common_part, word1[:3]))

    # Generate based on common patterns
    for word in base_words[:50]:
        # Year combinations
        for year in ["2020", "2021", "2022", "2023", "2024", "2025"]:
            result.add(f"{word}{year}")
            result.add(f"{year}{word}")

        # Number patterns
        for num in ["01", "02", "03", "123", "456", "789"]:
            result.add(f"{word}{num}")
            result.add(f"{num}{word}")

        # Special character patterns
        for char in ["!", "@", "#", "$", "%"]:
            result.add(f"{word}{char}")
            result.add(f"{char}{word}")

    return list(result)


def keyboard_pattern_generator(length_range=(4, 12)):
    """Generate keyboard-based patterns"""
    patterns = set()

    for pattern_name, pattern_chars in KEYBOARD_PATTERNS.items():
        for length in range(length_range[0], length_range[1] + 1):
            for start_pos in range(len(pattern_chars) - length + 1):
                patterns.add(pattern_chars[start_pos : start_pos + length])

    return list(patterns)


def password_pattern_generator(base_words, years=None):
    """Generate password-style patterns"""
    if not years:
        years = ["2020", "2021", "2022", "2023", "2024", "2025"]

    patterns = set()

    for word in base_words[:100]:  # Limit to prevent explosion
        for pattern in PASSWORD_PATTERNS:
            for year in years:
                try:
                    generated = pattern.format(word=word, year=year)
                    patterns.add(generated)
                except:
                    continue

    return list(patterns)


def osint_wordlist_enrichment(target, source_type="github"):
    """Enrich wordlist using OSINT sources"""
    words = set()

    if source_type == "github":
        try:
            url = OSINT_SOURCES["github"].format(query=target)
            response = requests.get(url, timeout=10, verify=True)
            if response.status_code == 200:
                data = response.json()
                for repo in data.get("items", [])[:10]:  # Limit results
                    name = repo.get("name", "")
                    description = repo.get("description", "")
                    # Extract words from repo names and descriptions
                    words.update(
                        re.findall(r"\b[a-zA-Z]{3,}\b", name + " " + description)
                    )
        except Exception as e:
            pass

    return list(words)


def smart_similarity_filter(wordlist, similarity_threshold=0.8):
    """Remove highly similar words to reduce redundancy"""
    filtered = []
    for word in wordlist:
        is_similar = False
        for existing in filtered:
            similarity = SequenceMatcher(None, word.lower(), existing.lower()).ratio()
            if similarity > similarity_threshold:
                is_similar = True
                break
        if not is_similar:
            filtered.append(word)

    return filtered


def generate_file_extension_combinations(base_words, categories=None):
    """Generate filename combinations with various extensions"""
    if not categories:
        categories = ["web", "config", "backup"]

    combinations = set()
    for word in base_words[:50]:  # Limit base words
        for category in categories:
            extensions = FILE_EXTENSIONS.get(category, [])
            for ext in extensions:
                combinations.add(f"{word}.{ext}")
                combinations.add(f"{word}_backup.{ext}")
                combinations.add(f"{word}_old.{ext}")

    return list(combinations)


def entropy_based_scoring(wordlist):
    """Score words based on entropy/randomness"""
    scored_words = []

    for word in wordlist:
        # Calculate character diversity
        char_set = set(word.lower())
        char_diversity = len(char_set) / len(word) if word else 0

        # Calculate pattern complexity
        has_upper = any(c.isupper() for c in word)
        has_lower = any(c.islower() for c in word)
        has_digit = any(c.isdigit() for c in word)
        has_special = any(not c.isalnum() for c in word)

        complexity_score = sum([has_upper, has_lower, has_digit, has_special])

        # Overall score
        entropy_score = (
            (char_diversity * 0.5) + (complexity_score * 0.3) + (len(word) / 50 * 0.2)
        )

        scored_words.append((word, entropy_score))

    # Sort by score (descending)
    scored_words.sort(key=lambda x: x[1], reverse=True)
    return [word for word, score in scored_words]


@click.command(name="makewordlist")
@click.option("--name", help="Target person's name")
@click.option("--surname", help="Target person's surname")
@click.option("--birth", help="Birth year/date")
@click.option("--city", help="Target city")
@click.option("--company", help="Target company name")
@click.option("--domain", help="Target domain (extract words automatically)")
@click.option("--url", help="URL to crawl with CeWL")
@click.option("--crawl-deep", is_flag=True, help="Deep website crawling (5 pages)")
@click.option("--kit", help="Kitrunner .kit path (e.g. kits/api-endpoints-kit)")
@click.option("--wordlist", help="External wordlist file to include")
@click.option(
    "--tech-stack",
    type=click.Choice(
        ["web", "api", "database", "cloud", "security", "mobile", "media"]
    ),
    help="Add technology-specific words",
)
@click.option(
    "--mutations", is_flag=True, help="Generate word mutations (leet speak, etc.)"
)
@click.option("--dates", is_flag=True, help="Generate date variations")
@click.option("--crunch-min", type=int, help="Minimum length for crunch")
@click.option("--crunch-max", type=int, help="Maximum length for crunch")
@click.option("--min-length", type=int, default=3, help="Minimum word length")
@click.option("--max-length", type=int, default=50, help="Maximum word length")
@click.option("--max-words", type=int, help="Maximum number of words in output")
@click.option(
    "--output-prefix", required=True, help="Prefix for output files (no extension)"
)
@click.option("--export-txt", is_flag=True, default=True, help="Export .txt")
@click.option("--export-json", is_flag=True, help="Export .json")
@click.option("--export-md", is_flag=True, help="Export .md with statistics")
@click.option("--full", is_flag=True, help="Enable all external sources")
@click.option(
    "--format", type=click.Choice(["ffuf", "hydra", "hashcat"]), help="Output format"
)
@click.option("--tag", help="Add tag header in output files")
@click.option(
    "--profile",
    type=click.Choice(
        [
            "corp",
            "login",
            "devops",
            "cloud",
            "ecommerce",
            "social",
            "healthcare",
            "education",
            "finance",
        ]
    ),
    help="Inject profile-specific words",
)
@click.option("--verbose", "-v", is_flag=True, help="Verbose output")
@click.option(
    "--pattern",
    type=click.Choice(
        ["credential", "subdomain", "directory", "filename", "parameter", "endpoint"]
    ),
    help="Generate words based on specific patterns",
)
@click.option(
    "--custom-patterns",
    help="Custom pattern file (one pattern per line, use {word} placeholder)",
)
@click.option(
    "--hybrid", is_flag=True, help="Enable hybrid/intelligent wordlist generation"
)
@click.option(
    "--frequency-analysis",
    "enable_frequency_analysis",
    is_flag=True,
    help="Include frequency analysis in output",
)
@click.option(
    "--transform-rules",
    help="Apply transformation rules (comma-separated: caps,lower,reverse,etc.)",
)
@click.option(
    "--keyboard-patterns", is_flag=True, help="Include keyboard-based patterns"
)
@click.option(
    "--password-patterns", is_flag=True, help="Generate password-style patterns"
)
@click.option("--osint-target", help="Target for OSINT enrichment (GitHub repos, etc.)")
@click.option(
    "--file-extensions",
    help="Include file extension combinations (comma-separated categories)",
)
@click.option(
    "--entropy-sort", is_flag=True, help="Sort output by entropy/complexity score"
)
@click.option(
    "--similarity-filter",
    type=float,
    default=0.0,
    help="Remove similar words (0.0-1.0 threshold)",
)
@click.option("--advanced", is_flag=True, help="Enable ALL advanced features")
def makewordlist(
    name,
    surname,
    birth,
    city,
    company,
    domain,
    url,
    crawl_deep,
    kit,
    wordlist,
    tech_stack,
    mutations,
    dates,
    crunch_min,
    crunch_max,
    min_length,
    max_length,
    max_words,
    output_prefix,
    export_txt,
    export_json,
    export_md,
    full,
    format,
    tag,
    profile,
    verbose,
    pattern,
    custom_patterns,
    hybrid,
    enable_frequency_analysis,
    transform_rules,
    keyboard_patterns,
    password_patterns,
    osint_target,
    file_extensions,
    entropy_sort,
    similarity_filter,
    advanced,
):
    """🎯 Generate custom wordlists using inputs + advanced techniques"""
    base_words = list(filter(None, [name, surname, birth, city, company]))
    final = set()
    stats = {"sources": [], "total_words": 0, "filtered_words": 0}

    click.secho("[*] 🎯 Starting advanced wordlist generation...", fg="cyan")

    # Enable all advanced features if --advanced flag is used
    if advanced:
        click.secho("[+] 🚀 ADVANCED MODE: All features enabled", fg="yellow")
        full = True
        mutations = True
        dates = True
        hybrid = True
        keyboard_patterns = True
        password_patterns = True
        enable_frequency_analysis = True
        entropy_sort = True
        similarity_filter = similarity_filter or 0.8
        crawl_deep = True
        if not transform_rules:
            transform_rules = "caps,lower,reverse,substitute_similar"

    if verbose:
        click.secho(f"[*] Input words: {base_words}", fg="blue")

    # Add profile-specific words
    if profile:
        profile_words = PROFILES.get(profile, [])
        base_words.extend(profile_words)
        stats["sources"].append(f"Profile ({profile}): {len(profile_words)} words")
        if verbose:
            click.secho(
                f"[+] Profile '{profile}': {len(profile_words)} words", fg="blue"
            )

    # Extract words from domain
    if domain:
        domain_words = extract_words_from_domain(domain)
        base_words.extend(domain_words)
        stats["sources"].append(f"Domain analysis: {len(domain_words)} words")
        if verbose:
            click.secho(f"[+] Domain '{domain}': {len(domain_words)} words", fg="blue")

    # Add technology stack words
    if tech_stack:
        tech_words = TECH_STACKS.get(tech_stack, [])
        base_words.extend(tech_words)
        stats["sources"].append(f"Tech stack ({tech_stack}): {len(tech_words)} words")
        if verbose:
            click.secho(
                f"[+] Tech stack '{tech_stack}': {len(tech_words)} words", fg="blue"
            )

    # Generate basic combinations
    for r in range(1, 4):  # Increased range
        for combo in itertools.permutations(base_words, r):
            word = "".join(combo)
            if len(word) >= min_length:
                final.add(word)
                # Add with prefixes and postfixes
                for prefix in PREFIXES:
                    final.add(prefix + word)
                    final.add(prefix + "_" + word)
                for postfix in POSTFIXES:
                    final.add(word + postfix)

    # Add year variations
    for word in base_words:
        for year in YEARS:
            final.add(word + year)
            final.add(year + word)

    if full:
        click.secho("[+] 🚀 FULL MODE: All sources enabled", fg="yellow")
        crunch_min = crunch_min or 6
        crunch_max = crunch_max or 12
        mutations = True
        dates = True
        crawl_deep = True

    # External wordlist
    if wordlist and Path(wordlist).exists():
        external_words = load_external_wordlist(wordlist)
        final.update(external_words)
        stats["sources"].append(f"External wordlist: {len(external_words)} words")
        if verbose:
            click.secho(
                f"[+] External wordlist: {len(external_words)} words", fg="green"
            )

    # CeWL crawling
    if full or url:
        if url:
            click.secho(f"[+] 🕷️  CeWL crawling: {url}", fg="green")
            try:
                cewl_words = run_cewl(url)
                final.update(cewl_words)
                stats["sources"].append(f"CeWL crawling: {len(cewl_words)} words")
                if verbose:
                    click.secho(f"[+] CeWL found: {len(cewl_words)} words", fg="green")
            except Exception as e:
                click.secho(f"[!] CeWL error: {e}", fg="red")

    # Deep website crawling
    if crawl_deep and url:
        click.secho("[+] 🌐 Deep website crawling...", fg="green")
        try:
            crawl_words = crawl_website_words(url, max_pages=5)
            final.update(crawl_words)
            stats["sources"].append(f"Deep crawling: {len(crawl_words)} words")
            if verbose:
                click.secho(
                    f"[+] Deep crawl found: {len(crawl_words)} words", fg="green"
                )
        except Exception as e:
            click.secho(f"[!] Crawling error: {e}", fg="red")

    # Pydictor combinations
    if full or len(base_words) > 0:
        click.secho("[+] 🔗 Running pydictor combinations...", fg="green")
        try:
            pydictor_words = run_pydictor(base_words, min_length, max_length)
            final.update(pydictor_words)
            stats["sources"].append(f"Pydictor: {len(pydictor_words)} words")
            if verbose:
                click.secho(
                    f"[+] Pydictor generated: {len(pydictor_words)} words", fg="green"
                )
        except Exception as e:
            if verbose:
                click.secho(f"[!] Pydictor not available: {e}", fg="yellow")

    # Crunch generation
    if full or (crunch_min and crunch_max):
        click.secho(f"[+] 🎲 Running crunch ({crunch_min}-{crunch_max})...", fg="green")
        try:
            crunch_words = run_crunch(crunch_min, crunch_max)
            final.update(crunch_words)
            stats["sources"].append(f"Crunch: {len(crunch_words)} words")
            if verbose:
                click.secho(
                    f"[+] Crunch generated: {len(crunch_words)} words", fg="green"
                )
        except Exception as e:
            if verbose:
                click.secho(f"[!] Crunch not available: {e}", fg="yellow")

    # Kitrunner
    if full or kit:
        if kit and Path(kit).exists():
            click.secho(f"[+] 🛠️  Kitrunner: {kit}", fg="green")
            try:
                kit_words = run_kitrunner(kit)
                final.update(kit_words)
                stats["sources"].append(f"Kitrunner: {len(kit_words)} words")
                if verbose:
                    click.secho(
                        f"[+] Kitrunner generated: {len(kit_words)} words", fg="green"
                    )
            except Exception as e:
                if verbose:
                    click.secho(f"[!] Kitrunner error: {e}", fg="yellow")
        elif kit:
            click.secho(f"[!] Kit not found: {kit}", fg="red")

    # Word mutations
    if mutations:
        click.secho("[+] 🧬 Generating word mutations...", fg="green")
        original_count = len(final)
        mutated_words = set()
        for word in list(final)[:1000]:  # Limit to prevent explosion
            mutated_words.update(generate_mutations(word))
        final.update(mutated_words)
        new_count = len(final) - original_count
        stats["sources"].append(f"Mutations: {new_count} words")
        if verbose:
            click.secho(f"[+] Generated {new_count} mutations", fg="green")

    # Date variations
    if dates:
        click.secho("[+] 📅 Adding date variations...", fg="green")
        date_words = generate_date_variations()
        original_count = len(final)
        # Combine dates with existing words
        for word in list(final)[:500]:  # Limit combinations
            for date in date_words:
                final.add(word + date)
                final.add(date + word)
        new_count = len(final) - original_count
        stats["sources"].append(f"Date variations: {new_count} words")
        if verbose:
            click.secho(f"[+] Generated {new_count} date variations", fg="green")

    # Advanced Pattern Generation
    if pattern or custom_patterns:
        click.secho("[+] 🎨 Generating pattern-based wordlist...", fg="green")
        if custom_patterns and Path(custom_patterns).exists():
            # Load custom patterns from file
            with open(custom_patterns, "r") as f:
                patterns = [line.strip() for line in f if line.strip()]
            pattern_words = generate_pattern_wordlist(
                base_words, custom_patterns=patterns
            )
        else:
            pattern_words = generate_pattern_wordlist(base_words, pattern_type=pattern)

        final.update(pattern_words)
        stats["sources"].append(f"Pattern generation: {len(pattern_words)} words")
        if verbose:
            click.secho(
                f"[+] Pattern generated: {len(pattern_words)} words", fg="green"
            )

    # Hybrid/Intelligent Generation
    if hybrid:
        click.secho("[+] 🧠 Generating hybrid/intelligent wordlist...", fg="green")
        hybrid_words = generate_hybrid_wordlist(list(final)[:200])  # Limit input
        original_count = len(final)
        final.update(hybrid_words)
        new_count = len(final) - original_count
        stats["sources"].append(f"Hybrid generation: {new_count} words")
        if verbose:
            click.secho(f"[+] Hybrid generated: {new_count} words", fg="green")

    # Transformation Rules
    if transform_rules:
        click.secho("[+] 🔄 Applying transformation rules...", fg="green")
        rules = [r.strip() for r in transform_rules.split(",")]
        transformed_words = apply_transformation_rules(list(final)[:500], rules)
        original_count = len(final)
        final.update(transformed_words)
        new_count = len(final) - original_count
        stats["sources"].append(f"Transformations: {new_count} words")
        if verbose:
            click.secho(f"[+] Transformations: {new_count} words", fg="green")

    # Keyboard Patterns
    if keyboard_patterns:
        click.secho("[+] ⌨️  Adding keyboard patterns...", fg="green")
        kb_patterns = keyboard_pattern_generator()
        final.update(kb_patterns)
        stats["sources"].append(f"Keyboard patterns: {len(kb_patterns)} words")
        if verbose:
            click.secho(f"[+] Keyboard patterns: {len(kb_patterns)} words", fg="green")

    # Password Patterns
    if password_patterns:
        click.secho("[+] 🔐 Generating password patterns...", fg="green")
        pwd_patterns = password_pattern_generator(base_words)
        final.update(pwd_patterns)
        stats["sources"].append(f"Password patterns: {len(pwd_patterns)} words")
        if verbose:
            click.secho(f"[+] Password patterns: {len(pwd_patterns)} words", fg="green")

    # OSINT Enrichment
    if osint_target:
        click.secho(f"[+] 🔍 OSINT enrichment for: {osint_target}", fg="green")
        osint_words = osint_wordlist_enrichment(osint_target)
        final.update(osint_words)
        stats["sources"].append(f"OSINT enrichment: {len(osint_words)} words")
        if verbose:
            click.secho(f"[+] OSINT found: {len(osint_words)} words", fg="green")

    # File Extension Combinations
    if file_extensions:
        click.secho("[+] 📁 Adding file extension combinations...", fg="green")
        categories = [cat.strip() for cat in file_extensions.split(",")]
        file_combos = generate_file_extension_combinations(base_words, categories)
        final.update(file_combos)
        stats["sources"].append(f"File extensions: {len(file_combos)} words")
        if verbose:
            click.secho(f"[+] File combinations: {len(file_combos)} words", fg="green")

    # Smart filtering
    click.secho("[+] 🧹 Filtering and cleaning wordlist...", fg="cyan")
    stats["total_words"] = len(final)
    sorted_final = smart_wordlist_filter(
        list(final),
        min_length=min_length,
        max_length=max_length,
        remove_duplicates=True,
    )
    stats["filtered_words"] = len(sorted_final)

    # Apply similarity filter if requested
    if similarity_filter > 0:
        click.secho(
            f"[+] 🔍 Applying similarity filter ({similarity_filter})...", fg="cyan"
        )
        original_count = len(sorted_final)
        sorted_final = smart_similarity_filter(sorted_final, similarity_filter)
        filtered_count = original_count - len(sorted_final)
        if verbose:
            click.secho(f"[+] Removed {filtered_count} similar words", fg="blue")

    # Sort by entropy/complexity if requested
    if entropy_sort:
        click.secho("[+] 📊 Sorting by entropy/complexity...", fg="cyan")
        sorted_final = entropy_based_scoring(sorted_final)
        if verbose:
            click.secho("[+] Words sorted by complexity score", fg="blue")
    else:
        sorted_final = sorted(sorted_final)

    # Limit output size if requested
    if max_words and len(sorted_final) > max_words:
        click.secho(f"[*] Limiting output to {max_words} words", fg="yellow")
        sorted_final = sorted_final[:max_words]

    # Export files
    if export_txt:
        txt_file = output_prefix + ".txt"
        with open(txt_file, "w") as f:
            if tag:
                f.write(f"# Wordlist: {tag}\n")
                f.write(f"# Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"# Total words: {len(sorted_final)}\n\n")

            if format == "ffuf":
                for w in sorted_final:
                    f.write(f"FUZZ={w}\n")
            elif format == "hydra":
                for w in sorted_final:
                    f.write(f"{w}\n")
            elif format == "hashcat":
                for w in sorted_final:
                    f.write(f"{w}\n")
            else:
                for w in sorted_final:
                    f.write(w + "\n")
        click.secho(
            f"[✓] 📝 .txt saved: {txt_file} ({len(sorted_final)} words)", fg="green"
        )

    if export_json:
        json_file = output_prefix + ".json"
        json_data = {
            "metadata": {
                "generated": time.strftime("%Y-%m-%d %H:%M:%S"),
                "tag": tag,
                "total_words": len(sorted_final),
                "sources": stats["sources"],
                "parameters": {
                    "min_length": min_length,
                    "max_length": max_length,
                    "max_words": max_words,
                    "format": format,
                },
            },
            "wordlist": sorted_final,
        }
        with open(json_file, "w") as f:
            json.dump(json_data, f, indent=2)
        click.secho(f"[✓] 📋 .json saved: {json_file}", fg="green")

    if export_md:
        md_file = output_prefix + ".md"
        with open(md_file, "w") as f:
            f.write(f"# Wordlist Report: {tag or 'Custom'}\n\n")
            f.write(f"**Generated:** {time.strftime('%Y-%m-%d %H:%M:%S')}  \n")
            f.write(f"**Total Words:** {len(sorted_final)}  \n")
            f.write(f"**Filter Settings:** {min_length}-{max_length} chars  \n")
            if similarity_filter > 0:
                f.write(f"**Similarity Filter:** {similarity_filter}  \n")
            if entropy_sort:
                f.write(f"**Sorting:** Entropy/complexity based  \n")
            f.write("\n")

            f.write("## Sources\n\n")
            for source in stats["sources"]:
                f.write(f"- {source}\n")

            f.write(f"\n## Statistics\n\n")
            f.write(f"- **Raw words collected:** {stats['total_words']}\n")
            f.write(f"- **After filtering:** {stats['filtered_words']}\n")
            f.write(f"- **Final output:** {len(sorted_final)}\n")

            # Frequency analysis if enabled
            if enable_frequency_analysis and len(sorted_final) > 0:
                freq_stats = frequency_analysis(sorted_final)
                f.write(f"\n## Frequency Analysis\n\n")
                f.write(f"### Most Common Words\n")
                for word, count in freq_stats["most_common_words"][:10]:
                    f.write(f"- `{word}`: {count}\n")

                f.write(f"\n### Length Distribution\n")
                for length, count in sorted(freq_stats["length_distribution"].items()):
                    f.write(f"- Length {length}: {count} words\n")

                f.write(f"\n### Character Patterns\n")
                f.write(
                    f"**Most common first characters:** {', '.join([f'{char}({count})' for char, count in list(freq_stats['first_char_freq'].items())[:5]])}\n"
                )
                f.write(
                    f"**Most common last characters:** {', '.join([f'{char}({count})' for char, count in list(freq_stats['last_char_freq'].items())[:5]])}\n"
                )

            f.write(f"\n## Sample Words\n\n")
            f.write("```\n")
            for word in sorted_final[:20]:  # Show first 20 words
                f.write(f"{word}\n")
            if len(sorted_final) > 20:
                f.write("...\n")
            f.write("```\n")

        click.secho(f"[✓] 📊 .md report saved: {md_file}", fg="green")

    # Print summary
    click.secho(f"\n🎉 Wordlist generation complete!", fg="green", bold=True)
    click.secho(f"📊 Final wordlist: {len(sorted_final)} words", fg="cyan")
    click.secho(f"📁 Files saved with prefix: {output_prefix}", fg="cyan")

    if verbose:
        click.secho(f"\n📈 Generation Summary:", fg="cyan")
        for source in stats["sources"]:
            click.secho(f"  • {source}", fg="blue")
        click.secho(f"  • Total collected: {stats['total_words']} words", fg="blue")
        click.secho(f"  • After filtering: {len(sorted_final)} words", fg="blue")


makewordlist.short_help = "🎯 Advanced wordlist generator with AI patterns, hybrid generation, entropy analysis, and multi-source intelligence"

if __name__ == "__main__":
    makewordlist()
