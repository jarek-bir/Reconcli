import click
import subprocess
import tempfile
import os
import json
import re
from datetime import datetime
from pathlib import Path


@click.command()
@click.option(
    "--input",
    "-i",
    required=True,
    type=click.Path(exists=True),
    help="Input file (e.g. subdomains, words)",
)
@click.option(
    "--output",
    "-o",
    required=True,
    type=click.Path(),
    help="Output file with generated permutations",
)
@click.option(
    "--tool",
    type=click.Choice(
        [
            "internal",
            "gotator",
            "goaltdns",
            "dnstwist",
            "dnsgen",
            "urlcrazy",
            "shuffledns",
            "dmut",
            "s3scanner",
            "alterx",
            "kr",
            "sublist3r",
            "amass",
            "subfinder",
            "assetfinder",
            "findomain",
        ],
        case_sensitive=False,
    ),
    default="internal",
    help="Tool to use for permutation",
)
@click.option(
    "--keywords", type=str, help="Comma-separated keywords (e.g. dev,test,stage)"
)
@click.option("--brand", type=str, help="Optional brand name (e.g. tesla)")
@click.option(
    "--year",
    type=str,
    default=str(datetime.now().year),
    help="Year to include in permutations",
)
@click.option("--uniq", is_flag=True, help="Remove duplicates from output")
@click.option("--domain", type=str, help="Target domain for DNS-based tools")
@click.option("--wordlist", type=click.Path(exists=True), help="Custom wordlist file")
@click.option(
    "--permutation-type",
    type=click.Choice(
        ["subdomains", "paths", "buckets", "parameters", "api"], case_sensitive=False
    ),
    default="subdomains",
    help="Type of permutations to generate",
)
@click.option(
    "--threads",
    "-t",
    type=int,
    default=50,
    help="Number of threads for tools that support it",
)
@click.option("--depth", type=int, default=2, help="Permutation depth")
@click.option(
    "--format",
    type=click.Choice(["txt", "json"], case_sensitive=False),
    default="txt",
    help="Output format",
)
@click.option("--verbose", "-v", is_flag=True, help="Verbose output")
@click.option(
    "--resolve", is_flag=True, help="Resolve generated domains (for DNS tools)"
)
@click.option(
    "--cloud-provider",
    type=click.Choice(["aws", "gcp", "azure", "all"], case_sensitive=False),
    default="aws",
    help="Cloud provider for bucket enumeration",
)
@click.option(
    "--api-endpoints", is_flag=True, help="Generate API endpoint permutations"
)
@click.option("--advanced", is_flag=True, help="Enable advanced permutation patterns")
@click.option("--max-results", type=int, help="Maximum number of results to generate")
@click.option(
    "--timeout", type=int, default=300, help="Timeout in seconds for external tools"
)
@click.option("--silent", is_flag=True, help="Silent mode - minimal output")
@click.option(
    "--output-format",
    type=click.Choice(["simple", "detailed", "csv"], case_sensitive=False),
    default="simple",
    help="Output format style",
)
@click.option(
    "--patterns", type=str, help="Custom patterns file for advanced generation"
)
@click.option(
    "--exclude", type=str, help="Comma-separated patterns to exclude from results"
)
@click.option("--include-tlds", is_flag=True, help="Include common TLD variations")
@click.option(
    "--numbers", is_flag=True, help="Include number variations (01, 02, 123, etc.)"
)
@click.option(
    "--years", type=str, help="Comma-separated years to include (default: current year)"
)
@click.option(
    "--mode", 
    type=click.Choice(["full", "tldinject"], case_sensitive=False),
    default="full",
    help="Generation mode: full (all permutations) or tldinject (TLD variations only)"
)
@click.option(
    "--tld-list", 
    type=click.Path(exists=True),
    help="Custom TLD list file (instead of hardcoded TLDs)"
)
@click.option(
    "--www-prefix", 
    is_flag=True,
    help="Generate only www. + TLD variations (for tldinject mode)"
)
@click.option(
    "--dry-run", 
    is_flag=True,
    help="Show only the number of permutations without generating them"
)
def permutcli(
    input,
    output,
    tool,
    keywords,
    brand,
    year,
    uniq,
    domain,
    wordlist,
    permutation_type,
    threads,
    depth,
    format,
    verbose,
    resolve,
    cloud_provider,
    api_endpoints,
    advanced,
    max_results,
    timeout,
    silent,
    output_format,
    patterns,
    exclude,
    include_tlds,
    numbers,
    years,
    mode,
    tld_list,
    www_prefix,
    dry_run,
):
    """🔄 Generate permutations of subdomains, paths, buckets, or parameters using various advanced tools.

    Supports multiple specialized tools for different use cases:
    - DNS: dnstwist, dnsgen, shuffledns, dmut, alterx, sublist3r, amass, subfinder, assetfinder, findomain
    - URLs: urlcrazy, gotator, goaltdns
    - Cloud: s3scanner
    - APIs: kr (kitrunner)
    - Internal: advanced built-in generator
    """

    if silent:
        verbose = False

    if verbose and not silent:
        click.secho(f"[*] 🔄 Starting permutation generation with {tool}", fg="cyan")
        click.secho(f"[*] 📁 Input: {input}", fg="blue")
        click.secho(f"[*] 📝 Output: {output}", fg="blue")
        click.secho(f"[*] 🎯 Type: {permutation_type}", fg="blue")

    # 🧱 Load base words
    try:
        with open(input, "r", encoding="utf-8", errors="ignore") as f:
            base_items = [line.strip() for line in f if line.strip()]

        if verbose and not silent:
            click.secho(f"[+] 📋 Loaded {len(base_items)} base items", fg="green")
    except Exception as e:
        click.secho(f"[!] ❌ Error reading input file: {e}", fg="red")
        return

    # 🧱 Build keywords list
    keyword_list = []
    if keywords:
        keyword_list.extend([k.strip() for k in keywords.split(",")])
    if brand:
        keyword_list.append(brand)
    if year:
        keyword_list.append(year)

    # Add years if specified
    if years:
        keyword_list.extend([y.strip() for y in years.split(",")])

    # Add common permutation words based on type
    if advanced:
        common_words = get_common_words(permutation_type)
        keyword_list.extend(common_words)

    # Add numbers if requested
    if numbers:
        number_variations = ["01", "02", "03", "1", "2", "3", "123", "2024", "2025"]
        keyword_list.extend(number_variations)

    if verbose and not silent and keyword_list:
        click.secho(
            f"[+] 🔑 Keywords: {', '.join(keyword_list[:10])}{'...' if len(keyword_list) > 10 else ''}",
            fg="green",
        )

    # Handle special modes
    if mode == "tldinject":
        if verbose and not silent:
            click.secho("[*] 🎯 TLD injection mode enabled", fg="cyan")
        results = run_tld_inject_mode(
            base_items, tld_list, www_prefix, dry_run, verbose
        )
        
        if dry_run:
            click.secho(f"[*] 📊 Would generate {len(results)} TLD permutations", fg="blue")
            return
        
        # Process and save results for TLD mode
        if uniq and results:
            original_count = len(results)
            results = list(set(results))
            if verbose and not silent:
                click.secho(
                    f"[+] 🔍 Removed {original_count - len(results)} duplicates",
                    fg="yellow",
                )
        
        if max_results and len(results) > max_results:
            results = results[:max_results]
            if verbose and not silent:
                click.secho(f"[+] 🔢 Limited to {max_results} results", fg="yellow")
        
        save_results(results, output, format, verbose)
        
        if not silent:
            click.secho(
                f"\n[✓] 🎉 Generated {len(results)} TLD permutations",
                fg="green",
                bold=True,
            )
            click.secho(f"[✓] 📁 Saved to: {output}", fg="green")
        return

    # Route to appropriate tool
    try:
        if tool == "internal":
            results = run_internal_permutator(
                base_items,
                keyword_list,
                permutation_type,
                advanced,
                verbose,
                include_tlds,
                patterns,
                tld_list,
                www_prefix,
            )
        elif tool == "dnstwist":
            results = run_dnstwist(base_items, domain, verbose, timeout)
        elif tool == "dnsgen":
            results = run_dnsgen(base_items, wordlist, verbose, timeout)
        elif tool == "urlcrazy":
            results = run_urlcrazy(base_items, domain, verbose, timeout)
        elif tool == "shuffledns":
            results = run_shuffledns(
                base_items, keyword_list, resolve, threads, verbose, timeout
            )
        elif tool == "dmut":
            results = run_dmut(base_items, keyword_list, threads, verbose, timeout)
        elif tool == "s3scanner":
            results = run_s3scanner(
                base_items, keyword_list, cloud_provider, verbose, timeout
            )
        elif tool == "alterx":
            results = run_alterx(base_items, keyword_list, verbose, timeout)
        elif tool == "kr":
            results = run_kitrunner_api(
                base_items, keyword_list, api_endpoints, verbose, timeout
            )
        elif tool == "gotator":
            results = run_gotator(base_items, keyword_list, depth, verbose, timeout)
        elif tool == "goaltdns":
            results = run_goaltdns(base_items, keyword_list, verbose, timeout)
        elif tool == "sublist3r":
            results = run_sublist3r(base_items, domain, verbose, timeout)
        elif tool == "amass":
            results = run_amass(base_items, domain, verbose, timeout)
        elif tool == "subfinder":
            results = run_subfinder(base_items, domain, verbose, timeout)
        elif tool == "assetfinder":
            results = run_assetfinder(base_items, domain, verbose, timeout)
        elif tool == "findomain":
            results = run_findomain(base_items, domain, verbose, timeout)
        else:
            click.secho(f"[!] ❌ Unknown tool: {tool}", fg="red")
            return

        # Handle dry-run mode
        if dry_run:
            click.secho(f"[*] 📊 Would generate {len(results)} permutations using {tool}", fg="blue")
            return

        # Process results
        if results:
            # Apply exclusion filter if provided
            if exclude:
                exclude_patterns = [p.strip() for p in exclude.split(",")]
                original_count = len(results)
                results = [
                    r
                    for r in results
                    if not any(pattern in r for pattern in exclude_patterns)
                ]
                if verbose and not silent:
                    click.secho(
                        f"[+] 🚫 Excluded {original_count - len(results)} results",
                        fg="yellow",
                    )

            # Apply max results limit if specified
            if max_results and len(results) > max_results:
                results = results[:max_results]
                if verbose and not silent:
                    click.secho(f"[+] 🔢 Limited to {max_results} results", fg="yellow")

        if uniq and results:
            original_count = len(results)
            results = list(set(results))
            if verbose and not silent:
                click.secho(
                    f"[+] 🔍 Removed {original_count - len(results)} duplicates",
                    fg="yellow",
                )

        # Save output
        save_results(results, output, format, verbose)

        # Summary
        if not silent:
            click.secho(
                f"\n[✓] 🎉 Generated {len(results)} permutations using {tool}",
                fg="green",
                bold=True,
            )
            click.secho(f"[✓] 📁 Saved to: {output}", fg="green")

    except Exception as e:
        click.secho(f"[!] ❌ Error during permutation: {e}", fg="red")


def get_common_words(permutation_type):
    """Get common words for different permutation types"""
    words = {
        "subdomains": [
            "dev",
            "test",
            "stage",
            "staging",
            "prod",
            "www",
            "api",
            "admin",
            "portal",
            "app",
            "beta",
            "alpha",
            "demo",
            "sandbox",
            "qa",
            "uat",
            "preprod",
            "internal",
            "external",
        ],
        "paths": [
            "admin",
            "api",
            "login",
            "dashboard",
            "panel",
            "config",
            "backup",
            "test",
            "dev",
            "staging",
            "assets",
            "static",
            "uploads",
            "files",
            "data",
            "tmp",
            "temp",
        ],
        "buckets": [
            "backup",
            "backups",
            "data",
            "logs",
            "assets",
            "static",
            "uploads",
            "files",
            "downloads",
            "archive",
            "storage",
            "media",
            "images",
            "documents",
        ],
        "parameters": [
            "id",
            "user",
            "admin",
            "token",
            "key",
            "session",
            "auth",
            "login",
            "password",
            "email",
            "name",
            "value",
            "data",
            "file",
            "path",
            "url",
            "redirect",
        ],
        "api": [
            "v1",
            "v2",
            "v3",
            "api",
            "rest",
            "graphql",
            "users",
            "auth",
            "admin",
            "config",
            "health",
            "status",
            "metrics",
            "logs",
            "data",
            "files",
            "search",
            "query",
        ],
    }
    return words.get(permutation_type, [])


def run_internal_permutator(
    base_items,
    keyword_list,
    permutation_type,
    advanced,
    verbose,
    include_tlds,
    patterns,
    tld_list_file=None,
    www_prefix=False,
):
    """Enhanced internal permutation generator"""
    if verbose:
        click.secho("[*] 🔧 Using enhanced internal permutator...", fg="cyan")

    results = []

    # Load custom patterns if provided
    custom_patterns = []
    if patterns and os.path.exists(patterns):
        try:
            with open(patterns, "r") as f:
                custom_patterns = [line.strip() for line in f if line.strip()]
            if verbose:
                click.secho(
                    f"[+] 📜 Loaded {len(custom_patterns)} custom patterns", fg="green"
                )
        except Exception as e:
            click.secho(f"[!] ⚠️  Error loading patterns file: {e}", fg="yellow")

    # Basic patterns
    for base in base_items:
        for word in keyword_list:
            if permutation_type == "subdomains":
                results.extend(
                    [
                        f"{word}.{base}",
                        f"{base}.{word}",
                        f"{word}-{base}",
                        f"{base}-{word}",
                        f"{base}{word}",
                        f"{word}{base}",
                    ]
                )
            elif permutation_type == "paths":
                results.extend(
                    [
                        f"/{word}/{base}",
                        f"/{base}/{word}",
                        f"/{word}-{base}",
                        f"/{base}-{word}",
                        f"/{word}_{base}",
                        f"/{base}_{word}",
                    ]
                )
            elif permutation_type == "buckets":
                results.extend(
                    [
                        f"{word}-{base}",
                        f"{base}-{word}",
                        f"{word}.{base}",
                        f"{base}.{word}",
                        f"{word}_{base}",
                        f"{base}_{word}",
                    ]
                )
            elif permutation_type == "api":
                results.extend(
                    [
                        f"/api/{word}/{base}",
                        f"/api/v1/{word}",
                        f"/api/v2/{base}",
                        f"/{word}/api/{base}",
                        f"/rest/{word}",
                        f"/graphql/{base}",
                    ]
                )

    # Add TLD variations if requested
    if include_tlds:
        # Load custom TLD list if provided
        if tld_list_file:
            try:
                with open(tld_list_file, "r") as f:
                    common_tlds = [line.strip() for line in f if line.strip() and not line.startswith("#")]
                if verbose:
                    click.secho(f"[+] 📜 Loaded {len(common_tlds)} custom TLDs for internal generator", fg="green")
            except Exception as e:
                click.secho(f"[!] ⚠️  Error loading TLD list: {e}, using defaults", fg="yellow")
                common_tlds = ["com", "net", "org", "io", "co", "dev", "app", "cloud"]
        else:
            common_tlds = ["com", "net", "org", "io", "co", "dev", "app", "cloud"]
        
        for base in base_items[:20]:  # Limit to prevent explosion
            for tld in common_tlds:
                if permutation_type == "subdomains":
                    if www_prefix:
                        results.append(f"www.{base}.{tld}")
                    else:
                        results.extend([f"{base}.{tld}", f"www.{base}.{tld}"])

    # Apply custom patterns if provided
    if custom_patterns:
        for base in base_items[:20]:
            for pattern in custom_patterns[:10]:
                for word in keyword_list[:5]:
                    # Replace placeholders in patterns
                    custom_result = pattern.replace("{base}", base).replace(
                        "{word}", word
                    )
                    results.append(custom_result)

    # Advanced patterns if enabled
    if advanced:
        numbers = ["1", "2", "01", "02", "123", "2024", "2025"]
        separators = ["-", "_", ".", ""]

        for base in base_items[:20]:  # Limit to prevent explosion
            for word in keyword_list[:10]:
                for num in numbers:
                    for sep in separators:
                        if permutation_type == "subdomains":
                            results.extend(
                                [
                                    f"{word}{sep}{num}.{base}",
                                    f"{base}{sep}{num}.{word}",
                                ]
                            )
                        elif permutation_type == "buckets":
                            results.extend(
                                [
                                    f"{word}{sep}{num}-{base}",
                                    f"{base}{sep}{num}-{word}",
                                ]
                            )

    if verbose:
        click.secho(
            f"[+] 🎯 Generated {len(results)} internal permutations", fg="green"
        )

    return results


def run_dnstwist(base_items, domain, verbose, timeout):
    """Run dnstwist for domain permutations"""
    if verbose:
        click.secho("[*] 🌀 Running dnstwist...", fg="cyan")

    if not domain:
        click.secho("[!] ⚠️  Domain required for dnstwist", fg="yellow")
        return []

    results = []
    try:
        cmd = ["dnstwist", "--format", "list", domain]
        if verbose:
            click.secho(f"[*] 🔧 Command: {' '.join(cmd)}", fg="blue")

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        if result.returncode == 0:
            results = [
                line.strip() for line in result.stdout.split("\n") if line.strip()
            ]
            if verbose:
                click.secho(
                    f"[+] 🎯 dnstwist found {len(results)} permutations", fg="green"
                )
        else:
            click.secho(f"[!] ❌ dnstwist error: {result.stderr}", fg="red")
    except subprocess.TimeoutExpired:
        click.secho("[!] ⏱️  dnstwist timeout", fg="yellow")
    except FileNotFoundError:
        click.secho("[!] 📦 dnstwist not installed", fg="red")
    except Exception as e:
        click.secho(f"[!] ❌ dnstwist error: {e}", fg="red")

    return results


def run_dnsgen(base_items, wordlist, verbose, timeout):
    """Run dnsgen for subdomain generation"""
    if verbose:
        click.secho("[*] 🧬 Running dnsgen...", fg="cyan")

    results = []
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", delete=False, suffix=".txt"
        ) as tmp_input:
            tmp_input.write("\n".join(base_items))
            tmp_input_path = tmp_input.name

        cmd = ["dnsgen"]
        if wordlist:
            cmd.extend(["-w", wordlist])
        cmd.append(tmp_input_path)

        if verbose:
            click.secho(f"[*] 🔧 Command: {' '.join(cmd)}", fg="blue")

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        if result.returncode == 0:
            results = [
                line.strip() for line in result.stdout.split("\n") if line.strip()
            ]
            if verbose:
                click.secho(
                    f"[+] 🎯 dnsgen generated {len(results)} subdomains", fg="green"
                )
        else:
            click.secho(f"[!] ❌ dnsgen error: {result.stderr}", fg="red")

        os.unlink(tmp_input_path)
    except subprocess.TimeoutExpired:
        click.secho("[!] ⏱️  dnsgen timeout", fg="yellow")
    except FileNotFoundError:
        click.secho("[!] 📦 dnsgen not installed", fg="red")
    except Exception as e:
        click.secho(f"[!] ❌ dnsgen error: {e}", fg="red")

    return results


def run_urlcrazy(base_items, domain, verbose, timeout):
    """Run urlcrazy for URL permutations"""
    if verbose:
        click.secho("[*] 🔀 Running urlcrazy...", fg="cyan")

    if not domain:
        click.secho("[!] ⚠️  Domain required for urlcrazy", fg="yellow")
        return []

    results = []
    try:
        cmd = ["urlcrazy", "-r", domain]  # -r for no resolve, cleaner output
        if verbose:
            click.secho(f"[*] 🔧 Command: {' '.join(cmd)}", fg="blue")

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        if result.returncode == 0:
            results = [
                line.strip() for line in result.stdout.split("\n") if line.strip()
            ]
            if verbose:
                click.secho(
                    f"[+] 🎯 urlcrazy found {len(results)} permutations", fg="green"
                )
        else:
            click.secho(f"[!] ❌ urlcrazy error: {result.stderr}", fg="red")
    except subprocess.TimeoutExpired:
        click.secho("[!] ⏱️  urlcrazy timeout", fg="yellow")
    except FileNotFoundError:
        click.secho("[!] 📦 urlcrazy not installed", fg="red")
    except Exception as e:
        click.secho(f"[!] ❌ urlcrazy error: {e}", fg="red")

    return results


def run_shuffledns(base_items, keyword_list, resolve, threads, verbose, timeout):
    """Run shuffledns for subdomain permutation and resolution"""
    if verbose:
        click.secho("[*] 🔀 Running shuffledns...", fg="cyan")

    results = []
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", delete=False, suffix=".txt"
        ) as tmp_domains:
            tmp_domains.write("\n".join(base_items))
            tmp_domains_path = tmp_domains.name

        with tempfile.NamedTemporaryFile(
            mode="w", delete=False, suffix=".txt"
        ) as tmp_words:
            tmp_words.write("\n".join(keyword_list))
            tmp_words_path = tmp_words.name

        cmd = [
            "shuffledns",
            "-mode",
            "bruteforce",
            "-d",
            tmp_domains_path,
            "-w",
            tmp_words_path,
            "-r",
            "/home/jarek/reconcli_dnscli_full/reconcli/wordlists/resolvers-trickest.txt",
            "-t",
            str(threads),
            "-silent",
        ]

        if verbose:
            click.secho(f"[*] 🔧 Command: {' '.join(cmd)}", fg="blue")

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        if result.returncode == 0:
            results = [
                line.strip() for line in result.stdout.split("\n") if line.strip()
            ]
            if verbose:
                click.secho(
                    f"[+] 🎯 shuffledns generated {len(results)} results", fg="green"
                )
        else:
            click.secho(f"[!] ❌ shuffledns error: {result.stderr}", fg="red")

        os.unlink(tmp_domains_path)
        os.unlink(tmp_words_path)
    except subprocess.TimeoutExpired:
        click.secho("[!] ⏱️  shuffledns timeout", fg="yellow")
    except FileNotFoundError:
        click.secho("[!] 📦 shuffledns not installed", fg="red")
    except Exception as e:
        click.secho(f"[!] ❌ shuffledns error: {e}", fg="red")

    return results


def run_dmut(base_items, keyword_list, threads, verbose, timeout):
    """Run dmut for subdomain mutation"""
    if verbose:
        click.secho("[*] 🧬 Running dmut...", fg="cyan")

    results = []
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", delete=False, suffix=".txt"
        ) as tmp_words:
            tmp_words.write("\n".join(keyword_list))
            tmp_words_path = tmp_words.name

        with tempfile.NamedTemporaryFile(
            mode="w", delete=False, suffix=".txt"
        ) as tmp_output:
            tmp_output_path = tmp_output.name

        # dmut expects -d for dictionary and -w for workers (number)
        # Use first domain from base_items as target
        target_domain = base_items[0] if base_items else "example.com"
        
        cmd = ["dmut", "-u", target_domain, "-d", tmp_words_path, "-w", str(threads), "-o", tmp_output_path]
        if verbose:
            click.secho(f"[*] 🔧 Command: {' '.join(cmd)}", fg="blue")

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        if result.returncode == 0 and os.path.exists(tmp_output_path):
            with open(tmp_output_path, "r") as f:
                results = [line.strip() for line in f if line.strip()]
            if verbose:
                click.secho(
                    f"[+] 🎯 dmut generated {len(results)} mutations", fg="green"
                )
        else:
            click.secho(f"[!] ❌ dmut error: {result.stderr}", fg="red")

        os.unlink(tmp_words_path)
        if os.path.exists(tmp_output_path):
            os.unlink(tmp_output_path)
    except subprocess.TimeoutExpired:
        click.secho("[!] ⏱️  dmut timeout", fg="yellow")
    except FileNotFoundError:
        click.secho("[!] 📦 dmut not installed", fg="red")
    except Exception as e:
        click.secho(f"[!] ❌ dmut error: {e}", fg="red")

    return results


def run_s3scanner(base_items, keyword_list, cloud_provider, verbose, timeout):
    """Run S3Scanner for bucket enumeration"""
    if verbose:
        click.secho("[*] ☁️  Running S3Scanner...", fg="cyan")

    results = []

    # Generate bucket names
    bucket_names = []
    for base in base_items:
        for keyword in keyword_list:
            bucket_names.extend(
                [
                    f"{base}-{keyword}",
                    f"{keyword}-{base}",
                    f"{base}.{keyword}",
                    f"{keyword}.{base}",
                    f"{base}{keyword}",
                    f"{keyword}{base}",
                ]
            )

    try:
        with tempfile.NamedTemporaryFile(
            mode="w", delete=False, suffix=".txt"
        ) as tmp_buckets:
            tmp_buckets.write("\n".join(bucket_names))
            tmp_buckets_path = tmp_buckets.name

        cmd = ["s3scanner", "scan", "-bucket-file", tmp_buckets_path]
        if cloud_provider != "all":
            cmd.extend(["--provider", cloud_provider])

        if verbose:
            click.secho(f"[*] 🔧 Command: {' '.join(cmd)}", fg="blue")

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        if result.returncode == 0:
            results = [
                line.strip() for line in result.stdout.split("\n") if line.strip()
            ]
            if verbose:
                click.secho(
                    f"[+] 🎯 S3Scanner found {len(results)} buckets", fg="green"
                )
        else:
            click.secho(f"[!] ❌ S3Scanner error: {result.stderr}", fg="red")

        os.unlink(tmp_buckets_path)
    except subprocess.TimeoutExpired:
        click.secho("[!] ⏱️  S3Scanner timeout", fg="yellow")
    except FileNotFoundError:
        click.secho("[!] 📦 S3Scanner not installed", fg="red")
    except Exception as e:
        click.secho(f"[!] ❌ S3Scanner error: {e}", fg="red")

    return results


def run_alterx(base_items, keyword_list, verbose, timeout):
    """Run alterx for advanced subdomain generation"""
    if verbose:
        click.secho("[*] 🔄 Running alterx...", fg="cyan")

    results = []
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", delete=False, suffix=".txt"
        ) as tmp_input:
            tmp_input.write("\n".join(base_items))
            tmp_input_path = tmp_input.name

        cmd = ["alterx", "-l", tmp_input_path]
        if keyword_list:
            with tempfile.NamedTemporaryFile(
                mode="w", delete=False, suffix=".txt"
            ) as tmp_patterns:
                tmp_patterns.write("\n".join(keyword_list))
                tmp_patterns_path = tmp_patterns.name
                cmd.extend(["-p", tmp_patterns_path])

        if verbose:
            click.secho(f"[*] 🔧 Command: {' '.join(cmd)}", fg="blue")

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        if result.returncode == 0:
            results = [
                line.strip() for line in result.stdout.split("\n") if line.strip()
            ]
            if verbose:
                click.secho(
                    f"[+] 🎯 alterx generated {len(results)} permutations", fg="green"
                )
        else:
            click.secho(f"[!] ❌ alterx error: {result.stderr}", fg="red")

        os.unlink(tmp_input_path)
        if keyword_list and "tmp_patterns_path" in locals():
            os.unlink(tmp_patterns_path)
    except subprocess.TimeoutExpired:
        click.secho("[!] ⏱️  alterx timeout", fg="yellow")
    except FileNotFoundError:
        click.secho("[!] 📦 alterx not installed", fg="red")
    except Exception as e:
        click.secho(f"[!] ❌ alterx error: {e}", fg="red")

    return results


def run_kitrunner_api(base_items, keyword_list, api_endpoints, verbose, timeout):
    """Run kitrunner (kr) for API endpoint generation and scanning"""
    if verbose:
        click.secho("[*] 🛠️  Running kitrunner (kr) for API endpoints...", fg="cyan")

    results = []

    # Try to use real kitrunner first
    try:
        # Create a temporary file with target URLs
        target_urls = []
        for item in base_items:
            # Assume these are domains/URLs
            if not item.startswith("http"):
                target_urls.extend([f"http://{item}", f"https://{item}"])
            else:
                target_urls.append(item)

        with tempfile.NamedTemporaryFile(
            mode="w", delete=False, suffix=".txt"
        ) as tmp_targets:
            tmp_targets.write("\n".join(target_urls))
            tmp_targets_path = tmp_targets.name

        # Use apiroutes wordlist for API scanning
        cmd = [
            "kr",
            "scan",
            tmp_targets_path,
            "-A",
            "apiroutes-250628",
            "-q",
            "-o",
            "json",
        ]

        if verbose:
            click.secho(f"[*] 🔧 Command: {' '.join(cmd)}", fg="blue")

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)

        if result.returncode == 0 and result.stdout.strip():
            # Parse JSON output from kr
            lines = result.stdout.strip().split("\n")
            for line in lines:
                try:
                    data = json.loads(line)
                    if "url" in data:
                        results.append(data["url"])
                except json.JSONDecodeError:
                    continue

            if verbose:
                click.secho(
                    f"[+] 🎯 kitrunner found {len(results)} API endpoints", fg="green"
                )
        else:
            if verbose:
                click.secho(
                    f"[!] ⚠️  kitrunner returned no results, falling back to internal patterns",
                    fg="yellow",
                )
            raise Exception("No results from kitrunner")

        os.unlink(tmp_targets_path)

    except (FileNotFoundError, subprocess.TimeoutExpired, Exception) as e:
        if verbose:
            if isinstance(e, FileNotFoundError):
                click.secho(
                    "[!] 📦 kitrunner (kr) not found, using internal API patterns",
                    fg="yellow",
                )
            elif isinstance(e, subprocess.TimeoutExpired):
                click.secho(
                    "[!] ⏱️  kitrunner timeout, using internal patterns", fg="yellow"
                )
            else:
                click.secho(
                    f"[!] ❌ kitrunner error: {e}, using internal patterns", fg="yellow"
                )

        # Fallback to internal pattern generation
        api_patterns = []
        for base in base_items:
            for keyword in keyword_list:
                api_patterns.extend(
                    [
                        f"/api/{base}",
                        f"/api/v1/{base}",
                        f"/api/v2/{base}",
                        f"/rest/{base}",
                        f"/{base}/api",
                        f"/graphql/{base}",
                        f"/api/{keyword}/{base}",
                        f"/api/{base}/{keyword}",
                    ]
                )

        results = api_patterns
        if verbose:
            click.secho(
                f"[*] 🎯 Generated {len(api_patterns)} internal API patterns",
                fg="green",
            )

    return results


def run_gotator(base_items, keyword_list, depth, verbose, timeout):
    """Run gotator with improved configuration"""
    if verbose:
        click.secho("[*] 🎯 Running gotator...", fg="cyan")

    results = []
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", delete=False, suffix=".txt"
        ) as tmp_input:
            tmp_input.write("\n".join(base_items))
            tmp_input_path = tmp_input.name

        with tempfile.NamedTemporaryFile(
            mode="w", delete=False, suffix=".txt"
        ) as tmp_prefix:
            tmp_prefix.write("\n".join(keyword_list))
            tmp_prefix_path = tmp_prefix.name

        cmd = [
            "gotator",
            "-sub",
            tmp_input_path,
            "-perm",
            tmp_prefix_path,
            "-depth",
            str(depth),
            "-silent",
        ]

        if verbose:
            click.secho(f"[*] 🔧 Command: {' '.join(cmd)}", fg="blue")

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        if result.returncode == 0:
            results = [
                line.strip() for line in result.stdout.split("\n") if line.strip()
            ]
            if verbose:
                click.secho(
                    f"[+] 🎯 gotator generated {len(results)} permutations", fg="green"
                )
        else:
            click.secho(f"[!] ❌ gotator error: {result.stderr}", fg="red")

        os.unlink(tmp_input_path)
        os.unlink(tmp_prefix_path)
    except subprocess.TimeoutExpired:
        click.secho("[!] ⏱️  gotator timeout", fg="yellow")
    except FileNotFoundError:
        click.secho("[!] 📦 gotator not installed", fg="red")
    except Exception as e:
        click.secho(f"[!] ❌ gotator error: {e}", fg="red")

    return results


def run_goaltdns(base_items, keyword_list, verbose, timeout):
    """Run goaltdns with improved configuration"""
    if verbose:
        click.secho("[*] 🎯 Running goaltdns...", fg="cyan")

    results = []
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", delete=False, suffix=".txt"
        ) as tmp_input:
            tmp_input.write("\n".join(base_items))
            tmp_input_path = tmp_input.name

        with tempfile.NamedTemporaryFile(
            mode="w", delete=False, suffix=".txt"
        ) as tmp_words:
            tmp_words.write("\n".join(keyword_list))
            tmp_words_path = tmp_words.name

        with tempfile.NamedTemporaryFile(
            mode="w", delete=False, suffix=".txt"
        ) as tmp_output:
            tmp_output_path = tmp_output.name

        cmd = [
            "goaltdns",
            "-l",
            tmp_input_path,
            "-w",
            tmp_words_path,
            "-o",
            tmp_output_path,
        ]

        if verbose:
            click.secho(f"[*] 🔧 Command: {' '.join(cmd)}", fg="blue")

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        if result.returncode == 0:
            with open(tmp_output_path, "r") as f:
                results = [line.strip() for line in f if line.strip()]
            if verbose:
                click.secho(
                    f"[+] 🎯 goaltdns generated {len(results)} permutations", fg="green"
                )
        else:
            click.secho(f"[!] ❌ goaltdns error: {result.stderr}", fg="red")

        os.unlink(tmp_input_path)
        os.unlink(tmp_words_path)
        os.unlink(tmp_output_path)
    except subprocess.TimeoutExpired:
        click.secho("[!] ⏱️  goaltdns timeout", fg="yellow")
    except FileNotFoundError:
        click.secho("[!] 📦 goaltdns not installed", fg="red")
    except Exception as e:
        click.secho(f"[!] ❌ goaltdns error: {e}", fg="red")

    return results


def run_sublist3r(base_items, domain, verbose, timeout):
    """Run sublist3r for subdomain enumeration"""
    if verbose:
        click.secho("[*] 🔍 Running sublist3r...", fg="cyan")

    if not domain:
        click.secho("[!] ⚠️  Domain required for sublist3r", fg="yellow")
        return []

    results = []
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", delete=False, suffix=".txt"
        ) as tmp_output:
            tmp_output_path = tmp_output.name

        cmd = ["sublist3r", "-d", domain, "-o", tmp_output_path]
        if verbose:
            click.secho(f"[*] 🔧 Command: {' '.join(cmd)}", fg="blue")

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        if result.returncode == 0 and os.path.exists(tmp_output_path):
            with open(tmp_output_path, "r") as f:
                results = [line.strip() for line in f if line.strip()]
            if verbose:
                click.secho(
                    f"[+] 🎯 sublist3r found {len(results)} subdomains", fg="green"
                )
        else:
            click.secho(f"[!] ❌ sublist3r error: {result.stderr}", fg="red")

        if os.path.exists(tmp_output_path):
            os.unlink(tmp_output_path)
    except subprocess.TimeoutExpired:
        click.secho("[!] ⏱️  sublist3r timeout", fg="yellow")
    except FileNotFoundError:
        click.secho("[!] 📦 sublist3r not installed", fg="red")
    except Exception as e:
        click.secho(f"[!] ❌ sublist3r error: {e}", fg="red")

    return results


def run_amass(base_items, domain, verbose, timeout):
    """Run amass for subdomain enumeration"""
    if verbose:
        click.secho("[*] 🌊 Running amass...", fg="cyan")

    if not domain:
        click.secho("[!] ⚠️  Domain required for amass", fg="yellow")
        return []

    results = []
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", delete=False, suffix=".txt"
        ) as tmp_output:
            tmp_output_path = tmp_output.name

        cmd = ["amass", "enum", "-d", domain, "-o", tmp_output_path]
        if verbose:
            click.secho(f"[*] 🔧 Command: {' '.join(cmd)}", fg="blue")

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        if result.returncode == 0 and os.path.exists(tmp_output_path):
            with open(tmp_output_path, "r") as f:
                results = [line.strip() for line in f if line.strip()]
            if verbose:
                click.secho(f"[+] 🎯 amass found {len(results)} subdomains", fg="green")
        else:
            click.secho(f"[!] ❌ amass error: {result.stderr}", fg="red")

        if os.path.exists(tmp_output_path):
            os.unlink(tmp_output_path)
    except subprocess.TimeoutExpired:
        click.secho("[!] ⏱️  amass timeout", fg="yellow")
    except FileNotFoundError:
        click.secho("[!] 📦 amass not installed", fg="red")
    except Exception as e:
        click.secho(f"[!] ❌ amass error: {e}", fg="red")

    return results


def run_subfinder(base_items, domain, verbose, timeout):
    """Run subfinder for subdomain enumeration"""
    if verbose:
        click.secho("[*] 🔎 Running subfinder...", fg="cyan")

    if not domain:
        click.secho("[!] ⚠️  Domain required for subfinder", fg="yellow")
        return []

    results = []
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", delete=False, suffix=".txt"
        ) as tmp_output:
            tmp_output_path = tmp_output.name

        cmd = ["subfinder", "-d", domain, "-o", tmp_output_path, "-silent"]
        if verbose:
            click.secho(f"[*] 🔧 Command: {' '.join(cmd)}", fg="blue")

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        if result.returncode == 0 and os.path.exists(tmp_output_path):
            with open(tmp_output_path, "r") as f:
                results = [line.strip() for line in f if line.strip()]
            if verbose:
                click.secho(
                    f"[+] 🎯 subfinder found {len(results)} subdomains", fg="green"
                )
        else:
            click.secho(f"[!] ❌ subfinder error: {result.stderr}", fg="red")

        if os.path.exists(tmp_output_path):
            os.unlink(tmp_output_path)
    except subprocess.TimeoutExpired:
        click.secho("[!] ⏱️  subfinder timeout", fg="yellow")
    except FileNotFoundError:
        click.secho("[!] 📦 subfinder not installed", fg="red")
    except Exception as e:
        click.secho(f"[!] ❌ subfinder error: {e}", fg="red")

    return results


def run_assetfinder(base_items, domain, verbose, timeout):
    """Run assetfinder for subdomain enumeration"""
    if verbose:
        click.secho("[*] 🏢 Running assetfinder...", fg="cyan")

    if not domain:
        click.secho("[!] ⚠️  Domain required for assetfinder", fg="yellow")
        return []

    results = []
    try:
        cmd = ["assetfinder", "--subs-only", domain]
        if verbose:
            click.secho(f"[*] 🔧 Command: {' '.join(cmd)}", fg="blue")

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        if result.returncode == 0:
            results = [
                line.strip() for line in result.stdout.split("\n") if line.strip()
            ]
            if verbose:
                click.secho(
                    f"[+] 🎯 assetfinder found {len(results)} subdomains", fg="green"
                )
        else:
            click.secho(f"[!] ❌ assetfinder error: {result.stderr}", fg="red")
    except subprocess.TimeoutExpired:
        click.secho("[!] ⏱️  assetfinder timeout", fg="yellow")
    except FileNotFoundError:
        click.secho("[!] 📦 assetfinder not installed", fg="red")
    except Exception as e:
        click.secho(f"[!] ❌ assetfinder error: {e}", fg="red")

    return results


def run_findomain(base_items, domain, verbose, timeout):
    """Run findomain for subdomain enumeration"""
    if verbose:
        click.secho("[*] 🌐 Running findomain...", fg="cyan")

    if not domain:
        click.secho("[!] ⚠️  Domain required for findomain", fg="yellow")
        return []

    results = []
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", delete=False, suffix=".txt"
        ) as tmp_output:
            tmp_output.write("\n".join(base_items))
            tmp_output_path = tmp_output.name

        cmd = ["findomain", "--target", domain, "--unique-output", tmp_output_path]
        if verbose:
            click.secho(f"[*] 🔧 Command: {' '.join(cmd)}", fg="blue")

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        if result.returncode == 0 and os.path.exists(tmp_output_path):
            with open(tmp_output_path, "r") as f:
                results = [line.strip() for line in f if line.strip()]
            if verbose:
                click.secho(
                    f"[+] 🎯 findomain found {len(results)} subdomains", fg="green"
                )
        else:
            click.secho(f"[!] ❌ findomain error: {result.stderr}", fg="red")

        if os.path.exists(tmp_output_path):
            os.unlink(tmp_output_path)
    except subprocess.TimeoutExpired:
        click.secho("[!] ⏱️  findomain timeout", fg="yellow")
    except FileNotFoundError:
        click.secho("[!] 📦 findomain not installed", fg="red")
    except Exception as e:
        click.secho(f"[!] ❌ findomain error: {e}", fg="red")

    return results


def save_results(results, output, format_type, verbose):
    """Save results in specified format"""
    if not results:
        click.secho("[!] ⚠️  No results to save", fg="yellow")
        return

    try:
        if format_type == "json":
            output_data = {
                "timestamp": datetime.now().isoformat(),
                "total_results": len(results),
                "results": results,
            }
            with open(output, "w") as f:
                json.dump(output_data, f, indent=2)
        else:  # txt format
            with open(output, "w") as f:
                f.write("\n".join(results) + "\n")

        if verbose:
            click.secho(f"[+] 💾 Saved {len(results)} results to {output}", fg="green")
    except Exception as e:
        click.secho(f"[!] ❌ Error saving results: {e}", fg="red")


def run_tld_inject_mode(base_items, tld_list_file, www_prefix, dry_run, verbose):
    """Run TLD injection mode - generate only TLD variations"""
    if verbose:
        click.secho("[*] 🌐 Running TLD injection mode...", fg="cyan")
    
    results = []
    
    # Load custom TLD list if provided
    if tld_list_file:
        try:
            with open(tld_list_file, "r") as f:
                tlds = [line.strip() for line in f if line.strip() and not line.startswith("#")]
            if verbose:
                click.secho(f"[+] 📜 Loaded {len(tlds)} custom TLDs", fg="green")
        except Exception as e:
            click.secho(f"[!] ⚠️  Error loading TLD list: {e}, using defaults", fg="yellow")
            tlds = ["com", "net", "org", "io", "co", "dev", "app", "cloud", "xyz", "online"]
    else:
        # Extended default TLD list
        tlds = [
            "com", "net", "org", "io", "co", "dev", "app", "cloud", "xyz", "online",
            "tech", "pro", "biz", "info", "site", "store", "shop", "blog", "news",
            "global", "digital", "ai", "ml", "data", "security", "host", "domains"
        ]
    
    # Generate TLD variations
    for base in base_items:
        # Remove existing TLD if present
        if "." in base:
            domain_base = base.split(".")[0]
        else:
            domain_base = base
        
        for tld in tlds:
            if www_prefix:
                # Generate only www. variations
                results.append(f"www.{domain_base}.{tld}")
            else:
                # Generate both plain and www variations
                results.extend([
                    f"{domain_base}.{tld}",
                    f"www.{domain_base}.{tld}"
                ])
    
    if verbose and not dry_run:
        click.secho(f"[+] 🎯 Generated {len(results)} TLD variations", fg="green")
    
    return results


if __name__ == "__main__":
    permutcli()
