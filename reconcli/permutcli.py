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
    required=False,
    type=click.Path(exists=True),
    help="Input file (e.g. subdomains, words)",
)
@click.option(
    "--output",
    "-o",
    required=False,
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
@click.option(
    "--brand",
    type=str,
    help="Brand name(s) - single brand or comma-separated list (e.g. tesla or tesla,zoom,slack)",
)
@click.option(
    "--brand-from-file",
    type=click.Path(exists=True),
    help="Load brand names from file (one per line)",
)
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
    help="Generation mode: full (all permutations) or tldinject (TLD variations only)",
)
@click.option(
    "--tld-list",
    type=click.Path(exists=True),
    help="Custom TLD list file (instead of hardcoded TLDs)",
)
@click.option(
    "--www-prefix",
    is_flag=True,
    help="Generate only www. + TLD variations (for tldinject mode)",
)
@click.option(
    "--dry-run",
    is_flag=True,
    help="Show only the number of permutations without generating them",
)
@click.option(
    "--mutate-case", is_flag=True, help="Add case-based variations (Dev, DEV, dev)"
)
@click.option(
    "--exclude-keywords",
    type=str,
    help="Comma-separated keywords to exclude from generation",
)
@click.option(
    "--filter", type=str, help="Comma-separated patterns to keep only matching results"
)
@click.option("--chunk", type=int, help="Split output into chunks of N lines each")
@click.option(
    "--prefix-only",
    is_flag=True,
    help="Generate only prefix-based permutations (keyword.domain)",
)
@click.option(
    "--suffix-only",
    is_flag=True,
    help="Generate only suffix-based permutations (domain.keyword)",
)
@click.option(
    "--inject-suffix",
    type=str,
    help="Comma-separated suffixes to append before TLDs (e.g. -cdn,-edge,-backup)",
)
@click.option(
    "--inject-prefix",
    type=str,
    help="Comma-separated prefixes to prepend to domains (e.g. dev-,staging-,test-)",
)
@click.option(
    "--exclude-tlds",
    type=str,
    help="Comma-separated TLDs to exclude from generation (e.g. gov,edu,mil)",
)
@click.option(
    "--update-resolvers",
    is_flag=True,
    help="Download/update DNS resolver lists for tools like shuffledns",
)
@click.option(
    "--store-db",
    is_flag=True,
    help="Store results in ReconCLI database for persistent storage and analysis",
)
@click.option(
    "--target-domain",
    help="Primary target domain for database storage (auto-detected if not provided)",
)
@click.option("--program", help="Bug bounty program name for database classification")
def permutcli(
    input,
    output,
    tool,
    keywords,
    brand,
    brand_from_file,
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
    mutate_case,
    exclude_keywords,
    filter,
    chunk,
    prefix_only,
    suffix_only,
    inject_suffix,
    inject_prefix,
    exclude_tlds,
    update_resolvers,
    store_db,
    target_domain,
    program,
):
    """🔄 Generate permutations of subdomains, paths, buckets, or parameters using various advanced tools.

    Supports multiple specialized tools for different use cases:
    - DNS: dnstwist, dnsgen, shuffledns, dmut, alterx, sublist3r, amass, subfinder, assetfinder, findomain
    - URLs: urlcrazy, gotator, goaltdns
    - Cloud: s3scanner
    - APIs: kr (kitrunner)
    - Internal: advanced built-in generator
    """

    # Handle --update-resolvers first
    if update_resolvers:
        update_dns_resolvers(verbose)
        return

    # Check required parameters if not updating resolvers
    if not input:
        click.secho(
            "[!] ❌ Error: --input/-i is required (unless using --update-resolvers)",
            fg="red",
        )
        return

    if not output:
        click.secho(
            "[!] ❌ Error: --output/-o is required (unless using --update-resolvers)",
            fg="red",
        )
        return

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

    # Handle brand options - support both single/multi brands and file input
    if brand:
        # Support comma-separated brands in --brand option
        brand_names = [b.strip() for b in brand.split(",")]
        keyword_list.extend(brand_names)
        if verbose and not silent:
            click.secho(
                f"[+] 🏷️  Added brands from --brand: {', '.join(brand_names)}",
                fg="green",
            )

    if brand_from_file:
        # Load brands from file
        try:
            with open(brand_from_file, "r", encoding="utf-8", errors="ignore") as f:
                brand_names_from_file = [line.strip() for line in f if line.strip()]
            keyword_list.extend(brand_names_from_file)
            if verbose and not silent:
                click.secho(
                    f"[+] 📁 Loaded {len(brand_names_from_file)} brands from file: {brand_from_file}",
                    fg="green",
                )
                click.secho(
                    f"[+] 🏷️  Brands: {', '.join(brand_names_from_file[:5])}{'...' if len(brand_names_from_file) > 5 else ''}",
                    fg="blue",
                )
        except Exception as e:
            click.secho(f"[!] ❌ Error reading brand file: {e}", fg="red")
            return

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

    # Apply exclude-keywords filter
    if exclude_keywords:
        exclude_list = [k.strip().lower() for k in exclude_keywords.split(",")]
        keyword_list = [k for k in keyword_list if k.lower() not in exclude_list]
        if verbose and not silent:
            click.secho(
                f"[+] 🚫 Excluded keywords: {', '.join(exclude_list)}", fg="yellow"
            )

    # Apply case mutations if requested
    if mutate_case:
        # Apply case mutations to keywords
        original_keywords = keyword_list.copy()
        for keyword in original_keywords:
            if keyword.isalpha():  # Only for alphabetic keywords
                keyword_list.extend(
                    [
                        keyword.lower(),
                        keyword.upper(),
                        keyword.capitalize(),
                        keyword.title(),
                    ]
                )
        # Remove duplicates after case mutations
        keyword_list = list(set(keyword_list))

        # Apply case mutations to base items too
        original_base_items = base_items.copy()
        for item in original_base_items:
            if item.isalpha():  # Only for alphabetic items
                base_items.extend(
                    [
                        item.lower(),
                        item.upper(),
                        item.capitalize(),
                        item.title(),
                    ]
                )
        # Remove duplicates after case mutations
        base_items = list(set(base_items))

        if verbose and not silent:
            click.secho(f"[+] 🔤 Added case variations", fg="cyan")

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
            base_items,
            tld_list,
            www_prefix,
            inject_suffix,
            inject_prefix,
            exclude_tlds,
            dry_run,
            verbose,
        )

        if dry_run:
            click.secho(
                f"[*] 📊 Would generate {len(results)} TLD permutations", fg="blue"
            )
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

        # Handle chunking for TLD mode if requested
        if chunk and results:
            if verbose and not silent:
                click.secho(f"[+] 📦 Splitting into chunks of {chunk} lines", fg="cyan")

            total_chunks = (len(results) + chunk - 1) // chunk  # Ceiling division
            base_output = output.rsplit(".", 1)
            if len(base_output) == 2:
                base_name, extension = base_output
            else:
                base_name, extension = output, "txt"

            for i in range(total_chunks):
                start_idx = i * chunk
                end_idx = min((i + 1) * chunk, len(results))
                chunk_results = results[start_idx:end_idx]

                chunk_filename = f"{base_name}_chunk_{i+1:03d}.{extension}"
                save_results(chunk_results, chunk_filename, format, verbose)

                if verbose and not silent:
                    click.secho(
                        f"[+] 📁 Chunk {i+1}/{total_chunks}: {chunk_filename}",
                        fg="green",
                    )

            if not silent:
                click.secho(
                    f"\n[✓] 🎉 Generated {len(results)} TLD permutations in {total_chunks} chunks",
                    fg="green",
                    bold=True,
                )
            return

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
                prefix_only,
                suffix_only,
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
            click.secho(
                f"[*] 📊 Would generate {len(results)} permutations using {tool}",
                fg="blue",
            )
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

        # Apply filter if provided (keep only matching patterns)
        if filter and results:
            filter_patterns = [p.strip().lower() for p in filter.split(",")]
            original_count = len(results)
            results = [
                r
                for r in results
                if any(pattern in r.lower() for pattern in filter_patterns)
            ]
            if verbose and not silent:
                click.secho(
                    f"[+] 🔍 Filter kept {len(results)}/{original_count} results",
                    fg="cyan",
                )

        # Handle chunking if requested
        if chunk and results:
            if verbose and not silent:
                click.secho(f"[+] 📦 Splitting into chunks of {chunk} lines", fg="cyan")

            total_chunks = (len(results) + chunk - 1) // chunk  # Ceiling division
            base_output = output.rsplit(".", 1)
            if len(base_output) == 2:
                base_name, extension = base_output
            else:
                base_name, extension = output, "txt"

            for i in range(total_chunks):
                start_idx = i * chunk
                end_idx = min((i + 1) * chunk, len(results))
                chunk_results = results[start_idx:end_idx]

                chunk_filename = f"{base_name}_chunk_{i+1:03d}.{extension}"
                save_results(chunk_results, chunk_filename, format, verbose)

                if verbose and not silent:
                    click.secho(
                        f"[+] 📁 Chunk {i+1}/{total_chunks}: {chunk_filename}",
                        fg="green",
                    )

            if not silent:
                click.secho(
                    f"\n[✓] 🎉 Generated {len(results)} permutations in {total_chunks} chunks using {tool}",
                    fg="green",
                    bold=True,
                )
            return

        # Save output
        save_results(results, output, format, verbose)

        # Database storage
        if store_db and results:
            try:
                from reconcli.db.operations import (
                    store_target,
                    store_subdomain_permutation,
                )

                # Auto-detect target domain if not provided
                if not target_domain and results:
                    # Try to extract domain from first result (assuming subdomains)
                    first_result = results[0] if results else None
                    if first_result and "." in first_result:
                        parts = first_result.split(".")
                        if len(parts) >= 2:
                            target_domain = ".".join(parts[-2:])

                if target_domain:
                    # Ensure target exists in database
                    target_id = store_target(target_domain, program=program)

                    # Convert results to database format
                    permutation_data = []
                    for result in results:
                        perm_entry = {
                            "permutation": result,
                            "permutation_type": permutation_type or "general",
                            "tool_used": tool,
                            "resolved": False,  # Could be enhanced to check resolution
                            "timestamp": datetime.now().isoformat(),
                        }
                        permutation_data.append(perm_entry)

                    # Store permutations in database
                    stored_ids = store_subdomain_permutation(
                        target_domain, permutation_data
                    )

                    if verbose and not silent:
                        click.secho(
                            f"[+] 💾 Stored {len(stored_ids)} permutations in database for target: {target_domain}",
                            fg="cyan",
                        )
                else:
                    if verbose and not silent:
                        click.secho(
                            "[!] ⚠️  No target domain provided or detected for database storage",
                            fg="yellow",
                        )

            except ImportError:
                if verbose and not silent:
                    click.secho("[!] ⚠️  Database module not available", fg="yellow")
            except Exception as e:
                if verbose and not silent:
                    click.secho(f"[!] ❌ Database storage failed: {e}", fg="red")

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
    prefix_only=False,
    suffix_only=False,
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
                if prefix_only:
                    # Only prefix patterns (word.base)
                    results.extend(
                        [
                            f"{word}.{base}",
                            f"{word}-{base}",
                            f"{word}{base}",
                        ]
                    )
                elif suffix_only:
                    # Only suffix patterns (base.word)
                    results.extend(
                        [
                            f"{base}.{word}",
                            f"{base}-{word}",
                            f"{base}{word}",
                        ]
                    )
                else:
                    # All patterns (default)
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
                if prefix_only:
                    results.extend(
                        [
                            f"/{word}/{base}",
                            f"/{word}-{base}",
                            f"/{word}_{base}",
                        ]
                    )
                elif suffix_only:
                    results.extend(
                        [
                            f"/{base}/{word}",
                            f"/{base}-{word}",
                            f"/{base}_{word}",
                        ]
                    )
                else:
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
                if prefix_only:
                    results.extend(
                        [
                            f"{word}-{base}",
                            f"{word}.{base}",
                            f"{word}_{base}",
                        ]
                    )
                elif suffix_only:
                    results.extend(
                        [
                            f"{base}-{word}",
                            f"{base}.{word}",
                            f"{base}_{word}",
                        ]
                    )
                else:
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
                    common_tlds = [
                        line.strip()
                        for line in f
                        if line.strip() and not line.startswith("#")
                    ]
                if verbose:
                    click.secho(
                        f"[+] 📜 Loaded {len(common_tlds)} custom TLDs for internal generator",
                        fg="green",
                    )
            except Exception as e:
                click.secho(
                    f"[!] ⚠️  Error loading TLD list: {e}, using defaults", fg="yellow"
                )
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
        ) as tmp_generated:
            tmp_generated_path = tmp_generated.name

        # dmut expects -d for dictionary and -w for workers (number)
        # Use first domain from base_items as target
        target_domain = base_items[0] if base_items else "example.com"

        # Add DNS servers to avoid DNS server list issues
        cmd = [
            "dmut",
            "-u",
            target_domain,
            "-d",
            tmp_words_path,
            "-w",
            str(threads),
            "-l",
            "8.8.8.8,1.1.1.1,208.67.222.222",  # Add reliable DNS servers
            "--save-gen",
            "--save-to",
            tmp_generated_path,
        ]

        if verbose:
            click.secho(f"[*] 🔧 Command: {' '.join(cmd)}", fg="blue")

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        if result.returncode == 0 and os.path.exists(tmp_generated_path):
            with open(tmp_generated_path, "r") as f:
                results = [line.strip() for line in f if line.strip()]
            if verbose:
                click.secho(
                    f"[+] 🎯 dmut generated {len(results)} mutations", fg="green"
                )
        else:
            if verbose:
                click.secho(f"[!] ⚠️  dmut stderr: {result.stderr}", fg="yellow")
                click.secho(f"[!] ⚠️  dmut stdout: {result.stdout}", fg="yellow")

        os.unlink(tmp_words_path)
        if os.path.exists(tmp_generated_path):
            os.unlink(tmp_generated_path)
    except subprocess.TimeoutExpired:
        click.secho("[!] ⏱️  dmut timeout", fg="yellow")
    except FileNotFoundError:
        click.secho("[!] 📦 dmut not installed", fg="red")
    except Exception as e:
        click.secho(f"[!] ❌ dmut error: {e}", fg="red")

    return results


def run_s3scanner(base_items, keyword_list, cloud_provider, verbose, timeout):
    """Run S3Scanner for bucket enumeration with advanced permutations"""
    if verbose:
        click.secho("[*] ☁️  Running S3Scanner...", fg="cyan")

    results = []

    # Generate comprehensive bucket names using our advanced function
    bucket_names = []
    current_year = str(datetime.now().year)

    for base in base_items:
        # Use our advanced bucket permutation generator
        bucket_perms = generate_bucket_permutations(
            brand=base,
            keywords=keyword_list,
            suffixes=["-cdn", "-backup", "-static", "-assets", "-data", "-logs"],
            year=current_year,
            verbose=verbose,
        )
        bucket_names.extend(bucket_perms)

        # Also add simple combinations for backwards compatibility
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

    # Remove duplicates
    bucket_names = list(set(bucket_names))

    try:
        with tempfile.NamedTemporaryFile(
            mode="w", delete=False, suffix=".txt"
        ) as tmp_buckets:
            tmp_buckets.write("\n".join(bucket_names))
            tmp_buckets_path = tmp_buckets.name

        cmd = ["s3scanner", "-bucket-file", tmp_buckets_path]
        if cloud_provider != "all":
            cmd.extend(["-provider", cloud_provider])

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


def run_tld_inject_mode(
    base_items,
    tld_list_file,
    www_prefix,
    inject_suffix,
    inject_prefix,
    exclude_tlds,
    dry_run,
    verbose,
):
    """Run TLD injection mode - generate only TLD variations"""
    if verbose:
        click.secho("[*] 🌐 Running TLD injection mode...", fg="cyan")

    results = []

    # Load custom TLD list if provided
    if tld_list_file:
        try:
            with open(tld_list_file, "r") as f:
                tlds = [
                    line.strip()
                    for line in f
                    if line.strip() and not line.startswith("#")
                ]
            if verbose:
                click.secho(f"[+] 📜 Loaded {len(tlds)} custom TLDs", fg="green")
        except Exception as e:
            click.secho(
                f"[!] ⚠️  Error loading TLD list: {e}, using defaults", fg="yellow"
            )
            tlds = [
                "com",
                "net",
                "org",
                "io",
                "co",
                "dev",
                "app",
                "cloud",
                "xyz",
                "online",
            ]
    else:
        # Extended default TLD list
        tlds = [
            "com",
            "net",
            "org",
            "io",
            "co",
            "dev",
            "app",
            "cloud",
            "xyz",
            "online",
            "tech",
            "pro",
            "biz",
            "info",
            "site",
            "store",
            "shop",
            "blog",
            "news",
            "global",
            "digital",
            "ai",
            "ml",
            "data",
            "security",
            "host",
            "domains",
        ]

    # Apply TLD exclusions if specified
    if exclude_tlds:
        exclude_list = [
            tld.strip().lower() for tld in exclude_tlds.split(",") if tld.strip()
        ]
        original_count = len(tlds)
        tlds = [tld for tld in tlds if tld.lower() not in exclude_list]
        if verbose:
            click.secho(
                f"[+] 🚫 Excluded {original_count - len(tlds)} TLDs: {', '.join(exclude_list)}",
                fg="yellow",
            )

    # Parse inject_suffix if provided
    suffixes = []
    if inject_suffix:
        suffixes = [s.strip() for s in inject_suffix.split(",") if s.strip()]
        if verbose:
            click.secho(f"[+] 🏷️  Using suffixes: {', '.join(suffixes)}", fg="green")

    # Parse inject_prefix if provided
    prefixes = []
    if inject_prefix:
        prefixes = [p.strip() for p in inject_prefix.split(",") if p.strip()]
        if verbose:
            click.secho(f"[+] 🏷️  Using prefixes: {', '.join(prefixes)}", fg="green")

    # Generate TLD variations
    for base in base_items:
        # Remove existing TLD if present
        if "." in base:
            domain_base = base.split(".")[0]
        else:
            domain_base = base

        for tld in tlds:
            # Create all combinations of prefixes and suffixes
            if prefixes or suffixes:
                # Generate with prefixes and/or suffixes
                prefix_list = prefixes if prefixes else [""]
                suffix_list = suffixes if suffixes else [""]

                for prefix in prefix_list:
                    for suffix in suffix_list:
                        domain_with_modifications = f"{prefix}{domain_base}{suffix}"

                        if www_prefix:
                            # Generate only www. variations
                            results.append(f"www.{domain_with_modifications}.{tld}")
                        else:
                            # Generate both plain and www variations
                            results.extend(
                                [
                                    f"{domain_with_modifications}.{tld}",
                                    f"www.{domain_with_modifications}.{tld}",
                                ]
                            )

                # Also generate without any prefixes/suffixes (original behavior)
                if www_prefix:
                    results.append(f"www.{domain_base}.{tld}")
                else:
                    results.extend([f"{domain_base}.{tld}", f"www.{domain_base}.{tld}"])
            else:
                # Original behavior when no prefixes/suffixes specified
                if www_prefix:
                    # Generate only www. variations
                    results.append(f"www.{domain_base}.{tld}")
                else:
                    # Generate both plain and www variations
                    results.extend([f"{domain_base}.{tld}", f"www.{domain_base}.{tld}"])

    if verbose and not dry_run:
        click.secho(f"[+] 🎯 Generated {len(results)} TLD variations", fg="green")

    return results


def update_dns_resolvers(verbose=False):
    """Download and update DNS resolver lists for tools like shuffledns"""
    if verbose:
        click.secho("[*] 🔄 Updating DNS resolver lists...", fg="cyan")

    resolvers_dir = Path(__file__).parent / "wordlists"
    resolvers_dir.mkdir(exist_ok=True)

    # List of resolver sources
    resolver_sources = [
        {
            "name": "trickest-resolvers.txt",
            "url": "https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt",
            "description": "Trickest public resolvers",
        },
        {
            "name": "fresh-resolvers.txt",
            "url": "https://raw.githubusercontent.com/janmasarik/resolvers/master/resolvers.txt",
            "description": "Fresh public resolvers",
        },
        {
            "name": "bass-resolvers.txt",
            "url": "https://raw.githubusercontent.com/bass-cloud/resolvers/main/resolvers.txt",
            "description": "Bass cloud resolvers",
        },
    ]

    success_count = 0

    for source in resolver_sources:
        try:
            if verbose:
                click.secho(f"[*] 📥 Downloading {source['description']}...", fg="blue")

            import urllib.request

            output_path = resolvers_dir / source["name"]

            urllib.request.urlretrieve(source["url"], output_path)

            # Count lines in the file
            with open(output_path, "r") as f:
                line_count = sum(1 for line in f if line.strip())

            if verbose:
                click.secho(
                    f"[+] ✅ {source['name']}: {line_count} resolvers", fg="green"
                )
            success_count += 1

        except Exception as e:
            if verbose:
                click.secho(
                    f"[!] ❌ Failed to download {source['name']}: {e}", fg="red"
                )
            continue

    # Create/update main resolvers file
    main_resolvers_path = resolvers_dir / "resolvers-trickest.txt"
    if (resolvers_dir / "trickest-resolvers.txt").exists():
        import shutil

        shutil.copy(resolvers_dir / "trickest-resolvers.txt", main_resolvers_path)
        if verbose:
            click.secho(
                f"[+] 🔗 Updated main resolver file: {main_resolvers_path}", fg="green"
            )

    if success_count > 0:
        click.secho(
            f"[✓] 🎉 Successfully updated {success_count} resolver lists",
            fg="green",
            bold=True,
        )
        click.secho(f"[✓] 📁 Files saved to: {resolvers_dir}", fg="green")
    else:
        click.secho("[!] ❌ Failed to update any resolver lists", fg="red")


def generate_bucket_permutations(
    brand, keywords=None, suffixes=None, year=None, verbose=False
):
    """
    Generate comprehensive S3 bucket permutations for reconnaissance.

    Args:
        brand (str): Target brand/company name (e.g., "tesla")
        keywords (list): Optional keywords (e.g., ["dev", "test", "staging"])
        suffixes (list): Optional suffixes (e.g., ["-cdn", "-backup", "-static"])
        year (str): Optional year (e.g., "2025")
        verbose (bool): Enable verbose output

    Returns:
        list: Unique bucket permutations
    """
    if verbose:
        click.secho("[*] 🪣 Generating S3 bucket permutations...", fg="cyan")

    results = []

    # Normalize inputs
    brand = brand.lower().strip()
    keywords = keywords or []
    suffixes = suffixes or []

    # Common bucket suffixes if none provided
    if not suffixes:
        suffixes = [
            "-cdn",
            "-backup",
            "-static",
            "-assets",
            "-data",
            "-logs",
            "-media",
            "-files",
            "-downloads",
            "-uploads",
            "-images",
            "-docs",
            "-storage",
            "-archive",
            "-cache",
            "-temp",
        ]

    # Common keywords if none provided
    if not keywords:
        keywords = [
            "dev",
            "test",
            "staging",
            "prod",
            "production",
            "demo",
            "beta",
            "alpha",
            "qa",
            "uat",
            "internal",
            "external",
            "public",
            "private",
            "secure",
            "admin",
            "api",
            "www",
        ]

    # 1. Basic brand variations
    results.extend(
        [
            brand,
            f"{brand}s",  # plural
            f"the{brand}",
            f"{brand}co",
            f"{brand}corp",
            f"{brand}inc",
        ]
    )

    # 2. Brand + year combinations
    if year:
        results.extend(
            [
                f"{brand}{year}",
                f"{brand}-{year}",
                f"{brand}_{year}",
                f"{year}-{brand}",
                f"{year}{brand}",
            ]
        )

    # 3. Brand + keyword combinations
    for keyword in keywords:
        results.extend(
            [
                f"{brand}-{keyword}",
                f"{keyword}-{brand}",
                f"{brand}_{keyword}",
                f"{keyword}_{brand}",
                f"{brand}{keyword}",
                f"{keyword}{brand}",
                f"{brand}.{keyword}",
                f"{keyword}.{brand}",
            ]
        )

        # With year included
        if year:
            results.extend(
                [
                    f"{brand}-{keyword}-{year}",
                    f"{keyword}-{brand}-{year}",
                    f"{brand}-{year}-{keyword}",
                    f"{year}-{brand}-{keyword}",
                    f"{brand}{keyword}{year}",
                    f"{keyword}{brand}{year}",
                ]
            )

    # 4. Brand + suffix combinations
    for suffix in suffixes:
        # Remove leading dash from suffix for some variations
        clean_suffix = suffix.lstrip("-")

        results.extend(
            [
                f"{brand}{suffix}",
                f"{brand}-{clean_suffix}",
                f"{brand}_{clean_suffix}",
                f"{brand}.{clean_suffix}",
                f"{clean_suffix}-{brand}",
                f"{clean_suffix}.{brand}",
            ]
        )

        # With year
        if year:
            results.extend(
                [
                    f"{brand}{suffix}{year}",
                    f"{brand}{suffix}-{year}",
                    f"{brand}-{year}{suffix}",
                    f"{year}-{brand}{suffix}",
                ]
            )

    # 5. AWS-specific patterns
    aws_patterns = [
        f"{brand}.s3.amazonaws.com",
        f"{brand}-s3.amazonaws.com",
        f"s3.amazonaws.com/{brand}",
        f"s3-{brand}.amazonaws.com",
        f"{brand}.s3-website-us-east-1.amazonaws.com",
        f"{brand}.s3-website.us-east-1.amazonaws.com",
        f"{brand}.s3.us-east-1.amazonaws.com",
        f"{brand}.s3.us-west-2.amazonaws.com",
        f"{brand}.s3.eu-west-1.amazonaws.com",
        f"{brand}-bucket.s3.amazonaws.com",
    ]
    results.extend(aws_patterns)

    # 6. Cloud provider variations
    cloud_patterns = [
        f"{brand}-aws",
        f"{brand}-gcp",
        f"{brand}-azure",
        f"{brand}-s3",
        f"{brand}-bucket",
        f"{brand}-storage",
        f"aws-{brand}",
        f"gcp-{brand}",
        f"azure-{brand}",
        f"s3-{brand}",
        f"bucket-{brand}",
        f"storage-{brand}",
    ]
    results.extend(cloud_patterns)

    # 7. Common business patterns
    business_patterns = [
        f"{brand}-website",
        f"{brand}-web",
        f"{brand}-app",
        f"{brand}-api",
        f"{brand}-content",
        f"{brand}-resources",
        f"assets.{brand}",
        f"downloads.{brand}",
        f"files.{brand}",
        f"media.{brand}",
        f"static.{brand}",
        f"cdn.{brand}",
        f"backup.{brand}",
        f"logs.{brand}",
        f"data.{brand}",
    ]
    results.extend(business_patterns)

    # 8. Regional and environment combinations
    regions = ["us", "eu", "asia", "global", "east", "west", "north", "south"]
    environments = ["dev", "test", "stage", "prod", "qa"]

    for region in regions:
        results.extend([f"{brand}-{region}", f"{region}-{brand}", f"{brand}.{region}"])

    for env in environments:
        results.extend(
            [
                f"{env}-{brand}",
                f"{brand}-{env}",
                f"{env}.{brand}.com",
                f"{brand}-{env}-bucket",
            ]
        )

    # 9. Numbered variations
    for i in range(1, 6):  # 1-5
        results.extend([f"{brand}{i}", f"{brand}-{i}", f"{brand}0{i}", f"{brand}-0{i}"])

    # 10. Special character variations
    special_variations = [
        brand.replace("-", ""),
        brand.replace("_", ""),
        brand.replace(".", ""),
        brand.replace("-", "_"),
        brand.replace("_", "-"),
        brand.replace(" ", "-"),
        brand.replace(" ", "_"),
        brand.replace(" ", ""),
    ]
    results.extend(special_variations)

    # Remove duplicates while preserving order
    seen = set()
    unique_results = []
    for item in results:
        if item and item not in seen:
            seen.add(item)
            unique_results.append(item)

    # Filter out very short or invalid bucket names
    filtered_results = [
        bucket
        for bucket in unique_results
        if len(bucket) >= 3
        and len(bucket) <= 63
        and bucket.replace("-", "").replace("_", "").replace(".", "").isalnum()
    ]

    if verbose:
        click.secho(
            f"[+] 🎯 Generated {len(filtered_results)} unique bucket permutations",
            fg="green",
        )

    return filtered_results


if __name__ == "__main__":
    permutcli()
