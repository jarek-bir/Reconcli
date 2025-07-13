#!/usr/bin/env python3

import json
import subprocess
import time
from datetime import datetime
from pathlib import Path

import click

try:
    import requests
    from gql import Client, gql
    from gql.transport.requests import RequestsHTTPTransport

    DEPENDENCIES_AVAILABLE = True
except ImportError:
    DEPENDENCIES_AVAILABLE = False


@click.command()
@click.option("--domain", required=True, help="Target domain (e.g. target.com)")
@click.option(
    "--engine",
    default="graphw00f",
    type=click.Choice(
        ["graphw00f", "graphql-cop", "graphqlmap", "gql", "gql-cli", "all"]
    ),
    help="Engine to use: graphw00f (default), graphql-cop, graphqlmap, gql, gql-cli, or all",
)
@click.option("--endpoint", help="Custom GraphQL endpoint (e.g. /api/graphql)")
@click.option("--proxy", help="Proxy (http://127.0.0.1:8080)")
@click.option("--tor", is_flag=True, help="Use Tor (graphql-cop only)")
@click.option(
    "--header",
    multiple=True,
    help='Custom headers: --header "Authorization: Bearer xyz" (use multiple times)',
)
@click.option("--wordlist", help="Path to custom endpoint wordlist")
@click.option("--threads", default=10, help="Number of threads for scanning")
@click.option("--timeout", default=30, help="Request timeout in seconds")
@click.option("--output-dir", default="output", help="Output directory")
@click.option("--csv-output", is_flag=True, help="Save results in CSV format")
@click.option("--json-output", is_flag=True, help="Save results in JSON format")
@click.option("--store-db", is_flag=True, help="Store session state")
@click.option("--resume", is_flag=True, help="Resume previous session")
@click.option("--resume-stat", is_flag=True, help="Show previous session state")
@click.option("--resume-reset", is_flag=True, help="Delete previous session state")
@click.option("--report", is_flag=True, help="Generate Markdown report")
@click.option("--fingerprint", is_flag=True, help="Enable GraphQL fingerprinting")
@click.option(
    "--threat-matrix", is_flag=True, help="Run GraphQL Threat Matrix assessment"
)
@click.option(
    "--detect-engines", is_flag=True, help="Detect GraphQL engine/implementation"
)
@click.option("--batch-queries", is_flag=True, help="Test GraphQL batching support")
@click.option(
    "--field-suggestions", is_flag=True, help="Test field suggestion vulnerabilities"
)
@click.option("--depth-limit", is_flag=True, help="Test query depth limit")
@click.option("--rate-limit", is_flag=True, help="Test rate limiting")
@click.option(
    "--sqli-test", is_flag=True, help="Test for SQL injection vulnerabilities"
)
@click.option(
    "--nosqli-test", is_flag=True, help="Test for NoSQL injection vulnerabilities"
)
@click.option(
    "--gql-cli", is_flag=True, help="Use gql-cli for enhanced GraphQL operations"
)
@click.option(
    "--print-schema",
    is_flag=True,
    help="Download and save GraphQL schema using gql-cli",
)
@click.option(
    "--schema-file", help="Custom schema output filename (default: schema.graphql)"
)
@click.option("--gql-variables", help="Variables for gql-cli in key:value format")
@click.option("--gql-operation", help="Specific GraphQL operation name to execute")
@click.option("--interactive-gql", is_flag=True, help="Run gql-cli in interactive mode")
@click.option(
    "--gql-transport",
    type=click.Choice(["auto", "aiohttp", "httpx", "websockets"]),
    default="auto",
    help="Transport type for gql-cli (default: auto)",
)
@click.option("--verbose", "-v", is_flag=True, help="Verbose output")
@click.option(
    "--insecure",
    is_flag=True,
    help="Disable SSL certificate verification (security risk)",
)
def graphqlcli(
    domain,
    engine,
    endpoint,
    proxy,
    tor,
    header,
    wordlist,
    threads,
    timeout,
    output_dir,
    csv_output,
    json_output,
    store_db,
    resume,
    resume_stat,
    resume_reset,
    report,
    fingerprint,
    threat_matrix,
    detect_engines,
    batch_queries,
    field_suggestions,
    depth_limit,
    rate_limit,
    sqli_test,
    nosqli_test,
    gql_cli,
    print_schema,
    schema_file,
    gql_variables,
    gql_operation,
    interactive_gql,
    gql_transport,
    verbose,
    insecure,
):
    """GraphQL recon & audit module using multiple engines and advanced techniques"""

    if not DEPENDENCIES_AVAILABLE:
        click.echo("[!] Required dependencies not found. Install with:")
        click.echo("    pip install requests gql[all] click")
        return

    # Security warning for insecure mode
    if insecure:
        click.echo(
            "⚠️  WARNING: SSL certificate verification is disabled. This is a security risk!"
        )
        click.echo("    Use --insecure only for testing against trusted endpoints.")

    # Set SSL verification behavior
    ssl_verify = not insecure

    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    state_file = output_path / f"graphqlcli_state_{domain}.json"
    json_output_file = output_path / f"graphql_audit_{domain}.json"
    csv_output_file = output_path / f"graphql_audit_{domain}.csv"
    md_output = output_path / f"graphql_report_{domain}.md"

    if verbose:
        click.echo(f"[+] Starting GraphQL security assessment for {domain}")
        click.echo(f"[+] Engine: {engine}")
        click.echo(f"[+] Output directory: {output_path}")

    # Resume logic
    if resume_reset:
        if state_file.exists():
            state_file.unlink()
            click.echo(f"[+] Reset state file for {domain}")
        return
    if resume_stat:
        if state_file.exists():
            click.echo(state_file.read_text())
        else:
            click.echo("[!] No session found.")
        return
    if resume and state_file.exists():
        with state_file.open() as f:
            session_data = json.load(f)
            click.echo(f"[+] Resuming previous session for {domain}")
            engine = session_data.get("engine", engine)
    elif resume:
        click.echo("[!] No previous session found.")
        return

    # Build target URL
    if endpoint:
        target_url = f"https://{domain}{endpoint}"
    else:
        target_url = f"https://{domain}/graphql"

    if verbose:
        click.echo(f"[+] Target URL: {target_url}")

    # Run selected engine(s)
    results = {}

    if engine == "all":
        engines = ["graphw00f", "graphql-cop", "graphqlmap", "gql", "gql-cli"]
    else:
        engines = [engine]

    for eng in engines:
        if verbose:
            click.echo(f"[+] Running {eng} engine...")

        if eng == "graphw00f":
            result = run_graphw00f(
                domain, header, proxy, fingerprint, detect_engines, verbose, ssl_verify
            )
        elif eng == "gql":
            result = run_gql_engine(domain, header, proxy, endpoint, timeout, verbose)
        elif eng == "gql-cli":
            # Run gql-cli as engine
            schema_output_file = schema_file or f"{domain}_schema.graphql"
            schema_path = output_path / schema_output_file
            result = run_gql_cli_operations(
                target_url,
                header,
                proxy,
                True,
                schema_path,
                gql_variables,
                gql_operation,
                False,
                gql_transport,
                verbose,
            )
        elif eng == "graphqlmap":
            result = run_graphqlmap(
                domain, header, proxy, endpoint, timeout, verbose, ssl_verify
            )
        elif eng == "graphql-cop":
            result = run_graphqlcop(
                domain, header, proxy, tor, endpoint, timeout, verbose
            )
        else:
            click.echo(f"[!] Unknown engine: {eng}")
            continue

        results[eng] = result

        # Run advanced tests if requested
        if threat_matrix:
            results[f"{eng}_threat_matrix"] = run_threat_matrix_assessment(
                target_url, header, proxy, timeout, verbose, ssl_verify
            )

        if batch_queries:
            results[f"{eng}_batch_test"] = test_batch_queries(
                target_url, header, proxy, timeout, verbose, ssl_verify
            )

        if sqli_test:
            results[f"{eng}_sqli"] = test_sql_injection(
                target_url, header, proxy, timeout, verbose, ssl_verify
            )

        if nosqli_test:
            results[f"{eng}_nosqli"] = test_nosql_injection(
                target_url, header, proxy, timeout, verbose, ssl_verify
            )

    # Handle gql-cli specific operations
    if print_schema or interactive_gql or gql_cli:
        schema_output_file = schema_file or f"{domain}_schema.graphql"
        schema_path = output_path / schema_output_file

        gql_result = run_gql_cli_operations(
            target_url,
            header,
            proxy,
            print_schema,
            schema_path,
            gql_variables,
            gql_operation,
            interactive_gql,
            gql_transport,
            verbose,
        )

        if print_schema and not interactive_gql:
            # If only schema download was requested, save and exit
            if gql_result.get("schema_downloaded"):
                click.echo(f"[+] Schema saved to: {schema_path}")
                return gql_result
            else:
                click.echo(
                    f"[!] Failed to download schema: {gql_result.get('error', 'Unknown error')}"
                )
                return gql_result

    # Save results in different formats
    if json_output or not csv_output:
        json_output_file.write_text(json.dumps(results, indent=2))
        click.echo(f"[+] Saved JSON: {json_output_file}")

    if csv_output:
        save_csv_results(results, csv_output_file)
        click.echo(f"[+] Saved CSV: {csv_output_file}")

    # Save session
    if store_db:
        state = {
            "domain": domain,
            "engine": engine,
            "timestamp": datetime.utcnow().isoformat(),
            "results": results,
        }
        state_file.write_text(json.dumps(state, indent=2))
        click.echo(f"[+] Session saved: {state_file}")

    # Generate report
    if report:
        md_content = generate_markdown_report(domain, engines, results, verbose)
        md_output.write_text(md_content)
        click.echo(f"[+] Markdown report saved: {md_output}")

    return results


def run_graphw00f(
    domain, headers, proxy, fingerprint, detect_engines, verbose, ssl_verify=True
):
    """Run GraphW00F fingerprinting tool"""
    url = f"https://{domain}/graphql"
    cmd = ["graphw00f", "-t", url]

    for h in headers:
        cmd += ["-H", h]
    if proxy:
        cmd += ["-p", proxy]
    if fingerprint:
        cmd += ["-f"]
    if detect_engines:
        cmd += ["-d"]

    try:
        if verbose:
            click.echo(f"[+] Running: {' '.join(cmd)}")
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)

        # Parse GraphW00F output
        output_data = {
            "engine": "graphw00f",
            "url": url,
            "fingerprint_enabled": fingerprint,
            "detect_engines": detect_engines,
            "raw_output": result.stdout,
            "errors": result.stderr if result.stderr else None,
        }

        # Try to extract structured data from output
        if "GraphQL Engine" in result.stdout:
            lines = result.stdout.split("\n")
            for line in lines:
                if "GraphQL Engine:" in line:
                    output_data["detected_engine"] = line.split(":", 1)[1].strip()
                elif "Version:" in line:
                    output_data["detected_version"] = line.split(":", 1)[1].strip()

        return output_data

    except subprocess.TimeoutExpired:
        return {
            "engine": "graphw00f",
            "url": url,
            "error": "Timeout expired",
            "timeout": 120,
        }
    except FileNotFoundError:
        # Fallback to manual fingerprinting if GraphW00F not installed
        if verbose:
            click.echo("[!] GraphW00F not found, using manual fingerprinting")
        return manual_graphql_fingerprinting(
            domain, headers, proxy, verbose, ssl_verify
        )
    except Exception as e:
        return {"engine": "graphw00f", "url": url, "error": str(e)}


def manual_graphql_fingerprinting(domain, headers, proxy, verbose, ssl_verify=True):
    """Manual GraphQL fingerprinting implementation"""
    url = f"https://{domain}/graphql"

    header_dict = {}
    for h in headers:
        if ":" in h:
            k, v = h.split(":", 1)
            header_dict[k.strip()] = v.strip()

    proxies = {"http": proxy, "https": proxy} if proxy else None

    fingerprint_data = {"engine": "manual_fingerprint", "url": url, "tests": {}}

    # Test 1: Introspection query
    introspection_query = {"query": "{ __schema { queryType { name } } }"}

    try:
        if verbose:
            click.echo("[+] Testing introspection...")
        response = requests.post(
            url,
            json=introspection_query,
            headers=header_dict,
            proxies=proxies,
            timeout=10,
            verify=ssl_verify,
        )
        fingerprint_data["tests"]["introspection"] = {
            "status_code": response.status_code,
            "response_size": len(response.text),
            "enabled": "queryType" in response.text,
        }
    except Exception as e:
        fingerprint_data["tests"]["introspection"] = {"error": str(e)}

    # Test 2: Error message fingerprinting
    invalid_query = {"query": "{ invalid_field }"}

    try:
        if verbose:
            click.echo("[+] Testing error messages...")
        response = requests.post(
            url,
            json=invalid_query,
            headers=header_dict,
            proxies=proxies,
            timeout=10,
            verify=ssl_verify,
        )
        error_text = response.text.lower()

        # Engine detection based on error patterns
        detected_engine = "unknown"
        if "apollo" in error_text:
            detected_engine = "Apollo Server"
        elif "graphene" in error_text:
            detected_engine = "Graphene"
        elif "hasura" in error_text:
            detected_engine = "Hasura"
        elif "lighthouse" in error_text:
            detected_engine = "Lighthouse"
        elif "sangria" in error_text:
            detected_engine = "Sangria"
        elif "juniper" in error_text:
            detected_engine = "Juniper"

        fingerprint_data["tests"]["error_fingerprint"] = {
            "detected_engine": detected_engine,
            "response_text": response.text[:500],  # First 500 chars
        }
    except Exception as e:
        fingerprint_data["tests"]["error_fingerprint"] = {"error": str(e)}

    # Test 3: Batching support
    batch_query = [{"query": "{ __typename }"}, {"query": "{ __typename }"}]

    try:
        if verbose:
            click.echo("[+] Testing batch queries...")
        response = requests.post(
            url,
            json=batch_query,
            headers=header_dict,
            proxies=proxies,
            timeout=10,
            verify=ssl_verify,
        )
        fingerprint_data["tests"]["batching"] = {
            "status_code": response.status_code,
            "supported": response.status_code == 200 and "[" in response.text,
        }
    except Exception as e:
        fingerprint_data["tests"]["batching"] = {"error": str(e)}

    return fingerprint_data


def run_gql_engine(domain, headers, proxy, endpoint=None, timeout=30, verbose=False):
    """Enhanced GQL engine with better error handling and features"""
    if endpoint:
        url = f"https://{domain}{endpoint}"
    else:
        url = f"https://{domain}/graphql"

    header_dict = {}
    for h in headers:
        if ":" in h:
            k, v = h.split(":", 1)
            header_dict[k.strip()] = v.strip()

    transport_opts = {
        "url": url,
        "headers": header_dict,
        "use_json": True,
        "verify": False,
        "timeout": timeout,
    }

    if proxy:
        transport_opts["proxies"] = {"http": proxy, "https": proxy}

    try:
        transport = RequestsHTTPTransport(**transport_opts)
        client = Client(transport=transport, fetch_schema_from_transport=False)

        # Enhanced introspection query
        introspection_query = gql(
            """
        {
          __schema {
            queryType { name }
            mutationType { name }
            subscriptionType { name }
            types {
              name
              kind
              description
              fields {
                name
                description
                type {
                  name
                  kind
                }
              }
            }
            directives {
              name
              description
              locations
            }
          }
        }
        """
        )

        if verbose:
            click.echo(f"[+] Executing introspection query on {url}")

        result = client.execute(introspection_query)

        # Extract additional information
        schema_data = result.get("__schema", {})
        types_count = len(schema_data.get("types", []))
        directives_count = len(schema_data.get("directives", []))

        return {
            "engine": "gql",
            "url": url,
            "introspection": True,
            "types_count": types_count,
            "directives_count": directives_count,
            "has_mutations": schema_data.get("mutationType") is not None,
            "has_subscriptions": schema_data.get("subscriptionType") is not None,
            "result": result,
        }
    except Exception as e:
        if verbose:
            click.echo(f"[!] GQL engine error: {str(e)}")
        return {"engine": "gql", "url": url, "introspection": False, "error": str(e)}


def run_graphqlcop(
    domain, headers, proxy, tor, endpoint=None, timeout=30, verbose=False
):
    """Enhanced GraphQL-Cop with additional options"""
    if endpoint:
        url = f"https://{domain}{endpoint}"
    else:
        url = f"https://{domain}"

    cmd = ["graphql-cop", "-t", url, "-o", "json"]

    for h in headers:
        cmd += ["-H", h]
    if proxy:
        cmd += ["-x", proxy]
    if tor:
        cmd += ["-T"]

    try:
        if verbose:
            click.echo(f"[+] Running: {' '.join(cmd)}")
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)

        if result.stdout.strip():
            return json.loads(result.stdout)
        else:
            return {
                "engine": "graphql-cop",
                "url": url,
                "error": "No output received",
                "stderr": result.stderr,
            }
    except json.JSONDecodeError:
        return {
            "engine": "graphql-cop",
            "url": url,
            "error": "Invalid JSON output",
            "raw_output": result.stdout,
        }
    except subprocess.TimeoutExpired:
        return {
            "engine": "graphql-cop",
            "url": url,
            "error": f"Timeout after {timeout} seconds",
        }
    except FileNotFoundError:
        return {
            "engine": "graphql-cop",
            "url": url,
            "error": "graphql-cop not found in PATH",
        }
    except Exception as e:
        return {"engine": "graphql-cop", "url": url, "error": str(e)}


def run_graphqlmap(
    domain, headers, proxy, endpoint=None, timeout=30, verbose=False, ssl_verify=True
):
    """Enhanced GraphQLMap with interactive mode simulation"""
    if endpoint:
        url = f"https://{domain}{endpoint}?query={{}}"
    else:
        url = f"https://{domain}/graphql?query={{}}"

    cmd = ["graphqlmap", "-u", url, "--json"]

    if proxy:
        cmd += ["--proxy", proxy]
    if headers:
        header_string = (
            "{"
            + ", ".join(
                f'"{h.split(":")[0].strip()}": "{h.split(":")[1].strip()}"'
                for h in headers
                if ":" in h
            )
            + "}"
        )
        cmd += ["--headers", header_string]

    try:
        if verbose:
            click.echo(f"[+] Running: {' '.join(cmd)}")

        # Since GraphQLMap is interactive, we'll simulate some common commands
        test_commands = ["dump_via_introspection", "dump_via_fragment", "debug"]

        results = {"engine": "graphqlmap", "url": url, "tests": {}}

        for command in test_commands:
            try:
                # Simulate GraphQLMap commands by sending requests manually
                if command == "dump_via_introspection":
                    result = test_graphqlmap_introspection(
                        url, headers, proxy, timeout, verbose, ssl_verify
                    )
                    results["tests"][command] = result
                elif command == "debug":
                    result = test_graphqlmap_debug(
                        url, headers, proxy, timeout, verbose, ssl_verify
                    )
                    results["tests"][command] = result
            except Exception as e:
                results["tests"][command] = {"error": str(e)}

        return results

    except Exception as e:
        return {"engine": "graphqlmap", "url": url, "error": str(e)}


def test_graphqlmap_introspection(
    url, headers, proxy, timeout, verbose, ssl_verify=True
):
    """Test GraphQL introspection manually"""
    header_dict = {}
    for h in headers:
        if ":" in h:
            k, v = h.split(":", 1)
            header_dict[k.strip()] = v.strip()

    proxies = {"http": proxy, "https": proxy} if proxy else None

    introspection_query = "{__schema{types{name}}}"
    test_url = url.replace("{}", introspection_query)

    try:
        response = requests.get(
            test_url,
            headers=header_dict,
            proxies=proxies,
            timeout=timeout,
            verify=ssl_verify,
        )
        return {
            "status_code": response.status_code,
            "response_size": len(response.text),
            "introspection_works": "__schema" in response.text
            and "types" in response.text,
        }
    except Exception as e:
        return {"error": str(e)}


def test_graphqlmap_debug(url, headers, proxy, timeout, verbose, ssl_verify=True):
    """Test GraphQL debug information"""
    header_dict = {}
    for h in headers:
        if ":" in h:
            k, v = h.split(":", 1)
            header_dict[k.strip()] = v.strip()

    proxies = {"http": proxy, "https": proxy} if proxy else None

    debug_query = '{__type(name:"Query"){name}}'
    test_url = url.replace("{}", debug_query)

    try:
        response = requests.get(
            test_url,
            headers=header_dict,
            proxies=proxies,
            timeout=timeout,
            verify=ssl_verify,
        )
        return {
            "status_code": response.status_code,
            "response_size": len(response.text),
            "debug_info_available": "__type" in response.text,
        }
    except Exception as e:
        return {"error": str(e)}


def run_threat_matrix_assessment(
    url, headers, proxy, timeout, verbose, ssl_verify=True
):
    """Run GraphQL Threat Matrix assessment"""
    if verbose:
        click.echo("[+] Running GraphQL Threat Matrix assessment...")

    header_dict = {}
    for h in headers:
        if ":" in h:
            k, v = h.split(":", 1)
            header_dict[k.strip()] = v.strip()

    proxies = {"http": proxy, "https": proxy} if proxy else None

    threats = {
        "introspection_enabled": test_introspection_threat(
            url, header_dict, proxies, timeout, ssl_verify
        ),
        "deep_recursion": test_deep_recursion_threat(
            url, header_dict, proxies, timeout, ssl_verify
        ),
        "field_duplication": test_field_duplication_threat(
            url, header_dict, proxies, timeout, ssl_verify
        ),
        "alias_overload": test_alias_overload_threat(
            url, header_dict, proxies, timeout, ssl_verify
        ),
        "directive_overload": test_directive_overload_threat(
            url, header_dict, proxies, timeout, ssl_verify
        ),
    }

    return {
        "assessment_type": "threat_matrix",
        "url": url,
        "threats": threats,
        "timestamp": datetime.utcnow().isoformat(),
    }


def test_introspection_threat(url, headers, proxies, timeout, ssl_verify=True):
    """Test for introspection vulnerability"""
    query = {"query": "{ __schema { queryType { name } } }"}
    try:
        response = requests.post(
            url,
            json=query,
            headers=headers,
            proxies=proxies,
            timeout=timeout,
            verify=ssl_verify,
        )
        return {
            "vulnerable": "queryType" in response.text and response.status_code == 200,
            "status_code": response.status_code,
            "response_size": len(response.text),
        }
    except Exception as e:
        return {"error": str(e), "vulnerable": False}


def test_deep_recursion_threat(url, headers, proxies, timeout, ssl_verify=True):
    """Test for deep recursion DoS"""
    deep_query = {"query": "{ " + "user { user { " * 50 + "id" + " } }" * 50 + " }"}
    try:
        start_time = time.time()
        response = requests.post(
            url,
            json=deep_query,
            headers=headers,
            proxies=proxies,
            timeout=timeout,
            verify=ssl_verify,
        )
        response_time = time.time() - start_time

        return {
            "vulnerable": response_time > 5 or response.status_code == 500,
            "response_time": response_time,
            "status_code": response.status_code,
        }
    except Exception as e:
        return {"error": str(e), "vulnerable": False}


def test_field_duplication_threat(url, headers, proxies, timeout, ssl_verify=True):
    """Test for field duplication DoS"""
    duplicate_query = {"query": "{ " + "__typename " * 1000 + " }"}
    try:
        start_time = time.time()
        response = requests.post(
            url,
            json=duplicate_query,
            headers=headers,
            proxies=proxies,
            timeout=timeout,
            verify=ssl_verify,
        )
        response_time = time.time() - start_time

        return {
            "vulnerable": response_time > 3 or response.status_code == 500,
            "response_time": response_time,
            "status_code": response.status_code,
        }
    except Exception as e:
        return {"error": str(e), "vulnerable": False}


def test_alias_overload_threat(url, headers, proxies, timeout, ssl_verify=True):
    """Test for alias overload DoS"""
    alias_query = {
        "query": "{ " + " ".join([f"alias{i}: __typename" for i in range(1000)]) + " }"
    }
    try:
        start_time = time.time()
        response = requests.post(
            url,
            json=alias_query,
            headers=headers,
            proxies=proxies,
            timeout=timeout,
            verify=ssl_verify,
        )
        response_time = time.time() - start_time

        return {
            "vulnerable": response_time > 3 or response.status_code == 500,
            "response_time": response_time,
            "status_code": response.status_code,
        }
    except Exception as e:
        return {"error": str(e), "vulnerable": False}


def test_directive_overload_threat(url, headers, proxies, timeout, ssl_verify=True):
    """Test for directive overload DoS"""
    directive_query = {"query": "{ __typename " + "@include(if: true) " * 1000 + " }"}
    try:
        start_time = time.time()
        response = requests.post(
            url,
            json=directive_query,
            headers=headers,
            proxies=proxies,
            timeout=timeout,
            verify=ssl_verify,
        )
        response_time = time.time() - start_time

        return {
            "vulnerable": response_time > 3 or response.status_code == 500,
            "response_time": response_time,
            "status_code": response.status_code,
        }
    except Exception as e:
        return {"error": str(e), "vulnerable": False}


def test_batch_queries(url, headers, proxy, timeout, verbose, ssl_verify=True):
    """Test GraphQL batching capabilities"""
    if verbose:
        click.echo("[+] Testing GraphQL batching...")

    header_dict = {}
    for h in headers:
        if ":" in h:
            k, v = h.split(":", 1)
            header_dict[k.strip()] = v.strip()

    proxies = {"http": proxy, "https": proxy} if proxy else None

    # Test various batch sizes
    batch_tests = {}

    for batch_size in [2, 5, 10, 50, 100]:
        batch_query = [{"query": "{ __typename }"} for _ in range(batch_size)]

        try:
            start_time = time.time()
            response = requests.post(
                url,
                json=batch_query,
                headers=header_dict,
                proxies=proxies,
                timeout=timeout,
                verify=ssl_verify,
            )
            response_time = time.time() - start_time

            batch_tests[f"batch_{batch_size}"] = {
                "status_code": response.status_code,
                "response_time": response_time,
                "supported": response.status_code == 200 and "[" in response.text,
                "response_size": len(response.text),
            }
        except Exception as e:
            batch_tests[f"batch_{batch_size}"] = {"error": str(e)}

    return {"test_type": "batch_queries", "url": url, "results": batch_tests}


def test_sql_injection(url, headers, proxy, timeout, verbose, ssl_verify=True):
    """Test for SQL injection vulnerabilities"""
    if verbose:
        click.echo("[+] Testing SQL injection...")

    header_dict = {}
    for h in headers:
        if ":" in h:
            k, v = h.split(":", 1)
            header_dict[k.strip()] = v.strip()

    proxies = {"http": proxy, "https": proxy} if proxy else None

    # SQL injection payloads
    sql_payloads = [
        "' OR '1'='1",
        "'; DROP TABLE users; --",
        "' UNION SELECT version() --",
        "' AND 1=1 --",
        "' AND 1=2 --",
    ]

    injection_tests = {}

    for i, payload in enumerate(sql_payloads):
        test_query = {"query": f'{{ user(id: "{payload}") {{ id name }} }}'}

        try:
            response = requests.post(
                url,
                json=test_query,
                headers=header_dict,
                proxies=proxies,
                timeout=timeout,
                verify=ssl_verify,
            )

            # Look for SQL error indicators
            error_indicators = [
                "sql",
                "mysql",
                "postgresql",
                "sqlite",
                "syntax error",
                "database",
            ]
            sql_error_detected = any(
                indicator in response.text.lower() for indicator in error_indicators
            )

            injection_tests[f"payload_{i + 1}"] = {
                "payload": payload,
                "status_code": response.status_code,
                "sql_error_detected": sql_error_detected,
                "response_snippet": response.text[:200],
            }
        except Exception as e:
            injection_tests[f"payload_{i + 1}"] = {"payload": payload, "error": str(e)}

    return {"test_type": "sql_injection", "url": url, "results": injection_tests}


def test_nosql_injection(url, headers, proxy, timeout, verbose, ssl_verify=True):
    """Test for NoSQL injection vulnerabilities"""
    if verbose:
        click.echo("[+] Testing NoSQL injection...")

    header_dict = {}
    for h in headers:
        if ":" in h:
            k, v = h.split(":", 1)
            header_dict[k.strip()] = v.strip()

    proxies = {"http": proxy, "https": proxy} if proxy else None

    # NoSQL injection payloads
    nosql_payloads = [
        '{"$ne": ""}',
        '{"$regex": ".*"}',
        '{"$where": "function() { return true; }"}',
        '{"$gt": ""}',
        '{"$exists": true}',
    ]

    injection_tests = {}

    for i, payload in enumerate(nosql_payloads):
        test_query = {"query": f'{{ user(filter: "{payload}") {{ id name }} }}'}

        try:
            response = requests.post(
                url,
                json=test_query,
                headers=header_dict,
                proxies=proxies,
                timeout=timeout,
                verify=ssl_verify,
            )

            # Look for NoSQL error indicators
            error_indicators = [
                "mongodb",
                "nosql",
                "bson",
                "mongo",
                "regex",
                "$ne",
                "$gt",
            ]
            nosql_error_detected = any(
                indicator in response.text.lower() for indicator in error_indicators
            )

            injection_tests[f"payload_{i + 1}"] = {
                "payload": payload,
                "status_code": response.status_code,
                "nosql_error_detected": nosql_error_detected,
                "response_snippet": response.text[:200],
            }
        except Exception as e:
            injection_tests[f"payload_{i + 1}"] = {"payload": payload, "error": str(e)}

    return {"test_type": "nosql_injection", "url": url, "results": injection_tests}


def save_csv_results(results, csv_file):
    """Save results in CSV format"""
    import csv

    with open(csv_file, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["Engine", "Test Type", "URL", "Status", "Details"])

        for engine, data in results.items():
            if isinstance(data, dict):
                url = data.get("url", "N/A")
                if "error" in data:
                    writer.writerow([engine, "error", url, "failed", data["error"]])
                elif "tests" in data:
                    for test_name, test_result in data["tests"].items():
                        status = "passed" if not test_result.get("error") else "failed"
                        details = str(test_result)[:100]  # Truncate for CSV
                        writer.writerow([engine, test_name, url, status, details])
                else:
                    status = "passed" if data.get("introspection", False) else "failed"
                    writer.writerow([engine, "main", url, status, str(data)[:100]])


def generate_markdown_report(domain, engines, results, verbose):
    """Generate enhanced Markdown report"""
    lines = [
        f"# GraphQL Security Assessment Report for `{domain}`",
        f"- **Engines Used**: {', '.join(engines)}",
        f"- **Timestamp**: {datetime.utcnow().isoformat()}",
        f"- **Total Tests**: {len(results)}",
        "---",
        "",
        "## Executive Summary",
        "",
    ]

    # Count vulnerabilities
    vuln_count = 0
    total_tests = 0

    for engine, data in results.items():
        if isinstance(data, dict):
            if "threats" in data:
                for threat, result in data["threats"].items():
                    total_tests += 1
                    if result.get("vulnerable", False):
                        vuln_count += 1
            elif "tests" in data:
                total_tests += len(data["tests"])
            else:
                total_tests += 1
                if data.get("introspection", False):
                    vuln_count += 1

    lines.extend(
        [
            f"- **Total Vulnerabilities Found**: {vuln_count}",
            f"- **Total Tests Performed**: {total_tests}",
            f"- **Security Score**: {max(0, 100 - (vuln_count * 10))}%",
            "",
            "## Detailed Results",
            "",
        ]
    )

    for engine, data in results.items():
        if isinstance(data, dict):
            lines.append(f"### {engine.upper()}")
            if "introspection" in data:
                if data.get("introspection"):
                    lines.append("✅ **Introspection**: Enabled")
                    lines.append(f"- Types found: {data.get('types_count', 'N/A')}")
                    lines.append(
                        f"- Mutations: {'Yes' if data.get('has_mutations') else 'No'}"
                    )
                    lines.append(
                        f"- Subscriptions: {'Yes' if data.get('has_subscriptions') else 'No'}"
                    )
                else:
                    lines.append("❌ **Introspection**: Disabled or Failed")
            elif "threats" in data:
                lines.append("**Threat Matrix Results:**")
                for threat, result in data["threats"].items():
                    if result.get("vulnerable", False):
                        lines.append(f"- ⚠️  **{threat}**: Vulnerable")
                    else:
                        lines.append(f"- ✅ **{threat}**: Safe")
            elif "tests" in data:
                lines.append("**Test Results:**")
                for test_name, test_result in data["tests"].items():
                    if "error" in test_result:
                        lines.append(
                            f"- ❌ **{test_name}**: Error - {test_result['error']}"
                        )
                    else:
                        lines.append(f"- ✅ **{test_name}**: Completed")

        lines.append("")

    lines.extend(
        [
            "## Recommendations",
            "",
            "1. **Disable Introspection** in production environments",
            "2. **Implement Query Depth Limiting** to prevent DoS attacks",
            "3. **Use Query Complexity Analysis** to limit resource consumption",
            "4. **Implement Rate Limiting** on GraphQL endpoints",
            "5. **Validate and Sanitize** all input parameters",
            "6. **Use Query Whitelisting** for critical applications",
            "7. **Enable Query Logging** for security monitoring",
            "",
            "## Security Tools Used",
            "",
        ]
    )

    for engine in engines:
        if engine == "graphw00f":
            lines.append("- **GraphW00F**: GraphQL fingerprinting and engine detection")
        elif engine == "graphql-cop":
            lines.append(
                "- **GraphQL-Cop**: Security analysis and vulnerability detection"
            )
        elif engine == "graphqlmap":
            lines.append(
                "- **GraphQLMap**: Interactive GraphQL testing and exploitation"
            )
        elif engine == "gql":
            lines.append(
                "- **GQL**: Python GraphQL client for introspection and testing"
            )
        elif engine == "gql-cli":
            lines.append(
                "- **GQL-CLI**: Command-line GraphQL client with schema downloading"
            )

    lines.extend(
        [
            "",
            "---",
            f"*Report generated by GraphQLCLI on {datetime.utcnow().isoformat()}*",
        ]
    )

    return "\n".join(lines)


def run_gql_cli_operations(
    url,
    headers,
    proxy,
    print_schema,
    schema_path,
    gql_variables,
    gql_operation,
    interactive_gql,
    gql_transport,
    verbose,
):
    """Run gql-cli operations for schema download and interactive mode"""

    # Prepare gql-cli command
    cmd = ["gql-cli", url]

    # Add headers
    for h in headers:
        cmd += ["-H", h]

    # Add transport type
    if gql_transport != "auto":
        cmd += ["--transport", gql_transport]

    # Add proxy if specified
    if proxy:
        # gql-cli doesn't have direct proxy support, but we can use env vars
        import os

        os.environ["HTTP_PROXY"] = proxy
        os.environ["HTTPS_PROXY"] = proxy

    # Add variables if specified
    if gql_variables:
        var_parts = gql_variables.split(",")
        for var_part in var_parts:
            if ":" in var_part:
                cmd += ["-V", var_part.strip()]

    # Add operation name if specified
    if gql_operation:
        cmd += ["-o", gql_operation]

    result = {"engine": "gql-cli", "url": url, "command": " ".join(cmd)}

    try:
        if print_schema:
            # Download schema
            schema_cmd = cmd + ["--print-schema"]
            if verbose:
                click.echo(
                    f"[+] Running gql-cli schema download: {' '.join(schema_cmd)}"
                )

            schema_result = subprocess.run(
                schema_cmd, capture_output=True, text=True, timeout=60
            )

            if schema_result.returncode == 0 and schema_result.stdout.strip():
                # Save schema to file
                schema_path.write_text(schema_result.stdout)
                result.update(
                    {
                        "schema_downloaded": True,
                        "schema_file": str(schema_path),
                        "schema_size": len(schema_result.stdout),
                    }
                )

                # Parse basic schema info
                schema_info = parse_graphql_schema_info(schema_result.stdout)
                result.update(schema_info)

            else:
                result.update(
                    {
                        "schema_downloaded": False,
                        "error": schema_result.stderr or "No schema output received",
                    }
                )

        if interactive_gql:
            # Run interactive mode
            if verbose:
                click.echo(f"[+] Starting gql-cli interactive mode: {' '.join(cmd)}")
            click.echo("[+] Starting gql-cli interactive mode...")
            click.echo("[+] Use Ctrl-D to send queries, 'exit' to quit")

            # Run in interactive mode (non-capturing)
            interactive_result = subprocess.run(cmd, timeout=300)  # 5 minute timeout
            result.update(
                {"interactive_mode": True, "exit_code": interactive_result.returncode}
            )

        return result

    except subprocess.TimeoutExpired:
        return {
            "engine": "gql-cli",
            "url": url,
            "error": "Command timeout expired",
            "timeout": True,
        }
    except FileNotFoundError:
        return {
            "engine": "gql-cli",
            "url": url,
            "error": "gql-cli not found in PATH. Install with: pip install gql[all]",
            "missing_tool": True,
        }
    except Exception as e:
        return {"engine": "gql-cli", "url": url, "error": str(e)}


def parse_graphql_schema_info(schema_text):
    """Parse basic information from GraphQL schema"""
    info = {
        "types_found": [],
        "queries_found": [],
        "mutations_found": [],
        "subscriptions_found": [],
        "total_types": 0,
        "total_queries": 0,
        "total_mutations": 0,
        "total_subscriptions": 0,
    }

    lines = schema_text.split("\n")
    current_type = None

    for line in lines:
        line = line.strip()

        # Find type definitions
        if (
            line.startswith("type ")
            and not line.startswith("type Query")
            and not line.startswith("type Mutation")
        ):
            type_name = line.split()[1].split("(")[0].split("{")[0]
            info["types_found"].append(type_name)

        # Find Query type
        elif line.startswith("type Query"):
            current_type = "query"
        elif line.startswith("type Mutation"):
            current_type = "mutation"
        elif line.startswith("type Subscription"):
            current_type = "subscription"
        elif line.startswith("}"):
            current_type = None
        elif current_type and ":" in line and not line.startswith("#"):
            # Extract field name
            field_name = line.split(":")[0].strip()
            if "(" in field_name:
                field_name = field_name.split("(")[0]

            if current_type == "query":
                info["queries_found"].append(field_name)
            elif current_type == "mutation":
                info["mutations_found"].append(field_name)
            elif current_type == "subscription":
                info["subscriptions_found"].append(field_name)

    # Add counts
    info["total_types"] = len(info["types_found"])
    info["total_queries"] = len(info["queries_found"])
    info["total_mutations"] = len(info["mutations_found"])
    info["total_subscriptions"] = len(info["subscriptions_found"])

    return info


if __name__ == "__main__":
    graphqlcli.main()
