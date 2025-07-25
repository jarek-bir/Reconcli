import json
import os
import shutil
import subprocess
import time
from datetime import datetime
from pathlib import Path

import click
import httpx

from reconcli.utils.notifications import send_notification

# Database and AI imports
try:
    from reconcli.aicli import AIReconAssistant
    from reconcli.db.operations import store_subdomains, store_target
    from reconcli.utils.resume import clear_resume, load_resume, save_resume_state
except ImportError:
    store_target = None
    store_subdomains = None
    AIReconAssistant = None
    load_resume = None
    save_resume_state = None
    clear_resume = None


@click.command()
@click.option("--domain", required=True, help="Domain name (e.g. example.com)")
@click.option("--ip", required=False, help="Target IP address")
@click.option(
    "--ip-list",
    required=False,
    type=click.Path(exists=True),
    help="File with list of IPs",
)
@click.option(
    "--wordlist", required=True, type=click.Path(exists=True), help="VHOST wordlist"
)
@click.option(
    "--proxy", required=False, help="Optional proxy (e.g. http://127.0.0.1:8080)"
)
@click.option(
    "--output-dir",
    required=False,
    type=click.Path(),
    default="vhostcli_output",
    help="Output directory",
)
@click.option(
    "--show-all",
    is_flag=True,
    default=False,
    help="Show all responses, not just status 200/403/401",
)
@click.option(
    "--engine",
    type=click.Choice(["ffuf", "httpx", "gobuster", "vhostfinder"]),
    default="ffuf",
    help="Engine to use for VHOST fuzzing (ffuf, httpx, gobuster, vhostfinder)",
)
@click.option("--verbose", is_flag=True, help="Enable verbose output")
@click.option(
    "--rate-limit",
    type=int,
    default=100,
    help="Rate limit for requests per second (default: 100)",
)
@click.option(
    "--timeout",
    type=int,
    default=10,
    help="Request timeout in seconds (default: 10)",
)
@click.option(
    "--retries",
    type=int,
    default=3,
    help="Number of retries for failed requests (default: 3)",
)
@click.option(
    "--store-db",
    is_flag=True,
    help="Store results in ReconCLI database",
)
@click.option(
    "--screenshot",
    is_flag=True,
    help="Take screenshots of discovered virtual hosts",
)
@click.option(
    "--screenshot-tool",
    type=click.Choice(["gowitness", "aquatone"]),
    default="gowitness",
    help="Tool to use for screenshots (gowitness, aquatone)",
)
@click.option(
    "--screenshot-timeout",
    type=int,
    default=15,
    help="Screenshot timeout in seconds (default: 15)",
)
@click.option(
    "--screenshot-threads",
    type=int,
    default=5,
    help="Number of screenshot threads (default: 5)",
)
@click.option(
    "--fullpage",
    is_flag=True,
    help="Take full-page screenshots (gowitness only)",
)
@click.option(
    "--ai-mode",
    is_flag=True,
    help="Enable AI-powered analysis of results",
)
@click.option(
    "--ai-model",
    default="gpt-3.5-turbo",
    help="AI model to use for analysis (default: gpt-3.5-turbo)",
)
@click.option(
    "--resume",
    is_flag=True,
    help="Resume from previous scan state",
)
@click.option(
    "--resume-file",
    type=click.Path(),
    help="Custom resume file path",
)
@click.option(
    "--target-domain",
    help="Primary target domain for database storage",
)
@click.option(
    "--program",
    help="Bug bounty program name for database classification",
)
@click.option(
    "--slack-webhook",
    required=False,
    help="Slack webhook URL for notifications",
)
@click.option(
    "--discord-webhook",
    required=False,
    help="Discord webhook URL for notifications",
)
def cli(
    domain,
    ip,
    ip_list,
    wordlist,
    proxy,
    output_dir,
    show_all,
    engine,
    verbose,
    rate_limit,
    timeout,
    retries,
    store_db,
    screenshot,
    screenshot_tool,
    screenshot_timeout,
    screenshot_threads,
    fullpage,
    ai_mode,
    ai_model,
    resume,
    resume_file,
    target_domain,
    program,
    slack_webhook,
    discord_webhook,
):
    # Input validation
    if not ip and not ip_list:
        raise click.UsageError("You must provide either --ip or --ip-list")

    # Resume functionality
    resume_data = None
    if resume and load_resume:
        resume_file_path = resume_file or "vhost_resume.json"
        resume_data = load_resume(resume_file_path)
        if resume_data and verbose:
            click.echo(f"📂 Resuming from: {resume_file_path}")
            click.echo(
                f"   Previous progress: {len(resume_data.get('completed_targets', []))} targets completed"
            )

    # AI initialization
    ai_assistant = None
    if ai_mode and AIReconAssistant:
        try:
            ai_assistant = AIReconAssistant()
            if verbose:
                click.echo(f"🧠 AI mode enabled with model: {ai_model}")
        except Exception as e:
            click.echo(f"⚠️ AI initialization failed: {e}")
            ai_mode = False

    # Database setup
    if store_db and not store_target:
        click.echo("⚠️ Database functionality not available (missing dependencies)")
        store_db = False

    # Check screenshot tool availability
    if screenshot:
        if not shutil.which(screenshot_tool):
            click.echo(f"❌ Error: {screenshot_tool} is not installed or not in PATH")
            if screenshot_tool == "gowitness":
                click.echo(
                    "💡 Install with: go install github.com/sensepost/gowitness@latest"
                )
            elif screenshot_tool == "aquatone":
                click.echo(
                    "💡 Install with: go install github.com/michenriksen/aquatone@latest"
                )
            screenshot = False

    # Check if chosen engine is available
    engine_path = engine
    if engine == "vhostfinder":
        engine_path = "/usr/local/bin/VhostFinder"

    if not shutil.which(engine) and not os.path.exists(engine_path):
        click.echo(f"❌ Error: {engine} is not installed or not in PATH")
        if engine == "ffuf":
            click.echo("💡 Install with: go install github.com/ffuf/ffuf/v2@latest")
        elif engine == "httpx":
            click.echo("💡 Install with: pip install httpx")
        elif engine == "gobuster":
            click.echo("💡 Install with: go install github.com/OJ/gobuster/v3@latest")
        elif engine == "vhostfinder":
            click.echo(
                "💡 Install VhostFinder or ensure it's at /usr/local/bin/VhostFinder"
            )
        return

    Path(output_dir).mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    # Load wordlist
    if verbose:
        click.echo(f"📖 Loading wordlist: {wordlist}")

    try:
        with open(wordlist, "r") as f:
            words = [line.strip() for line in f if line.strip()]
    except Exception as e:
        click.echo(f"❌ Error reading wordlist: {e}")
        return

    if verbose:
        click.echo(f"📝 Loaded {len(words)} words from wordlist")

    # Load targets
    targets = []
    if ip_list:
        if verbose:
            click.echo(f"📋 Loading IP list: {ip_list}")
        try:
            with open(ip_list, "r") as f:
                targets = [line.strip() for line in f if line.strip()]
        except Exception as e:
            click.echo(f"❌ Error reading IP list: {e}")
            return
    elif ip:
        targets = [ip]

    if verbose:
        click.echo(f"🎯 Targets to scan: {len(targets)}")
        click.echo(f"🔧 Engine: {engine}")
        click.echo(f"⚡ Rate limit: {rate_limit} req/s")
        click.echo(f"⏱️ Timeout: {timeout}s")
        click.echo(f"🔄 Retries: {retries}")
        if proxy:
            click.echo(f"🔀 Proxy: {proxy}")
        if screenshot:
            click.echo(f"📸 Screenshots: enabled ({screenshot_tool})")
            click.echo(f"📸 Screenshot timeout: {screenshot_timeout}s")
            click.echo(f"📸 Screenshot threads: {screenshot_threads}")
            if screenshot_tool == "gowitness" and fullpage:
                click.echo("📸 Full-page screenshots: enabled")
        if ai_mode:
            click.echo("🧠 AI analysis: enabled")
        if store_db:
            click.echo("💾 Database storage: enabled")

    # Initialize resume state
    if resume_data is None:
        resume_data = {
            "completed_targets": [],
            "current_target_index": 0,
            "scan_metadata": {
                "domain": domain,
                "engine": engine,
                "wordlist_size": len(words),
                "rate_limit": rate_limit,
                "timeout": timeout,
                "retries": retries,
                "timestamp": timestamp,
            },
        }

    all_results = []

    for target_idx, target_ip in enumerate(targets, 1):
        # Skip if already completed (resume functionality)
        if target_ip in resume_data.get("completed_targets", []):
            if verbose:
                click.echo(f"⏭️ Skipping {target_ip} (already completed)")
            continue

        click.echo(
            f"\n🎯 [{target_idx}/{len(targets)}] Target: {domain} ({target_ip}) | Engine: {engine}"
        )

        ip_output_dir = os.path.join(output_dir, target_ip.replace(":", "_"))
        Path(ip_output_dir).mkdir(parents=True, exist_ok=True)
        results = []

        if engine == "ffuf":
            results = run_ffuf_scan(
                target_ip,
                domain,
                words,
                ip_output_dir,
                timestamp,
                proxy,
                show_all,
                verbose,
                rate_limit,
                timeout,
            )
        elif engine == "gobuster":
            results = run_gobuster_scan(
                target_ip,
                domain,
                words,
                ip_output_dir,
                timestamp,
                proxy,
                show_all,
                verbose,
                rate_limit,
                timeout,
                retries,
            )
        elif engine == "httpx":
            results = run_httpx_scan(
                target_ip,
                domain,
                words,
                proxy,
                show_all,
                verbose,
                rate_limit,
                timeout,
                retries,
            )
        elif engine == "vhostfinder":
            results = run_vhostfinder_scan(
                target_ip,
                domain,
                words,
                output_dir,
                timestamp,
                proxy,
                show_all,
                verbose,
                rate_limit,
                timeout,
                retries,
            )

        # AI Analysis
        ai_analysis = None
        if ai_mode and ai_assistant and results:
            if verbose:
                click.echo("🧠 Running AI analysis...")
            ai_analysis = analyze_results_with_ai(
                ai_assistant, results, domain, target_ip, ai_model
            )

        # Store in database
        if store_db and store_target and store_subdomains and results:
            try:
                target_domain_final = target_domain or domain
                tid = store_target(target_domain_final, program=program)

                # Convert vhosts to subdomain format for database
                subdomain_entries = []
                for result in results:
                    subdomain_entries.append(
                        {
                            "subdomain": result["host"],
                            "ip": target_ip,
                            "status_code": result["status"],
                            "source": f"vhostcli-{engine}",
                            "timestamp": datetime.now().isoformat(),
                        }
                    )

                if subdomain_entries:
                    store_subdomains(target_domain_final, subdomain_entries)
                    if verbose:
                        click.echo(
                            f"💾 Stored {len(subdomain_entries)} vhosts in database"
                        )

            except Exception as e:
                if verbose:
                    click.echo(f"❌ Database storage error: {e}")

        # Save results to files
        save_results_to_files(
            ip_output_dir,
            domain,
            target_ip,
            engine,
            timestamp,
            words,
            results,
            proxy,
            ai_analysis,
        )

        # Screenshot functionality
        if screenshot and results:
            if screenshot_tool == "gowitness":
                screenshot_results = run_gowitness_screenshots(
                    target_ip,
                    domain,
                    results,
                    ip_output_dir,
                    timestamp,
                    proxy,
                    verbose,
                    screenshot_timeout,
                    screenshot_threads,
                    fullpage,
                )
            elif screenshot_tool == "aquatone":
                screenshot_results = run_aquatone_screenshots(
                    target_ip,
                    domain,
                    results,
                    ip_output_dir,
                    timestamp,
                    proxy,
                    verbose,
                    screenshot_timeout,
                    screenshot_threads,
                )

        # Add to all results for final summary
        all_results.extend(results)

        # Update resume state
        resume_data["completed_targets"].append(target_ip)
        if save_resume_state:
            resume_file_path = resume_file or "vhost_resume.json"
            try:
                save_resume_state(resume_file_path, resume_data)
            except Exception as e:
                if verbose:
                    click.echo(f"⚠️ Resume save failed: {e}")

        # Summary for this target
        if results:
            click.echo(f"🎉 Found {len(results)} virtual host(s) for {target_ip}")
            if screenshot and results:
                click.echo(f"📸 Screenshots taken with {screenshot_tool}")
            if verbose:
                for r in results:
                    status_emoji = (
                        "✅"
                        if r["status"] == 200
                        else "⚠️"
                        if r["status"] in [403, 401]
                        else "❓"
                    )
                    click.echo(f"   {status_emoji} {r['host']} ({r['status']})")
        else:
            click.echo(f"❌ No virtual hosts found for {target_ip}")

        click.echo(f"💾 Results saved to: {ip_output_dir}/")

        # Send notifications for this target
        if slack_webhook or discord_webhook:
            scan_metadata = {
                "engine": engine,
                "timestamp": timestamp,
                "wordlist_size": len(words),
                "proxy": proxy,
                "rate_limit": rate_limit,
                "timeout": timeout,
                "ai_analysis": ai_analysis is not None,
            }

            if verbose:
                click.echo(f"📱 Sending notifications for {target_ip}...")

            send_notification(
                "vhost",
                domain=domain,
                target_ip=target_ip,
                results=results,
                scan_metadata=scan_metadata,
                slack_webhook=slack_webhook,
                discord_webhook=discord_webhook,
                verbose=verbose,
            )

        # Save results
        json_path = os.path.join(ip_output_dir, "vhosts_found.json")
        md_path = os.path.join(ip_output_dir, "vhosts_found.md")

        # Enhanced JSON output
        json_data = {
            "scan_info": {
                "domain": domain,
                "target_ip": target_ip,
                "engine": engine,
                "timestamp": timestamp,
                "total_words": len(words),
                "results_found": len(results),
                "proxy_used": proxy if proxy else None,
            },
            "results": results,
        }

        with open(json_path, "w") as f:
            json.dump(json_data, f, indent=2)

        # Enhanced Markdown output
        with open(md_path, "w") as f:
            f.write("# 🎯 VHOST Scan Results\n\n")
            f.write(f"**Domain:** `{domain}`  \n")
            f.write(f"**Target IP:** `{target_ip}`  \n")
            f.write(f"**Engine:** `{engine}`  \n")
            f.write(f"**Scan Time:** `{timestamp}`  \n")
            f.write(f"**Total Words:** `{len(words)}`  \n")
            f.write(f"**Results Found:** `{len(results)}`  \n")
            if proxy:
                f.write(f"**Proxy:** `{proxy}`  \n")
            f.write("\n---\n\n")

            if results:
                f.write("## 🚨 Discovered Virtual Hosts\n\n")
                f.write("| Host | Status Code |\n")
                f.write("|------|------------|\n")
                for r in results:
                    status_emoji = (
                        "✅"
                        if r["status"] == 200
                        else "⚠️"
                        if r["status"] in [403, 401]
                        else "❓"
                    )
                    f.write(f"| `{r['host']}` | {status_emoji} {r['status']} |\n")
            else:
                f.write("## ❌ No Virtual Hosts Found\n\n")
                f.write("No virtual hosts were discovered during this scan.\n")

        # Summary
        if results:
            click.echo(f"🎉 Found {len(results)} virtual host(s) for {target_ip}")
            if verbose:
                for r in results:
                    click.echo(f"   - {r['host']} ({r['status']})")
        else:
            click.echo(f"❌ No virtual hosts found for {target_ip}")

        click.echo(f"💾 Results saved to: {ip_output_dir}/")

        # Send notifications for this target
        if slack_webhook or discord_webhook:
            scan_metadata = {
                "engine": engine,
                "timestamp": timestamp,
                "wordlist_size": len(words),
                "proxy": proxy,
            }

            if verbose:
                click.echo(f"📱 Sending notifications for {target_ip}...")

            send_notification(
                "vhost",
                domain=domain,
                target_ip=target_ip,
                results=results,
                scan_metadata=scan_metadata,
                slack_webhook=slack_webhook,
                discord_webhook=discord_webhook,
                verbose=verbose,
            )

    # Final summary and cleanup
    click.echo(f"\n🏁 Scan completed! Total targets: {len(targets)}")
    click.echo("📊 Summary:")
    click.echo(f"   • Total virtual hosts found: {len(all_results)}")
    click.echo(f"   • Unique hosts: {len(set([r['host'] for r in all_results]))}")

    if all_results:
        status_summary = {}
        for result in all_results:
            status = result["status"]
            status_summary[status] = status_summary.get(status, 0) + 1

        click.echo("   • Status code breakdown:")
        for status, count in sorted(status_summary.items()):
            emoji = "✅" if status == 200 else "⚠️" if status in [403, 401] else "❓"
            click.echo(f"     {emoji} {status}: {count}")

    if ai_mode and ai_assistant:
        click.echo(f"   • AI analysis: {'✅ Enabled' if ai_mode else '❌ Disabled'}")

    if store_db:
        click.echo(
            f"   • Database storage: {'✅ Enabled' if store_db else '❌ Disabled'}"
        )

    if screenshot:
        click.echo(f"   • Screenshots: ✅ Enabled ({screenshot_tool})")

    # Clear resume state on successful completion
    if save_resume_state and clear_resume:
        resume_file_path = resume_file or "vhost_resume.json"
        clear_resume(resume_file_path)
        if verbose:
            click.echo("🧹 Resume state cleared")

    click.echo(f"💾 All results saved to: {output_dir}/")


def run_ffuf_scan(
    target_ip,
    domain,
    words,
    output_dir,
    timestamp,
    proxy,
    show_all,
    verbose,
    rate_limit,
    timeout,
):
    """Run VHOST scan using ffuf"""
    results = []
    vhost_file = os.path.join(output_dir, f"vhosts_{timestamp}.txt")

    if verbose:
        click.echo(f"📝 Creating VHOST file: {vhost_file}")

    with open(vhost_file, "w") as vf:
        for word in words:
            vf.write(f"{word}.{domain}\n")

    ffuf_cmd = [
        "ffuf",
        "-w",
        vhost_file,
        "-u",
        f"http://{target_ip}/",
        "-H",
        "Host: FUZZ",
        "-mc",
        "200,403,401",
        "-rate",
        str(rate_limit),
        "-timeout",
        str(timeout),
        "-json",
        "-o",
        os.path.join(output_dir, "ffuf_output.json"),
    ]

    if proxy:
        ffuf_cmd += ["-x", proxy]
    if show_all:
        ffuf_cmd[ffuf_cmd.index("-mc") + 1] = "all"

    if verbose:
        click.echo(f"🚀 Command: {' '.join(ffuf_cmd)}")

    click.echo(f"⚡ Running ffuf on {target_ip}...")
    start_time = time.time()

    try:
        result = subprocess.run(ffuf_cmd, capture_output=True, text=True, check=True)
        elapsed = round(time.time() - start_time, 2)
        click.echo(f"✅ ffuf completed successfully in {elapsed}s")

        if verbose and result.stdout:
            click.echo(f"📄 ffuf output:\n{result.stdout}")

    except subprocess.CalledProcessError as e:
        click.echo(f"❌ ffuf failed: {e.stderr}")
        return results
    except FileNotFoundError:
        click.echo("❌ ffuf not found. Please install ffuf.")
        return results

    # Parse results
    ffuf_output_path = os.path.join(output_dir, "ffuf_output.json")
    if os.path.exists(ffuf_output_path):
        try:
            with open(ffuf_output_path) as f:
                ffuf_results = json.load(f)
                for r in ffuf_results.get("results", []):
                    results.append(
                        {
                            "host": r["input"]["FUZZ"],
                            "status": r["status"],
                            "length": r.get("length", 0),
                            "words": r.get("words", 0),
                        }
                    )

            if verbose:
                click.echo(f"📊 Parsed {len(results)} results from ffuf output")

        except (json.JSONDecodeError, KeyError) as e:
            click.echo(f"❌ Error parsing ffuf output: {e}")
    else:
        click.echo(f"⚠️ ffuf output file not found: {ffuf_output_path}")

    return results


def run_gobuster_scan(
    target_ip,
    domain,
    words,
    output_dir,
    timestamp,
    proxy,
    show_all,
    verbose,
    rate_limit,
    timeout,
    retries,
):
    """Run VHOST scan using gobuster"""
    results = []
    wordlist_file = os.path.join(output_dir, f"wordlist_{timestamp}.txt")

    # Create wordlist file for gobuster
    with open(wordlist_file, "w") as f:
        for word in words:
            f.write(f"{word}\n")

    gobuster_cmd = [
        "gobuster",
        "vhost",
        "-u",
        f"http://{target_ip}",
        "-w",
        wordlist_file,
        "--domain",
        domain,
        "-t",
        "50",  # threads
        "--timeout",
        f"{timeout}s",
        "-o",
        os.path.join(output_dir, f"gobuster_output_{timestamp}.txt"),
    ]

    if proxy:
        gobuster_cmd += ["--proxy", proxy]
    if not show_all:
        gobuster_cmd += ["--exclude-length", "0"]

    if verbose:
        click.echo(f"🚀 Command: {' '.join(gobuster_cmd)}")

    click.echo(f"⚡ Running gobuster on {target_ip}...")
    start_time = time.time()

    try:
        result = subprocess.run(
            gobuster_cmd, capture_output=True, text=True, check=True
        )
        elapsed = round(time.time() - start_time, 2)
        click.echo(f"✅ gobuster completed successfully in {elapsed}s")

        # Parse gobuster output
        output_file = os.path.join(output_dir, f"gobuster_output_{timestamp}.txt")
        if os.path.exists(output_file):
            with open(output_file, "r") as f:
                for line in f:
                    if "Found:" in line:
                        # Parse line like: "Found: admin.example.com (Status: 200) [Size: 1234]"
                        parts = line.strip().split()
                        if len(parts) >= 4:
                            host = parts[1]
                            status = parts[3].replace("(Status:", "").replace(")", "")
                            try:
                                status_code = int(status)
                                results.append(
                                    {
                                        "host": host,
                                        "status": status_code,
                                        "source": "gobuster",
                                    }
                                )
                            except ValueError:
                                pass

        if verbose and result.stdout:
            click.echo(f"📄 gobuster output:\n{result.stdout}")

    except subprocess.CalledProcessError as e:
        click.echo(f"❌ gobuster failed: {e.stderr}")
    except FileNotFoundError:
        click.echo("❌ gobuster not found. Please install gobuster.")

    return results


def run_httpx_scan(
    target_ip, domain, words, proxy, show_all, verbose, rate_limit, timeout, retries
):
    """Run VHOST scan using httpx"""
    import time as time_module

    results = []
    click.echo(f"⚡ Running httpx on {target_ip}...")
    start_time = time_module.time()

    # Rate limiting setup
    request_delay = 1.0 / rate_limit if rate_limit > 0 else 0

    for idx, word in enumerate(words, 1):
        vhost = f"{word}.{domain}"

        if verbose and idx % 50 == 0:
            click.echo(
                f"🔄 Progress: {idx}/{len(words)} ({idx / len(words) * 100:.1f}%)"
            )

        for attempt in range(retries + 1):
            try:
                headers = {"Host": vhost}
                client_kwargs = {"timeout": timeout, "follow_redirects": True}
                if proxy:
                    client_kwargs["proxies"] = {"http://": proxy, "https://": proxy}

                with httpx.Client(**client_kwargs) as client:
                    response = client.get(f"http://{target_ip}/", headers=headers)
                    if show_all or response.status_code in [200, 403, 401]:
                        results.append(
                            {
                                "host": vhost,
                                "status": response.status_code,
                                "length": len(response.text),
                                "source": "httpx",
                            }
                        )
                        click.echo(f"✅ Found: {vhost} -> {response.status_code}")
                    break  # Success, break retry loop

            except (
                httpx.ConnectError,
                httpx.TimeoutException,
                httpx.RequestError,
            ) as e:
                if attempt < retries:
                    if verbose:
                        click.echo(f"🔄 Retry {attempt + 1}/{retries} for {vhost}: {e}")
                    time_module.sleep(1)  # Wait before retry
                    continue
                else:
                    if verbose:
                        click.echo(
                            f"❌ Failed after {retries} retries for {vhost}: {e}"
                        )
                    break
            except Exception as e:
                if verbose:
                    click.echo(f"❌ Unexpected error for {vhost}: {e}")
                break

        # Rate limiting
        if request_delay > 0:
            time_module.sleep(request_delay)

    elapsed = round(time_module.time() - start_time, 2)
    click.echo(f"✅ httpx completed in {elapsed}s")
    return results


def run_vhostfinder_scan(
    target_ip,
    domain,
    words,
    output_dir,
    timestamp,
    proxy,
    show_all,
    verbose,
    rate_limit,
    timeout,
    retries,
):
    """Run VHOST scan using VhostFinder"""
    results = []
    wordlist_file = os.path.join(output_dir, f"vhostfinder_wordlist_{timestamp}.txt")
    output_file = os.path.join(output_dir, f"vhostfinder_output_{timestamp}.txt")

    # Create wordlist file for VhostFinder (prefixes only)
    with open(wordlist_file, "w") as f:
        for word in words:
            f.write(f"{word}\n")

    vhostfinder_cmd = [
        "/usr/local/bin/VhostFinder",
        "-ip",
        target_ip,
        "-wordlist",
        wordlist_file,
        "-d",
        domain,
        "-port",
        "80",  # HTTP port
        "-timeout",
        str(timeout),
        "-threads",
        "10",
    ]

    if verbose:
        vhostfinder_cmd.append("-v")

    if proxy:
        vhostfinder_cmd += ["-proxy", proxy]

    # VhostFinder uses HTTPS by default, disable TLS for HTTP
    vhostfinder_cmd += ["-tls=false"]

    # Force bruteforce to show all results if show_all is enabled
    if show_all:
        vhostfinder_cmd.append("-force")

    if verbose:
        click.echo(f"🚀 Command: {' '.join(vhostfinder_cmd)}")

    click.echo(f"⚡ Running VhostFinder on {target_ip}...")
    start_time = time.time()

    try:
        result = subprocess.run(
            vhostfinder_cmd, capture_output=True, text=True, timeout=120
        )
        elapsed = round(time.time() - start_time, 2)

        if result.returncode == 0:
            click.echo(f"✅ VhostFinder completed successfully in {elapsed}s")
        else:
            click.echo(f"⚠️ VhostFinder completed with warnings in {elapsed}s")

        # Parse VhostFinder stdout output
        if result.stdout:
            lines = result.stdout.split("\n")
            for line in lines:
                line = line.strip()
                # Parse lines like: "[-] [3.220.111.131] [/] [301] [134] beta.httpbin.org is not different than the baseline"
                # or positive results like: "[+] [3.220.111.131] [/] [200] [1234] admin.httpbin.org is different!"
                if ("[+]" in line or (show_all and "[-]" in line)) and "] [" in line:
                    try:
                        # Extract status code and hostname
                        parts = line.split("] [")
                        if len(parts) >= 4:
                            # Find status code (should be numeric in brackets)
                            status_code = None
                            hostname = None

                            for i, part in enumerate(parts):
                                # Look for status code pattern
                                if part.isdigit() and len(part) == 3:
                                    status_code = int(part)
                                # Look for hostname after status code
                                if status_code and i > 0:
                                    remaining_text = "] [".join(parts[i + 1 :])
                                    # Extract hostname from text like "134] beta.httpbin.org is not different"
                                    if "] " in remaining_text:
                                        hostname_part = remaining_text.split("] ", 1)[1]
                                        if " " in hostname_part:
                                            hostname = hostname_part.split(" ")[0]
                                        else:
                                            hostname = hostname_part
                                    break

                            if status_code and hostname and ("." in hostname):
                                if (
                                    show_all
                                    or status_code in [200, 403, 401]
                                    or "[+]" in line
                                ):
                                    results.append(
                                        {
                                            "host": hostname,
                                            "status": status_code,
                                            "source": "vhostfinder",
                                        }
                                    )
                                    if verbose:
                                        status_indicator = (
                                            "✅" if "[+]" in line else "ℹ️"
                                        )
                                        click.echo(
                                            f"{status_indicator} Found: {hostname} -> {status_code}"
                                        )
                    except (ValueError, IndexError) as e:
                        if verbose:
                            click.echo(f"⚠️ Could not parse line: {line} ({e})")

                # Also handle simpler output formats if they exist
                elif line and not line.startswith("[") and "Status:" in line:
                    try:
                        parts = line.split()
                        if len(parts) >= 3:
                            host = parts[0]
                            # Find status code
                            status_idx = -1
                            for i, part in enumerate(parts):
                                if part == "Status:":
                                    status_idx = i + 1
                                    break

                            if status_idx > 0 and status_idx < len(parts):
                                status_code = int(parts[status_idx])
                                if show_all or status_code in [200, 403, 401]:
                                    results.append(
                                        {
                                            "host": host,
                                            "status": status_code,
                                            "source": "vhostfinder",
                                        }
                                    )
                                    if verbose:
                                        click.echo(f"✅ Found: {host} -> {status_code}")
                    except (ValueError, IndexError) as e:
                        if verbose:
                            click.echo(f"⚠️ Could not parse line: {line} ({e})")

        if verbose and result.stdout:
            click.echo(f"📄 VhostFinder stdout:\n{result.stdout}")
        if verbose and result.stderr:
            click.echo(f"📄 VhostFinder stderr:\n{result.stderr}")

    except subprocess.TimeoutExpired:
        click.echo("⏰ VhostFinder timed out after 120 seconds")
    except subprocess.CalledProcessError as e:
        click.echo(f"❌ VhostFinder failed: {e.stderr}")
    except FileNotFoundError:
        click.echo("❌ VhostFinder not found at /usr/local/bin/VhostFinder")

    if verbose:
        click.echo(f"📊 Parsed {len(results)} results from VhostFinder output")

    return results


def analyze_results_with_ai(ai_assistant, results, domain, target_ip, ai_model):
    """Analyze VHOST results using AI"""
    if not ai_assistant or not results:
        return None

    try:
        # Prepare data for AI analysis
        analysis_data = {
            "domain": domain,
            "target_ip": target_ip,
            "total_vhosts_found": len(results),
            "vhosts": results[:10],  # Limit to avoid token limits
            "status_codes": list(set([r["status"] for r in results])),
        }

        prompt = f"""
        Analyze these VHOST scan results for {domain} on {target_ip}:

        Found {len(results)} virtual hosts:
        {json.dumps(analysis_data, indent=2)}

        Please provide:
        1. Security assessment of discovered vhosts
        2. Interesting patterns or anomalies
        3. Recommendations for further testing
        4. Risk level assessment
        """

        response = ai_assistant.ask_ai(prompt)
        return response

    except Exception as e:
        click.echo(f"⚠️ AI analysis failed: {e}")
        return None


def save_results_to_files(
    output_dir,
    domain,
    target_ip,
    engine,
    timestamp,
    words,
    results,
    proxy,
    ai_analysis=None,
):
    """Save scan results to JSON and Markdown files"""
    json_path = os.path.join(output_dir, "vhosts_found.json")
    md_path = os.path.join(output_dir, "vhosts_found.md")

    # Enhanced JSON output
    json_data = {
        "scan_info": {
            "domain": domain,
            "target_ip": target_ip,
            "engine": engine,
            "timestamp": timestamp,
            "total_words": len(words),
            "results_found": len(results),
            "proxy_used": proxy if proxy else None,
        },
        "results": results,
        "ai_analysis": ai_analysis,
    }

    with open(json_path, "w") as f:
        json.dump(json_data, f, indent=2)

    # Enhanced Markdown output
    with open(md_path, "w") as f:
        f.write("# 🎯 VHOST Scan Results\n\n")
        f.write(f"**Domain:** `{domain}`  \n")
        f.write(f"**Target IP:** `{target_ip}`  \n")
        f.write(f"**Engine:** `{engine}`  \n")
        f.write(f"**Scan Time:** `{timestamp}`  \n")
        f.write(f"**Total Words:** `{len(words)}`  \n")
        f.write(f"**Results Found:** `{len(results)}`  \n")
        if proxy:
            f.write(f"**Proxy:** `{proxy}`  \n")
        f.write("\n---\n\n")

        if results:
            f.write("## 🚨 Discovered Virtual Hosts\n\n")
            f.write("| Host | Status Code | Length | Source |\n")
            f.write("|------|------------|--------|---------|\n")
            for r in results:
                status_emoji = (
                    "✅"
                    if r["status"] == 200
                    else "⚠️"
                    if r["status"] in [403, 401]
                    else "❓"
                )
                length = r.get("length", "N/A")
                source = r.get("source", engine)
                f.write(
                    f"| `{r['host']}` | {status_emoji} {r['status']} | {length} | {source} |\n"
                )
        else:
            f.write("## ❌ No Virtual Hosts Found\n\n")
            f.write("No virtual hosts were discovered during this scan.\n")

        # Add AI analysis if available
        if ai_analysis:
            f.write("\n## 🧠 AI Analysis\n\n")
            f.write(f"```\n{ai_analysis}\n```\n")


def run_gowitness_screenshots(
    target_ip,
    domain,
    results,
    output_dir,
    timestamp,
    proxy,
    verbose,
    timeout,
    threads,
    fullpage,
):
    """Run screenshots using gowitness"""
    screenshot_dir = os.path.join(output_dir, "screenshots")
    Path(screenshot_dir).mkdir(parents=True, exist_ok=True)

    if verbose:
        click.echo(f"📸 Running gowitness screenshots on {len(results)} hosts...")

    # Create gowitness batch file
    batch_file = os.path.join(screenshot_dir, f"gowitness_batch_{timestamp}.txt")
    with open(batch_file, "w") as f:
        for result in results:
            f.write(f"http://{result['host']}\n")

    gowitness_cmd = [
        "gowitness",
        "file",
        batch_file,
        "--destination",
        screenshot_dir,
        "--timeout",
        str(timeout),
        "--threads",
        str(threads),
    ]

    if proxy:
        gowitness_cmd += ["--proxy", proxy]
    if fullpage:
        gowitness_cmd += ["--full-page"]

    click.echo("📸 Running gowitness screenshots...")

    if verbose:
        click.echo(f"🚀 Command: {' '.join(gowitness_cmd)}")

    try:
        result = subprocess.run(
            gowitness_cmd, capture_output=True, text=True, check=True
        )
        click.echo("✅ gowitness completed successfully")
        if verbose and result.stdout:
            click.echo(f"📄 gowitness output:\n{result.stdout}")
    except subprocess.CalledProcessError as e:
        click.echo(f"❌ gowitness failed: {e.stderr}")
    except FileNotFoundError:
        click.echo("❌ gowitness not found. Please install gowitness.")
        click.echo("💡 Install with: go install github.com/sensepost/gowitness@latest")

    return screenshot_dir


def run_aquatone_screenshots(
    target_ip,
    domain,
    results,
    output_dir,
    timestamp,
    proxy,
    verbose,
    timeout,
    threads,
):
    """Run screenshots using aquatone"""
    screenshot_dir = os.path.join(output_dir, "aquatone_screenshots")
    Path(screenshot_dir).mkdir(parents=True, exist_ok=True)

    # Create aquatone report directory
    report_dir = os.path.join(screenshot_dir, f"report_{timestamp}")
    Path(report_dir).mkdir(parents=True, exist_ok=True)

    # Generate aquatone URLs file
    urls_file = os.path.join(screenshot_dir, f"aquatone_urls_{timestamp}.txt")
    with open(urls_file, "w") as f:
        for result in results:
            f.write(f"http://{result['host']}\n")

    # Aquatone uses different command structure
    aquatone_cmd = [
        "aquatone",
        "-ports",
        "80,443",
        "-threads",
        str(threads),
        "-screenshot-timeout",
        str(timeout * 1000),  # aquatone expects milliseconds
        "-out",
        report_dir,
    ]

    if proxy:
        aquatone_cmd += ["-proxy", proxy]

    if verbose:
        click.echo(f"📸 Running aquatone screenshots on {len(results)} hosts...")

    click.echo("📸 Running aquatone screenshots...")

    if verbose:
        click.echo(f"🚀 Command: {' '.join(aquatone_cmd)}")

    try:
        # Aquatone reads URLs from stdin
        urls_input = "\n".join([f"http://{result['host']}" for result in results])

        process = subprocess.Popen(
            aquatone_cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            cwd=report_dir,
        )

        stdout, stderr = process.communicate(input=urls_input)

        if process.returncode == 0:
            click.echo("✅ aquatone completed successfully")
            if verbose and stdout:
                click.echo(f"📄 aquatone output:\n{stdout}")
        else:
            click.echo(f"❌ aquatone failed with return code {process.returncode}")
            if stderr:
                click.echo(f"Error: {stderr}")

    except FileNotFoundError:
        click.echo("❌ aquatone not found. Please install aquatone.")
        click.echo(
            "💡 Install with: go install github.com/michenriksen/aquatone@latest"
        )

    return report_dir


if __name__ == "__main__":
    cli()
