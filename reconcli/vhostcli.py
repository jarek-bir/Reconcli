import click
import subprocess
import os
import httpx
import json
import shutil
import time
from datetime import datetime
from pathlib import Path
from reconcli.utils.notifications import send_notification


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
    type=click.Choice(["ffuf", "httpx"]),
    default="ffuf",
    help="Engine to use for VHOST fuzzing",
)
@click.option("--verbose", is_flag=True, help="Enable verbose output")
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
    slack_webhook,
    discord_webhook,
):
    # Input validation
    if not ip and not ip_list:
        raise click.UsageError("You must provide either --ip or --ip-list")

    # Check if chosen engine is available
    if not shutil.which(engine):
        click.echo(f"❌ Error: {engine} is not installed or not in PATH")
        if engine == "ffuf":
            click.echo("💡 Install with: go install github.com/ffuf/ffuf/v2@latest")
        elif engine == "httpx":
            click.echo("💡 Install with: pip install httpx")
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
        if proxy:
            click.echo(f"🔀 Proxy: {proxy}")

    for target_idx, target_ip in enumerate(targets, 1):
        click.echo(
            f"\n🎯 [{target_idx}/{len(targets)}] Target: {domain} ({target_ip}) | Engine: {engine}"
        )

        ip_output_dir = os.path.join(output_dir, target_ip.replace(":", "_"))
        Path(ip_output_dir).mkdir(parents=True, exist_ok=True)
        results = []

        if engine == "ffuf":
            vhost_file = os.path.join(ip_output_dir, f"vhosts_{timestamp}.txt")

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
                "-json",
                "-o",
                os.path.join(ip_output_dir, "ffuf_output.json"),
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
                result = subprocess.run(
                    ffuf_cmd, capture_output=True, text=True, check=True
                )
                elapsed = round(time.time() - start_time, 2)
                click.echo(f"✅ ffuf completed successfully in {elapsed}s")

                if verbose and result.stdout:
                    click.echo(f"📄 ffuf output:\n{result.stdout}")

            except subprocess.CalledProcessError as e:
                click.echo(f"❌ ffuf failed: {e.stderr}")
                continue
            except FileNotFoundError:
                click.echo(f"❌ ffuf not found. Please install ffuf.")
                continue

            ffuf_output_path = os.path.join(ip_output_dir, "ffuf_output.json")
            if os.path.exists(ffuf_output_path):
                try:
                    with open(ffuf_output_path) as f:
                        ffuf_results = json.load(f)
                        for r in ffuf_results.get("results", []):
                            results.append(
                                {"host": r["input"]["FUZZ"], "status": r["status"]}
                            )

                    if verbose:
                        click.echo(f"📊 Parsed {len(results)} results from ffuf output")

                except (json.JSONDecodeError, KeyError) as e:
                    click.echo(f"❌ Error parsing ffuf output: {e}")
            else:
                click.echo(f"⚠️  ffuf output file not found: {ffuf_output_path}")

        elif engine == "httpx":
            click.echo(f"⚡ Running httpx on {target_ip}...")
            start_time = time.time()

            for idx, word in enumerate(words, 1):
                vhost = f"{word}.{domain}"

                if verbose and idx % 50 == 0:
                    click.echo(
                        f"🔄 Progress: {idx}/{len(words)} ({idx/len(words)*100:.1f}%)"
                    )

                try:
                    headers = {"Host": vhost}
                    client_kwargs = {"timeout": 10, "follow_redirects": True}
                    if proxy:
                        client_kwargs["proxies"] = {"http://": proxy, "https://": proxy}

                    with httpx.Client(**client_kwargs) as client:
                        response = client.get(f"http://{target_ip}/", headers=headers)
                        if show_all or response.status_code in [200, 403, 401]:
                            results.append(
                                {"host": vhost, "status": response.status_code}
                            )
                            click.echo(f"✅ Found: {vhost} -> {response.status_code}")

                except httpx.ConnectError as e:
                    if verbose:
                        click.echo(f"🔌 Connection error for {vhost}: {e}")
                    continue
                except httpx.TimeoutException as e:
                    if verbose:
                        click.echo(f"⏰ Timeout for {vhost}: {e}")
                    continue
                except httpx.RequestError as e:
                    if verbose:
                        click.echo(f"📡 Request error for {vhost}: {e}")
                    continue
                except httpx.HTTPStatusError as e:
                    if verbose:
                        click.echo(f"🌐 HTTP error for {vhost}: {e}")
                    continue
                except Exception as e:
                    if verbose:
                        click.echo(f"❌ Unexpected error for {vhost}: {e}")
                    continue

            elapsed = round(time.time() - start_time, 2)
            click.echo(f"✅ httpx completed in {elapsed}s")

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
            f.write(f"# 🎯 VHOST Scan Results\n\n")
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
                        else "⚠️" if r["status"] in [403, 401] else "❓"
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

    click.echo(f"\n🏁 Scan completed! Total targets: {len(targets)}")


if __name__ == "__main__":
    cli()
