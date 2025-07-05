import os
import sys
import click


@click.command(name="one-shot")
@click.option("--domain", required=True, help="Target domain")
@click.option("--output-dir", required=True, help="Directory to save results")
@click.option("--resolvers", type=click.Path(), help="Resolvers file for DNS")
@click.option("--wordlist", type=click.Path(), help="Wordlist for permutations")
@click.option("--proxy", help="Proxy URL for tools like httpcli or urlcli")
@click.option("--flow", type=click.Path(), help="Path to recon flow YAML for dnscli")
@click.option("--resume", is_flag=True, help="Resume previous one-shot session")
@click.option("--only-dns", is_flag=True, help="Only run DNS module")
def cli(domain, output_dir, resolvers, wordlist, proxy, flow, resume, only_dns):
    os.makedirs(output_dir, exist_ok=True)

    # DNS module
    dns_cmd = f"reconcli dns --domain {domain} --output-dir {output_dir}"
    if resolvers:
        dns_cmd += f" --resolvers {resolvers}"
    if wordlist:
        dns_cmd += f" --wordlist {wordlist}"
    if flow:
        dns_cmd += f" --flow {flow}"
    if proxy:
        dns_cmd += f" --proxy {proxy}"
    if resume:
        dns_cmd += " --resume"

    print("[ONE-SHOT] Running DNS module...")
    print(f"[ONE-SHOT] Command: {dns_cmd}")
    os.system(dns_cmd)

    if only_dns:
        return

    # Export IPs from subs_resolved_tagged.txt
    resolved_file = os.path.join(output_dir, "subs_resolved_tagged.txt")
    ips_file = os.path.join(output_dir, "ips.txt")
    if os.path.exists(resolved_file):
        print("[ONE-SHOT] Extracting IPs...")
        with open(resolved_file) as rf, open(ips_file, "w") as wf:
            for line in rf:
                parts = line.strip().split()
                if len(parts) >= 2 and parts[1].count(".") == 3:
                    wf.write(parts[1] + "\n")
        print(f"[ONE-SHOT] Exported IPs to {ips_file}")
    else:
        print(f"[ONE-SHOT] Could not find {resolved_file}, skipping IP export.")
        sys.exit(1)

    # IP Scan
    print("[ONE-SHOT] Running IPS module...")
    if not os.path.exists(ips_file):
        print(f"[ONE-SHOT] Could not find {ips_file}, skipping IPS module.")
        sys.exit(1)
    ips_cmd = f"reconcli ipscli --input {ips_file} --scan rustscan --output-dir {output_dir}/ipscan --verbose"
    os.system(ips_cmd)

    # URL Discovery
    print("[ONE-SHOT] Running URL module...")
    subs_resolved = os.path.join(output_dir, "subs_resolved.txt")
    if not os.path.exists(subs_resolved):
        print(f"[ONE-SHOT] Could not find {subs_resolved}, skipping URL module.")
        sys.exit(1)
    url_cmd = (
        f"reconcli urlcli --input {subs_resolved} --output-dir {output_dir}/urlscan"
    )
    if proxy:
        url_cmd += f" --proxy {proxy}"
    os.system(url_cmd)

    # Vulnerability Scanning
    print("[ONE-SHOT] Running VULN module...")
    urls_json = os.path.join(output_dir, "urlscan/urls.json")
    if not os.path.exists(urls_json):
        print(f"[ONE-SHOT] Could not find {urls_json}, skipping VULN module.")
        sys.exit(1)
    vuln_cmd = (
        f"reconcli vulncli --input {urls_json} --output-dir {output_dir}/vulnscan"
    )
    os.system(vuln_cmd)

    print("[ONE-SHOT] Recon complete. All results in:", output_dir)


if __name__ == "__main__":
    cli()
