import os
import click
import subprocess


@click.command()
@click.option("--domain", required=True, help="Root domain to scan")
@click.option(
    "--resolvers", type=click.Path(exists=True), help="Path to resolvers file"
)
@click.option("--wordlist", type=click.Path(exists=True), help="Path to wordlist")
@click.option(
    "--flow", type=click.Path(exists=True), help="YAML flow file for DNS module"
)
@click.option("--proxy", help="Proxy URL (e.g. http://127.0.0.1:8080)")
@click.option("--output-dir", type=click.Path(), help="Directory to save results")
@click.option("--only-dns", is_flag=True, help="Run only the DNS module")
def cli(domain, resolvers, wordlist, flow, proxy, output_dir, only_dns):
    print(f"[ONE-SHOT] Recon for: {domain}")
    base_cmd = ["reconcli"]

    if only_dns:
        dns_cmd = base_cmd + ["dns", "--domain", domain]
        if resolvers:
            dns_cmd += ["--resolvers", resolvers]
        if wordlist:
            dns_cmd += ["--wordlist", wordlist]
        if proxy:
            dns_cmd += ["--proxy", proxy]
        if output_dir:
            dns_cmd += ["--output-dir", output_dir]
        if flow:
            dns_cmd += ["--flow", flow]
        print(f"[ONE-SHOT] Command: {' '.join(dns_cmd)}")
        print("[ONE-SHOT] Running DNS module...")
        subprocess.run(dns_cmd, check=True)
        return

    # TODO: future: urlcli, ipcli, vulncli etc.
    print("[ONE-SHOT] Currently only DNS module is supported.")
    print("Use --only-dns to run it directly.")


if __name__ == "__main__":
    cli()
