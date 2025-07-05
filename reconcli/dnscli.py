import os
import sys
import socket
import click
from tqdm import tqdm


@click.command()
@click.option("--input", type=click.Path(), help="Path to file with subdomains")
@click.option("--output-dir", required=True, help="Directory to save results")
@click.option(
    "--resolve-only",
    is_flag=True,
    help="Only resolve subdomains to IPs and tag with PTRs",
)
def cli(input, output_dir, resolve_only):
    if not input or not os.path.exists(input):
        click.echo("Error: You must provide a valid --input file with subdomains.")
        sys.exit(1)

    with open(input) as f:
        subdomains = [line.strip() for line in f if line.strip()]

    os.makedirs(output_dir, exist_ok=True)

    resolved = {}
    tagged_output_path = os.path.join(output_dir, "subs_resolved_tagged.txt")

    with open(tagged_output_path, "w") as outf:
        for sub in tqdm(subdomains, desc="Resolving subdomains"):
            try:
                ip = socket.gethostbyname(sub)
            except:
                ip = "unresolved"

            ptr = ""
            tags = []

            if ip != "unresolved":
                try:
                    ptr = socket.gethostbyaddr(ip)[0]
                except:
                    ptr = ""

                ptr_l = ptr.lower()
                if any(c in ptr_l for c in ["cloudflare", "akamai", "cdn", "fastly"]):
                    tags.append("cdn")
                if "amazonaws" in ptr_l or "aws" in ptr_l:
                    tags.append("aws")
                if "google" in ptr_l or "gcp" in ptr_l:
                    tags.append("gcp")
                if "microsoft" in ptr_l or "azure" in ptr_l:
                    tags.append("azure")
                if "corp" in ptr_l:
                    tags.append("corp")
                if "vpn" in ptr_l:
                    tags.append("vpn")
                if "honeypot" in ptr_l:
                    tags.append("honeypot")

            outf.write(
                f"{sub} {ip} PTR: {ptr or '-'} TAGS: {','.join(tags) if tags else '-'}\n"
            )

    click.echo(f"[+] Done. Tagged results saved to: {tagged_output_path}")


if __name__ == "__main__":
    cli()
