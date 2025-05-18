import click


@click.command()
@click.option("--domain", required=True, help="Domain name (e.g. example.com)")
@click.option("--ip", required=True, help="Target IP address")
@click.option(
    "--wordlist", required=True, type=click.Path(exists=True), help="VHOST wordlist"
)
def cli(domain, ip, wordlist):
    print(f"[VHOST] Target: {domain} ({ip})")
    print(f"[VHOST] Wordlist: {wordlist}")
