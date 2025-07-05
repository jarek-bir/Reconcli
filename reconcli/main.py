import click

from reconcli.dnscli import cli as dns_cli
from reconcli.urlcli import main as url_cli
from reconcli.vhostcli import cli as vhost_cli  # ← poprawiona linia
from reconcli.urlsorter import cli as urlsort_cli
from reconcli.jscli import main as js_cli
from reconcli.httpcli import httpcli
from reconcli.ipscli import ipscli
from reconcli.one_shot import cli as one_shot_cli
from reconcli.zonewalkcli import cli as zonewalk_cli
from reconcli.takeovercli import takeovercli
from reconcli.whoisfreakscli import cli as whoisfreaks_cli


@click.group()
def cli():
    """ReconCLI – modular recon tool"""
    pass


cli.add_command(dns_cli, name="dns")
cli.add_command(url_cli, name="urlcli")
cli.add_command(vhost_cli, name="vhostcli")
cli.add_command(urlsort_cli, name="urlsort")
cli.add_command(js_cli, name="jscli")
cli.add_command(httpcli, name="httpcli")
cli.add_command(ipscli, name="ipscli")
cli.add_command(one_shot_cli, name="oneshot")
cli.add_command(zonewalk_cli, name="zonewalkcli")
cli.add_command(takeovercli, name="takeover")  # <-- 🚀 tu dodajemy takeover
cli.add_command(whoisfreaks_cli, name="whoisfreaks")  # <-- 🚀 nowy moduł WhoisFreaks


if __name__ == "__main__":
    cli()
