import click
from reconcli.dnscli import cli as dns_cli
from reconcli.urlcli import cli as url_cli
from reconcli.vhostcli import cli as vhost_cli
from reconcli.one_shot import cli as one_shot_cli


@click.group()
def cli():
    pass


cli.add_command(dns_cli, name="dns")
cli.add_command(url_cli, name="url")
cli.add_command(vhost_cli, name="vhost")
cli.add_command(one_shot_cli, name="one-shot")

if __name__ == "__main__":
    cli()
