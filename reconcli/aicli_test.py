#!/usr/bin/env python3
import click


@click.command()
@click.option("--test", help="Test option")
def aicli(test):
    """Test AI CLI"""
    click.echo("AI CLI Test Working!")
    if test:
        click.echo(f"Test value: {test}")


if __name__ == "__main__":
    aicli()
