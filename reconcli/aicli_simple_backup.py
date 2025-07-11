#!/usr/bin/env python3

import click
import openai
import os
from dotenv import load_dotenv

load_dotenv()
openai.api_key = os.getenv("OPENAI_API_KEY")


@click.command()
@click.option("--prompt", help="Ask the AI anything recon-related.")
@click.option("--payload", help="Generate payload (e.g. xss, lfi, ssrf).")
@click.option("--plan", help="Generate recon flow for a given domain.")
def aicli(prompt, payload, plan):
    """
    AI Assistant: Payload generation, recon planning, and prompt-based support.
    """
    if prompt:
        ask_gpt(prompt)
    elif payload:
        ask_gpt(f"Generate a {payload.upper()} payload with short explanation.")
    elif plan:
        ask_gpt(f"Create a complete recon plan for {plan}, including tools and order.")
    else:
        click.echo("💡 Use --prompt, --payload or --plan to interact with the AI.")


def ask_gpt(message):
    click.echo(f"\n🤖 Asking AI: {message}\n")
    try:
        response = openai.ChatCompletion.create(
            model="gpt-4",
            messages=[
                {
                    "role": "system",
                    "content": "You are a helpful AI assistant focused on bug bounty, recon, and security tools.",
                },
                {"role": "user", "content": message},
            ],
        )
        answer = response["choices"][0]["message"]["content"]
        click.echo(f"🧠 AI:\n{answer}\n")
    except Exception as e:
        click.echo(f"❌ Error: {e}")
