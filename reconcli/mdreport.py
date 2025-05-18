import json
import os
import click
from reconcli.utils.mdexport import generate_dns_summary
from reconcli.utils.resume import load_resume, save_resume_state


@click.command()
@click.option("--input", required=True, help="Path to enriched JSON input file")
@click.option(
    "--output", required=True, help="Path to output markdown file (dns_summary.md)"
)
@click.option("--resume", is_flag=True, help="Resume previous session")
@click.option("--resume-from", type=str, help="Resume from specific step")
def cli(input, output, resume, resume_from):
    """
    CLI wrapper to generate a clean Obsidian-ready DNS Markdown summary.
    Supports resume state tracking.
    """
    output_dir = os.path.dirname(output)

    if resume:
        print("[RESUME] Loading previous session state...")
        state = load_resume(output_dir)
        print(json.dumps(state, indent=2))
        return

    if resume_from:
        print(f"[RESUME] Resuming from step: {resume_from}")
        state = load_resume(output_dir)
        print(json.dumps(state, indent=2))
        # TODO: Add selective resume logic here
        return

    with open(input, "r") as f:
        enriched_data = json.load(f)

    if not enriched_data:
        print("[!] No data found in enriched JSON.")
        return

    domain = enriched_data[0].get("subdomain", "").split(".", 1)[-1]

    generate_dns_summary(domain, enriched_data, output_dir)

    save_resume_state(
        output_dir, {"last_module": "mdreport", "completed": True, "domain": domain}
    )

    print(f"[+] Saved resume state to {output_dir}/resume.cfg")


if __name__ == "__main__":
    cli()
