import click
import json
import os
from reconcli.utils.resume import load_resume, save_resume_state
from reconcli.utils.loaders import run_from_yaml
from reconcli.utils.mdexport import generate_dns_summary


@click.command("dns")
@click.option("--domain", required=True, help="Target domain")
@click.option("--resolvers", type=click.Path(), help="Path to resolvers file")
@click.option("--wordlist", type=click.Path(), help="Path to wordlist for permutation")
@click.option("--proxy", type=str, help="Proxy URL (e.g. http://127.0.0.1:8080)")
@click.option("--output-dir", type=click.Path(), help="Directory to save results")
@click.option("--flow", type=click.Path(), help="Path to YAML flow file")
@click.option(
    "--dnsx-rate-limit", type=int, help="Rate limit for DNSx (requests per second)"
)
@click.option(
    "--whois-file", type=click.Path(), help="Path to WhoisFreaks whois.json file"
)
@click.option("--wildcard-detect", is_flag=True, help="Detect wildcard DNS behavior")
@click.option(
    "--wildcard-filter", is_flag=True, help="Filter out wildcard DNS responses"
)
@click.option("--resume", is_flag=True, help="Resume previous session")
@click.option("--resume-from", type=str, help="Resume from specific step")
def cli(
    domain,
    resolvers,
    wordlist,
    proxy,
    output_dir,
    flow,
    dnsx_rate_limit,
    whois_file,
    wildcard_detect,
    wildcard_filter,
    resume,
    resume_from,
):

    # ✅ Validation
    if wildcard_detect and (not wordlist or not resolvers):
        print(
            "[ERR] --wordlist and --resolvers are required for wildcard detection using AlterX."
        )
        return

    # ✅ Resume logic
    if resume:
        print("[RESUME] Loading previous session state...")
        state = load_resume(output_dir)
        print(json.dumps(state, indent=2))
        return

    if resume_from:
        print(f"[RESUME] Resuming from step: {resume_from}")
        state = load_resume(output_dir)
        print(json.dumps(state, indent=2))
        # TODO: resume from specific step logic here
        return

    # ✅ YAML Flow execution
    vars = {
        "{{Target}}": domain,
        "{{Resolvers}}": resolvers or "",
        "{{Wordlist}}": wordlist or "",
        "{{Output}}": output_dir or "",
    }

    if flow:
        run_from_yaml(flow, vars)

        # ✅ Save resume state
        if output_dir:
            save_resume_state(output_dir, {
                "last_module": "dns",
                "completed": True,
                "domain": domain,
                "flow": flow,
                "wildcard": wildcard_detect,
            })
            print(f"[+] Saved resume state to {output_dir}/resume.cfg")

    else:
        print(
            "[ERR] No YAML flow file provided. Use --flow to specify a recon workflow."
        )
