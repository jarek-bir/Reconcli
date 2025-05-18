import json
import re
import click


def strip_ansi(text):
    ansi_escape = re.compile(r"\x1B[@-_][0-?]*[ -/]*[@-~]")
    return ansi_escape.sub("", text)


def load_resolved(input_file):
    results = []
    with open(input_file, "r") as f:
        for line in f:
            line = strip_ansi(line.strip())
            if not line or " " not in line:
                continue
            parts = line.split()
            if len(parts) >= 2:
                subdomain = parts[0]
                ip = parts[-1].strip("[]")
                results.append({"domain": subdomain, "ip": ip, "tags": []})
    return results


def auto_tag(entry):
    domain = entry["domain"]
    tags = []

    if any(t in domain for t in ["cdn", "cloudfront", "akamai", "fastly"]):
        tags.append("cdn")
    if "mail" in domain or "smtp" in domain:
        tags.append("mail")
    if "dev" in domain or "test" in domain:
        tags.append("dev")
    if "admin" in domain or "panel" in domain:
        tags.append("admin")
    if "api" in domain:
        tags.append("api")

    return tags


@click.command()
@click.option("--input", required=True, help="Path to subs_resolved.txt")
@click.option("--output", required=True, help="Path to output subs_tagged.json")
def cli(input, output):
    resolved = load_resolved(input)
    for entry in resolved:
        entry["tags"] = auto_tag(entry)

    with open(output, "w") as f:
        json.dump(resolved, f, indent=2)
    print(f"[TAGGING] Saved tagged results to: {output}")


if __name__ == "__main__":
    cli()
