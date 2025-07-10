#!/usr/bin/env python3
import httpx
import click


@click.command()
@click.option("--ip", required=True, help="Target IP (e.g. 1.2.3.4)")
@click.option("--domain", required=True, help="Main domain (e.g. example.com)")
@click.option(
    "--vhost", required=True, help="Subdomain/VHOST to test (e.g. admin, store)"
)
@click.option("--proxy", help="Optional proxy (e.g. http://127.0.0.1:8080)")
@click.option("--https", is_flag=True, help="Use HTTPS instead of HTTP")
@click.option("--insecure", is_flag=True, help="Ignore SSL cert warnings")
def check(ip, domain, vhost, proxy, https, insecure):
    scheme = "https" if https else "http"
    target_url = f"{scheme}://{ip}/"
    vhost_header = f"{vhost}.{domain}"

    headers = {"Host": vhost_header, "User-Agent": "Mozilla/5.0 (Recon VHOST Checker)"}

    proxies = {"http://": proxy, "https://": proxy} if proxy else None

    try:
        resp = httpx.get(
            target_url,
            headers=headers,
            timeout=10,
            follow_redirects=True,
            proxies=proxies,
            verify=not insecure,
        )
        print(f"[+] {vhost_header} → {resp.status_code} ({len(resp.text)} bytes)")
        if resp.status_code in [200, 403, 401]:
            print("    ⚠️  Possible valid VHOST!")
        if "shopify" in resp.text.lower():
            print("    🛍️  Shopify detected in response body.")
    except Exception as e:
        print(f"[-] {vhost_header} → ERROR: {e}")


if __name__ == "__main__":
    check()
