#!/usr/bin/env python3
import httpx
import click
import time


@click.command()
@click.option("--ip", required=True, help="Target IP (e.g. 1.2.3.4 or 1.2.3.4:8080)")
@click.option("--domain", required=True, help="Main domain (e.g. example.com)")
@click.option(
    "--vhost", required=True, help="Subdomain/VHOST to test (e.g. admin, store)"
)
@click.option("--proxy", help="Optional proxy (e.g. http://127.0.0.1:8080)")
@click.option("--https", is_flag=True, help="Use HTTPS instead of HTTP")
@click.option("--insecure", is_flag=True, help="Ignore SSL cert warnings")
@click.option("--verbose", is_flag=True, help="Show detailed response information")
def check(ip, domain, vhost, proxy, https, insecure, verbose):
    scheme = "https" if https else "http"

    # Handle IP with port
    if ":" in ip and not ip.startswith("["):  # IPv4 with port
        target_url = f"{scheme}://{ip}/"
    elif ip.startswith("[") and "]:" in ip:  # IPv6 with port
        target_url = f"{scheme}://{ip}/"
    else:  # IP without port
        target_url = f"{scheme}://{ip}/"

    vhost_header = f"{vhost}.{domain}"

    headers = {
        "Host": vhost_header,
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate",
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1",
    }

    # Create client with proper configuration
    client_kwargs = {"timeout": 10, "follow_redirects": True, "verify": not insecure}

    if proxy:
        client_kwargs["proxies"] = {"http://": proxy, "https://": proxy}

    try:
        start_time = time.time()
        with httpx.Client(**client_kwargs) as client:
            resp = client.get(target_url, headers=headers)

        response_time = round((time.time() - start_time) * 1000, 2)

        print(
            f"[+] {vhost_header} → {resp.status_code} ({len(resp.text)} bytes) [{response_time}ms]"
        )

        if resp.status_code in [200, 403, 401]:
            print("    ⚠️  Possible valid VHOST!")

        # Check for common technologies/patterns
        response_lower = resp.text.lower()
        if "shopify" in response_lower:
            print("    🛍️  Shopify detected in response body.")
        if "cloudflare" in response_lower:
            print("    ☁️  Cloudflare detected in response body.")
        if "nginx" in response_lower or "nginx" in str(resp.headers).lower():
            print("    🔧  Nginx detected.")
        if "apache" in response_lower or "apache" in str(resp.headers).lower():
            print("    �  Apache detected.")

        # Show server header if present
        if "server" in resp.headers:
            print(f"    🖥️  Server: {resp.headers['server']}")

        # Show title if present
        if "<title>" in response_lower:
            title_start = response_lower.find("<title>") + 7
            title_end = response_lower.find("</title>", title_start)
            if title_end > title_start:
                title = resp.text[title_start:title_end].strip()
                if title:
                    print(f"    📄  Title: {title}")

        # Verbose output
        if verbose:
            print(f"    📊  Response headers:")
            for key, value in resp.headers.items():
                print(f"        {key}: {value}")
            print(f"    🔗  Final URL: {resp.url}")

    except httpx.ConnectError as e:
        print(f"[-] {vhost_header} → CONNECTION ERROR: {e}")
    except httpx.TimeoutException as e:
        print(f"[-] {vhost_header} → TIMEOUT: {e}")
    except httpx.HTTPStatusError as e:
        print(f"[-] {vhost_header} → HTTP ERROR: {e}")
    except httpx.RequestError as e:
        print(f"[-] {vhost_header} → REQUEST ERROR: {e}")
    except Exception as e:
        print(f"[-] {vhost_header} → UNEXPECTED ERROR: {e}")


if __name__ == "__main__":
    check()
