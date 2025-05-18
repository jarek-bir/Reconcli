import json
import socket
import argparse
import requests
from ipwhois import IPWhois


def get_ptr(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception as e:
        print(f"[ERROR] PTR lookup failed for {ip}: {e}")
        return None


def get_geo(ip):
    try:
        resp = requests.get(f"http://ip-api.com/json/{ip}", timeout=5)
        if resp.status_code == 200:
            geo = resp.json()
            return {
                "country": geo.get("country"),
                "city": geo.get("city"),
                "org": geo.get("org"),
                "isp": geo.get("isp"),
            }
    except Exception as e:
        print(f"[ERROR] Geo lookup failed for {ip}: {e}")
    return {}


def get_asn(ip):
    try:
        obj = IPWhois(ip)
        res = obj.lookup_rdap()
        return {
            "asn": res.get("asn"),
            "asn_description": res.get("asn_description"),
            "network": res.get("network", {}).get("name"),
        }
    except Exception as e:
        print(f"[ERROR] ASN lookup failed for {ip}: {e}")
    return {}


def enrich(data):
    enriched = []
    for entry in data:
        ip = entry.get("ip")
        if not ip:
            continue
        entry["ptr"] = get_ptr(ip)
        entry["geo"] = get_geo(ip)
        entry["asn"] = get_asn(ip)
        enriched.append(entry)
    return enriched


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, help="Input tagged JSON")
    parser.add_argument("--output", required=True, help="Output enriched JSON")
    args = parser.parse_args()

    with open(args.input) as f:
        data = json.load(f)

    enriched = enrich(data)

    with open(args.output, "w") as f:
        json.dump(enriched, f, indent=2)

    print(f"[ENRICH-FULL] Saved to: {args.output}")
