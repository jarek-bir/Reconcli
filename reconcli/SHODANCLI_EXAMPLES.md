# 🌐 SHODAN CLI - ReconCLI Elite Examples
# Zaawansowane przykłady użycia Shodan CLI
# Data: 2025-07-19

## 🚀 QUICK START

### Podstawowe wyszukiwanie
```bash
# Apache servers
python -m reconcli shodancli -q "apache" -c 50

# Nginx with version info
python -m reconcli shodancli -q "nginx/1.18" --format table

# All SSH servers in Poland
python -m reconcli shodancli -q "port:22" --country PL --format rich
```

### Lookup konkretnych IP
```bash
# Google DNS
python -m reconcli shodancli -ip 8.8.8.8 --format table

# Cloudflare
python -m reconcli shodancli -ip 1.1.1.1 --format rich
```

## 🗄️ NOWE FUNKCJE BAZY DANYCH I RETRY

### Store do lokalnej bazy SQLite
```bash
# Zapisz wyniki do bazy danych dla analizy
python -m reconcli shodancli -q "mongodb" -c 100 --store-db --format table

# Kombinuj z innymi opcjami
python -m reconcli shodancli -q "elasticsearch" --country US --store-db --format rich
```

### Retry przy błędach API
```bash
# Domyślnie 1 próba, można zwiększyć
python -m reconcli shodancli -q "apache" --retry 3 --format table

# Kombinuj z store-db
python -m reconcli shodancli -q "nginx" -c 50 --retry 5 --store-db --format json
```

### Analiza zapisanych danych
```bash
# Sprawdź bazę danych
sqlite3 ~/.reconcli/shodan_results.db "SELECT count(*), query FROM shodan_results GROUP BY query;"

# Export z bazy do CSV
sqlite3 -header -csv ~/.reconcli/shodan_results.db "SELECT * FROM shodan_results WHERE country='United States';" > us_results.csv
```

## 📊 FORMATY OUTPUTU

### JSON (domyślny)
```bash
python -m reconcli shodancli -q "IIS" -c 10 --format json
```

### Rich tabela z kolorami
```bash
python -m reconcli shodancli -q "apache" -c 20 --format table
```

### Rich panels (najbardziej czytelny)
```bash
python -m reconcli shodancli -q "nginx" -c 15 --format rich
```

### CSV do analizy
```bash
python -m reconcli shodancli -q "mongodb" -c 100 --format csv --save mongo_servers.csv
```

### TXT format (tylko IP)
```bash
python -m reconcli shodancli -q "elasticsearch" --format txt > ips.txt
```

### Silent mode (tylko IP bez logów)
```bash
python -m reconcli shodancli -q "elasticsearch" --silent > ips.txt
```

## 🔍 ZAAWANSOWANE WYSZUKIWANIE

### Filtry geograficzne
```bash
# USA tylko
python -m reconcli shodancli -q "apache" --country US --format table

# Kombination filtrów
python -m reconcli shodancli -q "nginx" --country DE --org "Hetzner" --format rich
```

### Filtry portów
```bash
# HTTP/HTTPS
python -m reconcli shodancli -q "server" --ports "80,443" --format table

# Common ports
python -m reconcli shodancli -q "linux" --ports "22,80,443,3389" --format rich
```

### Filtry produktów
```bash
# Specific product
python -m reconcli shodancli -q "port:80" --product "Apache" --format table

# OS filtering
python -m reconcli shodancli -q "ssh" --os "Ubuntu" --format rich
```

## 📈 ANALIZA FACETS

### Analiza krajów
```bash
python -m reconcli shodancli -q "apache" --facets "country" --format json | jq '.facets'
```

### Top organizacje
```bash
python -m reconcli shodancli -q "nginx" --facets "org" --format json
```

### Kombinowane facets
```bash
python -m reconcli shodancli -q "port:22" --facets "country,org,port" --format json
```

## 🎯 ASN ENUMERATION

### Google ASN
```bash
python -m reconcli shodancli -asn AS15169 --format table --save google_ips.json
```

### Cloudflare ASN
```bash
python -m reconcli shodancli -asn AS13335 --format rich -c 100
```

### Z dodatkowymi filtrami
```bash
python -m reconcli shodancli -asn AS15169 --ports "80,443" --format csv
```

## 🔐 EXPLOIT SEARCH

### Wszystkie exploity Apache
```bash
python -m reconcli shodancli --exploit "apache" --format table
```

### High severity tylko
```bash
python -m reconcli shodancli --exploit "nginx" --severity high --format rich
```

### Specific CVE
```bash
python -m reconcli shodancli --exploit "CVE-2021-44228" --format json
```

## 📊 EXPORT & ANALYSIS

### JSON z pretty print
```bash
python -m reconcli shodancli -q "elasticsearch" --format json --save elastic.json
```

### CSV for Excel/analysis
```bash
python -m reconcli shodancli -q "mongodb" --format csv --save mongo_analysis.csv
```

### TXT file z IP listą
```bash
python -m reconcli shodancli -q "redis" --format txt --save redis_ips.txt
```

## 🔄 AUTOMATION EXAMPLES

### Daily monitoring z bazą danych
```bash
#!/bin/bash
# daily_scan.sh

# MongoDB exposed - zapisz do bazy
python -m reconcli shodancli -q "product:MongoDB" --country US --store-db --retry 3 --format csv --save "mongodb_$(date +%Y%m%d).csv"

# Elasticsearch exposed z retry
python -m reconcli shodancli -q "elasticsearch" --country US --store-db --retry 5 --format csv --save "elastic_$(date +%Y%m%d).csv"

# Redis exposed z pełną obsługą błędów
python -m reconcli shodancli -q "redis" --country US --store-db --retry 3 --format csv --save "redis_$(date +%Y%m%d).csv"
```

### Bulk analysis z bazą danych
```bash
#!/bin/bash
# bulk_analysis.sh

# Lista query do sprawdzenia
QUERIES=("mongodb" "elasticsearch" "redis" "memcached" "mysql")

for query in "${QUERIES[@]}"; do
    echo "Scanning $query..."
    python -m reconcli shodancli -q "$query" -c 100 --store-db --retry 5 --format json --save "${query}_$(date +%Y%m%d).json"
    sleep 10  # Rate limiting
done

# Generuj raport z bazy
echo "Generating report..."
sqlite3 -header -csv ~/.reconcli/shodan_results.db \
    "SELECT country, count(*) as count FROM shodan_results GROUP BY country ORDER BY count DESC;" \
    > country_analysis.csv
```

### Mass IP lookup
```bash
#!/bin/bash
# mass_lookup.sh

while read ip; do
    echo "=== $ip ==="
    python -m reconcli shodancli -ip "$ip" --format rich
    echo ""
done < ips.txt
```

### ASN monitoring
```bash
#!/bin/bash
# asn_monitor.sh

ASNS=("AS15169" "AS13335" "AS8075" "AS16509")

for asn in "${ASNS[@]}"; do
    echo "Scanning $asn..."
    python -m reconcli shodancli -asn "$asn" --format csv --save "${asn}_$(date +%Y%m%d).csv"
done
```

## 🎪 CREATIVE QUERIES

### IoT devices
```bash
# Webcams
python -m reconcli shodancli -q "Server: IP Webcam Server" --format rich

# Printers
python -m reconcli shodancli -q "hp-printer" --format table

# Industrial systems
python -m reconcli shodancli -q "Modbus" --format rich
```

### Cloud services
```bash
# Docker APIs
python -m reconcli shodancli -q "Docker" --ports "2375,2376" --format table

# Kubernetes
python -m reconcli shodancli -q "kubernetes" --format rich

# Jenkins exposed
python -m reconcli shodancli -q "X-Jenkins" --format table
```

### Databases exposed
```bash
# All databases
python -m reconcli shodancli -q "mongodb OR mysql OR postgresql OR redis OR elasticsearch" --format csv

# NoSQL focus
python -m reconcli shodancli -q "mongodb OR couchdb OR cassandra" --country US --format rich
```

## 📱 MOBILE & API

### API endpoints
```bash
# REST APIs
python -m reconcli shodancli -q "json api" --format table

# GraphQL
python -m reconcli shodancli -q "graphql" --format rich

# SOAP services
python -m reconcli shodancli -q "soap wsdl" --format json
```

## 🎯 SPECIFIC SEARCHES

### Cryptocurrency
```bash
# Bitcoin nodes
python -m reconcli shodancli -q "bitcoin" --format table

# Ethereum nodes
python -m reconcli shodancli -q "ethereum geth" --format rich

# Mining pools
python -m reconcli shodancli -q "stratum mining" --format json
```

### Game servers
```bash
# Minecraft
python -m reconcli shodancli -q "minecraft" --format table

# CS:GO servers
python -m reconcli shodancli -q "Counter-Strike" --format rich
```

## 🔧 TROUBLESHOOTING

### Check API limits
```bash
python -m reconcli shodancli --account --format json
```

### Test connection
```bash
python -m reconcli shodancli -q "test" -c 1 --format json
```

### Verbose debugging
```bash
export SHODAN_DEBUG=1
python -m reconcli shodancli -q "apache" -c 5 --format rich
```

## 🚀 PERFORMANCE TIPS

### Large datasets
```bash
# Use streaming for large results
python -m reconcli shodancli -q "nginx" -c 1000 --format csv --save nginx_large.csv

# Split by country for manageability
python -m reconcli shodancli -q "apache" --country US -c 500 --format csv
python -m reconcli shodancli -q "apache" --country DE -c 500 --format csv
```

### API efficiency
```bash
# Use facets instead of large searches
python -m reconcli shodancli -q "port:80" --facets "country,org" --format json

# Target specific ASNs
python -m reconcli shodancli -asn AS15169 --format csv  # More efficient than broad search
```

## 💡 PRO TIPS

1. **API Key**: Set `SHODAN_API_KEY` environment variable
2. **Rate Limits**: Free accounts have limits, use -c to control
3. **Facets**: Use for statistical analysis without hitting limits
4. **ASN Search**: More reliable for infrastructure enumeration
5. **CSV Export**: Best for further analysis in Excel/pandas
6. **Rich Format**: Best for manual review and presentations
7. **Silent Mode**: Perfect for piping to other tools
8. **🆕 Store DB**: Use `--store-db` for long-term analysis and correlation
9. **🆕 Retry Logic**: Use `--retry N` for unstable network connections
10. **🆕 Database Analysis**: Query SQLite database for advanced analytics

### Database Schema
```sql
-- Tabela shodan_results
CREATE TABLE shodan_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    query TEXT,
    ip_str TEXT,
    port INTEGER,
    product TEXT,
    version TEXT,
    organization TEXT,
    country TEXT,
    asn TEXT,
    data TEXT,
    raw_json TEXT
);
```

### Advanced Database Queries
```bash
# Top countries
sqlite3 ~/.reconcli/shodan_results.db "SELECT country, count(*) FROM shodan_results GROUP BY country ORDER BY count(*) DESC LIMIT 10;"

# Timeline analysis
sqlite3 ~/.reconcli/shodan_results.db "SELECT date(timestamp), count(*) FROM shodan_results GROUP BY date(timestamp);"

# Product analysis
sqlite3 ~/.reconcli/shodan_results.db "SELECT product, count(*) FROM shodan_results WHERE product != '' GROUP BY product ORDER BY count(*) DESC;"
```

## 🔗 INTEGRATION EXAMPLES

### With other ReconCLI modules
```bash
# Get IPs and scan ports
python -m reconcli shodancli -q "nginx" --silent | python -m reconcli portcli -

# Get ASN and analyze DNS
python -m reconcli shodancli -asn AS15169 --silent | python -m reconcli dnscli -
```

### With external tools
```bash
# Shodan + Nmap
python -m reconcli shodancli -q "ssh" --silent | nmap -iL - -p 22

# Shodan + Masscan
python -m reconcli shodancli -asn AS15169 --silent | masscan -iL - -p 80,443
```

---
**⚠️ UWAGA**: Używaj odpowiedzialnie i zgodnie z ToS Shodan oraz prawem lokalnym!
