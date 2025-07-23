# 🌐 IPSCLI - Advanced IP Analysis Module

**ReconCLI IP Analysis Module** to zaawansowany moduł do analizy adresów IP z wykorzystaniem wielu źródeł danych, cache'owania wyników, AI-powered analysis oraz profesjonalnego raportowania.

## 📋 Spis treści

1. [Funkcje](#funkcje)
2. [Instalacja](#instalacja)
3. [Podstawowe użycie](#podstawowe-użycie)
4. [Zaawansowane opcje](#zaawansowane-opcje)
5. [Cache Management](#cache-management)
6. [AI Analysis](#ai-analysis)
7. [Skanowanie portów](#skanowanie-portów)
8. [Przykłady użycia](#przykłady-użycia)
9. [Format danych wyjściowych](#format-danych-wyjściowych)
10. [Rozwiązywanie problemów](#rozwiązywanie-problemów)

## 🚀 Funkcje

### Core Features
- **Multi-source IP enrichment**: ipinfo.io, uncover, shodan
- **Geolocation analysis**: Analiza geograficzna i ASN mapping
- **Cloud provider detection**: AWS, GCP, Azure, DigitalOcean
- **CDN filtering**: Automatyczne wykrywanie i filtrowanie CDN
- **Resume functionality**: Możliwość wznawiania przerwanych analiz

### Port Scanning
- **Multiple scanners**: rustscan, masscan, nmap, simple
- **Custom port lists**: Własne listy portów do skanowania
- **Service detection**: Automatyczna detekcja usług
- **Performance optimization**: Wielowątkowe skanowanie

### Cache Management
- **IP Scan Cache**: Cache wyników skanowania portów
- **AI Analysis Cache**: Cache analiz AI
- **Configurable TTL**: Konfigurowalny czas życia cache
- **Statistics**: Szczegółowe statystyki cache (hit rate, rozmiar)

### AI-Powered Analysis
- **Pattern Analysis**: Analiza wzorców infrastruktury IP
- **Threat Classification**: Klasyfikacja zagrożeń dla pojedynczych IP
- **Attack Surface Analysis**: Analiza powierzchni ataku
- **Risk Assessment**: Ocena ryzyka i rekomendacje

### Professional Reporting
- **JSON Output**: Szczegółowe raporty w formacie JSON
- **Markdown Reports**: Profesjonalne raporty Markdown
- **Executive Summary**: AI-generated podsumowania wykonawcze
- **Statistics**: Kompleksowe statystyki analizy

## 💿 Instalacja

### Wymagania systemowe
```bash
# Python 3.8+
python --version

# Wymagane narzędzia (opcjonalne)
sudo apt install masscan nmap
cargo install rustscan

# Uncover (dla dodatkowego discovery)
go install github.com/projectdiscovery/uncover/cmd/uncover@latest
```

### Instalacja modułu
```bash
# Klonowanie repozytorium
git clone https://github.com/jarek-bir/reconcli
cd reconcli

# Instalacja zależności
pip install -r requirements.txt

# Test instalacji
reconcli ipscli --help
```

## 🎯 Podstawowe użycie

### 1. Podstawowa analiza IP
```bash
# Analiza z plik tekstowego
reconcli ipscli --input ips.txt --resolve-from raw --enrich --verbose

# Analiza z subdomain resolution format
reconcli ipscli --input subs_resolved.txt --resolve-from subs --enrich
```

### 2. Skanowanie portów
```bash
# Rustscan (domyślny, szybki)
reconcli ipscli --input ips.txt --scan rustscan --enrich

# Masscan (bardzo szybki, wymaga uprawnień root)
sudo reconcli ipscli --input ips.txt --scan masscan --enrich

# Nmap (szczegółowy)
reconcli ipscli --input ips.txt --scan nmap --enrich

# Simple scan (wbudowany scanner)
reconcli ipscli --input ips.txt --scan simple --enrich
```

### 3. Filtrowanie i analiza
```bash
# Filtrowanie CDN
reconcli ipscli --input ips.txt --enrich --filter-cdn

# Filtrowanie według kraju
reconcli ipscli --input ips.txt --enrich --filter-country US

# Filtrowanie cloud providers
reconcli ipscli --input ips.txt --enrich --filter-cloud aws,gcp
```

## ⚙️ Zaawansowane opcje

### CIDR Expansion
```bash
# Rozwijanie zakresów CIDR do pojedynczych IP
reconcli ipscli --input cidrs.txt --cidr-expand --enrich --verbose
```

### Uncover Integration
```bash
# Automatyczne wykrywanie ASN i query
reconcli ipscli --input ips.txt --use-uncover --enrich

# Custom query
reconcli ipscli --input ips.txt --use-uncover --uncover-query 'org:"Example Corp"'

# Specific engine
reconcli ipscli --input ips.txt --use-uncover --uncover-engine shodan

# Analiza istniejącego JSON output z uncover
reconcli ipscli --uncover-json uncover_results.json --enrich
```

### Custom Port Lists
```bash
# Własna lista portów
echo -e "22\n80\n443\n8080" > custom_ports.txt
reconcli ipscli --input ips.txt --scan rustscan --port-list custom_ports.txt
```

## 🗄️ Cache Management

### Włączanie cache
```bash
# IP scan cache
reconcli ipscli --input ips.txt --scan rustscan --ip-cache --enrich

# AI analysis cache
reconcli ipscli --input ips.txt --enrich --ai-mode --ai-cache

# Oba typy cache
reconcli ipscli --input ips.txt --scan masscan --enrich --ai-mode --ip-cache --ai-cache
```

### Konfiguracja cache
```bash
# Custom cache directories
reconcli ipscli --input ips.txt --ip-cache --ip-cache-dir /tmp/ip_cache --ai-cache --ai-cache-dir /tmp/ai_cache

# Custom TTL (w sekundach)
reconcli ipscli --input ips.txt --ip-cache --ip-cache-max-age 3600  # 1 godzina
reconcli ipscli --input ips.txt --ai-cache --ai-cache-max-age 7200  # 2 godziny
```

### Cache statistics
```bash
# Statystyki IP cache
reconcli ipscli --ip-cache --ip-cache-stats

# Statystyki AI cache
reconcli ipscli --ai-cache --ai-cache-stats
```

### Czyszczenie cache
```bash
# Czyszczenie IP cache
reconcli ipscli --ip-clear-cache

# Czyszczenie AI cache
reconcli ipscli --ai-clear-cache
```

## 🤖 AI Analysis

### AI Modes
```bash
# Pełny tryb AI (wszystkie funkcje)
reconcli ipscli --input ips.txt --enrich --ai-mode --ai-cache

# Analiza wzorców IP
reconcli ipscli --input ips.txt --enrich --ai-pattern-analysis

# Klasyfikacja zagrożeń
reconcli ipscli --input ips.txt --enrich --ai-threat-classification

# Analiza powierzchni ataku
reconcli ipscli --input ips.txt --enrich --scan rustscan --ai-attack-surface
```

### AI Configuration
```bash
# Konfiguracja progu ufności
reconcli ipscli --input ips.txt --enrich --ai-mode --ai-confidence-threshold 0.8

# AI z cache i custom settings
reconcli ipscli --input ips.txt --enrich --ai-mode \
  --ai-cache --ai-cache-max-age 86400 \
  --ai-confidence-threshold 0.7
```

## 🔍 Skanowanie portów

### Masscan (Recommended for large scans)
```bash
# Podstawowy masscan
sudo reconcli ipscli --input ips.txt --scan masscan

# Masscan z cache i custom rate
sudo reconcli ipscli --input large_ip_list.txt --scan masscan --ip-cache --verbose

# Note: Masscan wymaga uprawnień root
```

### Rustscan (Fast and reliable)
```bash
# Rustscan z custom ulimit
reconcli ipscli --input ips.txt --scan rustscan --verbose

# Rustscan z custom port list
reconcli ipscli --input ips.txt --scan rustscan --port-list web_ports.txt
```

### Nmap (Detailed analysis)
```bash
# Nmap z service detection
reconcli ipscli --input ips.txt --scan nmap --verbose

# Nmap z timeout settings
reconcli ipscli --input ips.txt --scan nmap --timeout 15
```

## 📝 Przykłady użycia

### 1. Kompleksowa analiza z AI
```bash
#!/bin/bash
# complete_analysis.sh

echo "8.8.8.8" > test_ips.txt
echo "1.1.1.1" >> test_ips.txt
echo "9.9.9.9" >> test_ips.txt

reconcli ipscli \
  --input test_ips.txt \
  --resolve-from raw \
  --enrich \
  --scan masscan \
  --ai-mode \
  --ip-cache \
  --ai-cache \
  --markdown \
  --json \
  --verbose \
  --output-dir results/complete_analysis
```

### 2. Analiza corporate infrastructure
```bash
#!/bin/bash
# corporate_analysis.sh

# Analiza infrastruktury korporacyjnej
reconcli ipscli \
  --input corporate_ranges.txt \
  --cidr-expand \
  --enrich \
  --scan rustscan \
  --filter-cdn \
  --ai-threat-classification \
  --ai-pattern-analysis \
  --honeypot \
  --exclude-tags cdn,hosting \
  --markdown \
  --verbose
```

### 3. Bug bounty reconnaissance
```bash
#!/bin/bash
# bugbounty_recon.sh

# Recon dla bug bounty
reconcli ipscli \
  --input target_subdomains_resolved.txt \
  --resolve-from subs \
  --enrich \
  --scan rustscan \
  --use-uncover \
  --uncover-engine shodan \
  --filter-cdn \
  --ai-attack-surface \
  --store-db \
  --target-domain example.com \
  --program "Example Bug Bounty" \
  --markdown \
  --verbose
```

### 4. Cloud infrastructure audit
```bash
#!/bin/bash
# cloud_audit.sh

# Audit infrastruktury chmurowej
reconcli ipscli \
  --input cloud_ips.txt \
  --enrich \
  --scan nmap \
  --filter-cloud aws,gcp,azure \
  --ai-pattern-analysis \
  --ai-threat-classification \
  --ai-confidence-threshold 0.8 \
  --ip-cache \
  --ai-cache \
  --json \
  --markdown \
  --verbose
```

### 5. Batch processing with resume
```bash
#!/bin/bash
# batch_processing.sh

# Przetwarzanie wsadowe z resume
reconcli ipscli \
  --input large_ip_list.txt \
  --enrich \
  --scan masscan \
  --ai-mode \
  --ip-cache \
  --ai-cache \
  --resume \
  --verbose

# W przypadku przerwania, ponowne uruchomienie:
reconcli ipscli --resume --verbose
```

### 6. Threat hunting analysis
```bash
#!/bin/bash
# threat_hunting.sh

# Analiza threat hunting
reconcli ipscli \
  --input suspicious_ips.txt \
  --enrich \
  --scan simple \
  --honeypot \
  --ai-threat-classification \
  --ai-confidence-threshold 0.9 \
  --filter-country CN,RU,KP,IR \
  --exclude-tags cdn \
  --markdown \
  --verbose
```

## 📊 Format danych wyjściowych

### Struktura katalogów
```
output/ipscli/
├── ips_enriched.json          # Wzbogacone dane IP
├── ips_ports.json             # Wyniki skanowania portów
├── ips_summary.md             # Podsumowanie Markdown
├── ai_analysis.json           # Wyniki analizy AI
├── ai_executive_summary.md    # Podsumowanie wykonawcze AI
├── ip_analysis_TIMESTAMP.json # Pełny raport JSON
├── ipscli_resume.json         # Stan resume
└── uncover_summary.md         # Podsumowanie uncover (jeśli użyte)
```

### JSON Schema - Enriched Data
```json
{
  "192.168.1.1": {
    "ip": "192.168.1.1",
    "city": "Mountain View",
    "region": "California",
    "country": "US",
    "org": "AS15169 Google LLC",
    "postal": "94043",
    "timezone": "America/Los_Angeles",
    "hostname": "dns.google",
    "ptr": "dns.google",
    "cloud_provider": "gcp",
    "is_cdn": false,
    "tags": ["cloud", "gcp", "dns-server"],
    "scan_time": "2025-07-23T17:29:21.123456"
  }
}
```

### JSON Schema - Port Scan Results
```json
{
  "192.168.1.1": [53, 80, 443, 853],
  "192.168.1.2": {"status": "no open ports"},
  "192.168.1.3": {"error": "scan timeout"}
}
```

### JSON Schema - AI Analysis
```json
{
  "pattern_analysis": {
    "high_value_targets": [
      {
        "ip": "192.168.1.1",
        "type": "government",
        "details": "US Government Agency"
      }
    ],
    "attack_vectors": [
      "Government infrastructure targets",
      "High cloud infrastructure concentration"
    ],
    "risk_assessment": {
      "overall_score": 7.5,
      "risk_level": "high",
      "total_targets": 100,
      "high_value_count": 5
    },
    "recommendations": [
      "Exercise extreme caution with government IPs",
      "Consider cloud-specific attack vectors"
    ]
  }
}
```

## 🔧 Konfiguracja i customization

### Environment Variables
```bash
# Proxy settings
export HTTP_PROXY=http://proxy.company.com:8080
export HTTPS_PROXY=http://proxy.company.com:8080

# Custom timeout settings
export IPSCLI_TIMEOUT=30
export IPSCLI_THREADS=20
```

### Custom Port Lists

#### Web Services Ports
```bash
# web_ports.txt
80
443
8080
8443
8000
8888
3000
```

#### Database Ports
```bash
# db_ports.txt
3306
5432
1521
1433
27017
6379
```

#### Critical Services
```bash
# critical_ports.txt
22
23
21
25
53
80
443
3389
```

## 🛠️ Rozwiązywanie problemów

### Częste problemy

#### 1. Permission denied dla masscan
```bash
# Problem: masscan wymaga uprawnień root
sudo reconcli ipscli --input ips.txt --scan masscan

# Alternatywa: użyj rustscan
reconcli ipscli --input ips.txt --scan rustscan
```

#### 2. Rate limiting od ipinfo.io
```bash
# Użyj proxy lub zmniejsz liczbę wątków
reconcli ipscli --input ips.txt --threads 5 --timeout 15

# Użyj cache żeby uniknąć powtórnych zapytań
reconcli ipscli --input ips.txt --ip-cache
```

#### 3. Timeout podczas skanowania
```bash
# Zwiększ timeout
reconcli ipscli --input ips.txt --scan nmap --timeout 30

# Użyj szybszego skanera
reconcli ipscli --input ips.txt --scan rustscan
```

#### 4. Problemy z uncover
```bash
# Sprawdź instalację uncover
which uncover

# Test uncover ręcznie
uncover -q 'org:"Google"' -silent
```

### Debug mode
```bash
# Włącz verbose logging
reconcli ipscli --input ips.txt --verbose

# Sprawdź logi błędów
cat errors.log

# Sprawdź debug files
cat debug_ips_loaded.txt
cat debug_scan_output.log
```

### Performance tuning

#### Dla dużych list IP
```bash
# Użyj cache
reconcli ipscli --input large_list.txt --ip-cache --ai-cache

# Zmniejsz liczbę wątków
reconcli ipscli --input large_list.txt --threads 5

# Użyj resume
reconcli ipscli --input large_list.txt --resume
```

#### Dla szybkiego skanowania
```bash
# Masscan (najszybszy)
sudo reconcli ipscli --input ips.txt --scan masscan

# Rustscan (szybki, bez root)
reconcli ipscli --input ips.txt --scan rustscan

# Simple scan (dla małych list)
reconcli ipscli --input ips.txt --scan simple
```

## 📚 Advanced Examples

### Integration z innymi narzędziami

#### 1. Pipeline z subfinder
```bash
#!/bin/bash
# subfinder_pipeline.sh

# Zbierz subdomeny
subfinder -d example.com -silent > subdomains.txt

# Resolve IP addresses
cat subdomains.txt | httpx -silent -ip > resolved_subs.txt

# Analiza IP z ipscli
reconcli ipscli \
  --input resolved_subs.txt \
  --resolve-from subs \
  --enrich \
  --scan rustscan \
  --ai-mode \
  --ip-cache \
  --ai-cache \
  --markdown
```

#### 2. Integration z nmap scripts
```bash
#!/bin/bash
# nmap_integration.sh

# Pierwsza faza: identyfikacja otwartych portów
reconcli ipscli \
  --input targets.txt \
  --scan rustscan \
  --ip-cache \
  --json

# Druga faza: szczegółowa analiza z nmap scripts
jq -r 'keys[]' output/ipscli/ips_ports.json | while read ip; do
  nmap -sV -sC -A "$ip" -oN "nmap_${ip}.txt"
done
```

## 🔗 API Reference

### Cache Manager Classes

#### IPScanCacheManager
```python
from reconcli.ipscli import IPScanCacheManager

cache = IPScanCacheManager("custom_cache_dir")

# Store result
cache.store_result("port_scan", ["1.1.1.1"], {"1.1.1.1": [80, 443]})

# Get cached result
result = cache.get_cached_result("port_scan", ["1.1.1.1"])

# Statistics
stats = cache.get_cache_stats()
```

#### AICacheManager
```python
from reconcli.ipscli import AICacheManager

ai_cache = AICacheManager("ai_cache_dir")

# Store analysis
ai_cache.store_analysis("threat_classification", input_data, analysis_result)

# Get cached analysis
cached = ai_cache.get_cached_analysis("threat_classification", input_data)
```

### Core Functions

#### IP Enrichment
```python
from reconcli.ipscli import enrich_ips

enriched_data = enrich_ips(["8.8.8.8", "1.1.1.1"])
```

#### Port Scanning
```python
from reconcli.ipscli import scan_ips

results = scan_ips(["8.8.8.8"], scan_type="rustscan")
```

#### AI Analysis
```python
from reconcli.ipscli import ai_analyze_ip_patterns, ai_classify_ip_threats

# Pattern analysis
patterns = ai_analyze_ip_patterns(ip_list, enriched_data)

# Threat classification
threat_info = ai_classify_ip_threats(ip_data)
```

## 📈 Performance Guidelines

### Małe analizy (< 100 IP)
- Używaj `--scan simple` lub `--scan rustscan`
- Cache nie jest konieczny
- AI analysis można włączyć bez problemów

### Średnie analizy (100-1000 IP)
- Używaj `--scan rustscan` lub `--scan masscan`
- Włącz cache: `--ip-cache --ai-cache`
- Rozważ zmniejszenie threads: `--threads 10`

### Duże analizy (1000+ IP)
- Używaj `--scan masscan` (wymaga root)
- Obowiązkowo cache: `--ip-cache --ai-cache`
- Używaj resume: `--resume`
- Zmniejsz threads: `--threads 5`
- Rozważ batch processing

## 🔒 Security Considerations

### Ethical Scanning
- Skanuj tylko autoryzowane cele
- Szanuj rate limits
- Używaj honeypot detection: `--honeypot`

### Data Privacy
- Cache może zawierać wrażliwe dane
- Regularnie czyść cache: `--ip-clear-cache --ai-clear-cache`
- Chroń pliki wyjściowe

### Network Impact
- Używaj odpowiednich rate limits
- Rozważ proxy dla dużych analiz
- Monitoruj wpływ na sieć

---

## 📞 Support

### Issues i Bug Reports
- GitHub Issues: https://github.com/jarek-bir/reconcli/issues
- Dołącz logi verbose i informacje o systemie

### Contributing
- Fork repository
- Utwórz feature branch
- Wyślij Pull Request

### Documentation Updates
Ta dokumentacja jest żywa - prosimy o zgłaszanie aktualizacji i poprawek.

---

**Created by:** ReconCLI Team  
**Last Updated:** 2025-07-23  
**Version:** 1.0.0
