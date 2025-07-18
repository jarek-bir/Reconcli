# XSS CLI - Advanced XSS Testing Module

## Overview
XSS CLI is an advanced Cross-Site Scripting (XSS) testing module for ReconCLI that provides comprehensive XSS vulnerability detection and analysis capabilities.

## Features

### Core Functionality
- **Multi-tool XSS scanning** - Integration with popular XSS testing tools
- **Custom payload management** - Store and organize custom XSS payloads
- **WAF detection** - Identify Web Application Firewalls
- **URL discovery** - Gather URLs from multiple sources
- **Database tracking** - SQLite database for results management
- **Resume capabilities** - Pause and resume scanning sessions

### Supported Tools
- **Dalfox** - Fast XSS scanner
- **XSStrike** - Advanced XSS detection tool
- **kxss** - Fast XSS detection
- **Linkfinder** - Endpoint discovery in JavaScript
- **ParamSpider** - Parameter discovery
- **WAYbackurls** - Historical URL discovery
- **GAU** - GetAllUrls
- **Hakrawler** - Fast web crawler
- **GoSpider** - Fast web spider
- **Katana** - Next-generation crawling framework
- **Nuclei** - Vulnerability scanner

### 1. Zarządzanie Bazą Danych
- Automatyczne tworzenie bazy SQLite
- Zapisywanie wyników testów
- Zarządzanie niestandardowymi payloadami
- Statystyki i raporty

### 2. Integracja z Zewnętrznymi Narzędziami
- **Dalfox** - Nowoczesny skaner XSS
- **XSStrike** - Python-owy skaner XSS  
- **kxss** - Szybkie wykrywanie reflected XSS
- **Nuclei** - Szablony XSS
- **Hakrawler/Katana** - Crawling stron
- **Linkfinder** - Wykrywanie endpointów w JS
- **ParamSpider** - Odkrywanie parametrów

### 3. Ręczne Testowanie
- Niestandardowe payloady
- Różne metody HTTP (GET/POST)
- Testowanie konkretnych parametrów
- Automatyczne zapisywanie wyników

## Instalacja Narzędzi

```bash
# Dalfox
go install github.com/hahwul/dalfox/v2@latest

# XSStrike  
git clone https://github.com/s0md3v/XSStrike.git
cd XSStrike
pip install -r requirements.txt

# kxss
go install github.com/Emoe/kxss@latest

# Nuclei
go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest

# Hakrawler
go install github.com/hakluke/hakrawler@latest

# Katana
go install github.com/projectdiscovery/katana/cmd/katana@latest

# Linkfinder
git clone https://github.com/GerbenJavado/LinkFinder.git
cd LinkFinder
pip install -r requirements.txt

# ParamSpider
git clone https://github.com/devanshbatham/ParamSpider
cd ParamSpider
pip install -r requirements.txt

# GAU (Get All URLs)
go install github.com/lc/gau/v2/cmd/gau@latest

# Waybackurls
go install github.com/tomnomnom/waybackurls@latest
```

## Przykłady Użycia

### Sprawdzenie Zależności
```bash
python -m reconcli.xsscli check-deps
```

### Zbieranie URL-i
```bash
# Z wielu źródeł
python -m reconcli.xsscli gather-urls --domain example.com --output urls.txt --sources wayback,gau,hakrawler

# Tylko z wayback machine
python -m reconcli.xsscli gather-urls --domain example.com --sources wayback
```

### Filtrowanie URL-i
```bash
# Znajdź URL-e z parametrami
cat urls.txt | gf xss > potential_xss.txt

# Lub używając modułu
python -m reconcli.xsscli gf --input urls.txt --pattern xss --output filtered.txt
```

### Automatyczne Skanowanie

#### Dalfox
```bash
python -m reconcli.xsscli dalfox --target "https://example.com/search?q=test" --threads 50 --output dalfox_results.txt
```

#### XSStrike
```bash
python -m reconcli.xsscli xsstrike --input urls.txt --threads 10 --output xsstrike_results.txt
```

#### kxss
```bash
python -m reconcli.xsscli kxss --input urls.txt --output kxss_results.txt
```

#### Nuclei
```bash
python -m reconcli.xsscli nuclei-xss --input urls.txt --output nuclei_results.txt
```

### Ręczne Testowanie
```bash
# Podstawowe testowanie GET
python -m reconcli.xsscli manual-test --target "https://example.com/search" --param "q"

# Testowanie POST
python -m reconcli.xsscli manual-test --target "https://example.com/form" --method POST --param "message"

# Z niestandardowymi payloadami
python -m reconcli.xsscli manual-test --target "https://example.com/search" --payloads custom_payloads.txt
```

### Crawling
```bash
# Hakrawler
python -m reconcli.xsscli hakrawler --domain example.com --depth 3 --output crawled.txt

# Katana
python -m reconcli.xsscli katana --domain example.com --depth 2 --threads 20 --output katana_results.txt
```

### Odkrywanie Parametrów
```bash
python -m reconcli.xsscli paramspider --domain example.com --output params/
```

### Analiza JavaScript
```bash
python -m reconcli.xsscli linkfinder --input "https://example.com/app.js" --output js_endpoints.txt
```

### Zarządzanie Payloadami
```bash
# Dodaj niestandardowy payload
python -m reconcli.xsscli add-payload --payload "<script>alert('custom')</script>" --category "custom" --description "Custom alert payload"

# Lista payloadów
python -m reconcli.xsscli list-payloads --category custom
```

### Eksport Wyników
```bash
# JSON
python -m reconcli.xsscli export --format json --output results.json

# CSV  
python -m reconcli.xsscli export --format csv --output results.csv

# TXT
python -m reconcli.xsscli export --format txt --output results.txt
```

### Statystyki i Raporty
```bash
# Ogólne statystyki
python -m reconcli.xsscli stats

# Tylko podatne wyniki
python -m reconcli.xsscli stats --vulnerable-only

# Filtruj po narzędziu
python -m reconcli.xsscli stats --tool dalfox --limit 20

# Szczegółowe wyniki
python -m reconcli.xsscli results --severity high --limit 50
```

### Zarządzanie Queue Resume
```bash
# Dodaj URL do kolejki
python -m reconcli.xsscli resume-add --url "https://example.com/test"

# Import URL-i z pliku
python -m reconcli.xsscli resume-import --input urls.txt

# Status kolejki
python -m reconcli.xsscli resume-stat

# Wyczyść kolejkę
python -m reconcli.xsscli resume-clear
```

### Czyszczenie Bazy
```bash
# Usuń stare wyniki i zoptymalizuj bazę
python -m reconcli.xsscli cleanup
```

## Struktura Bazy Danych

### Tabela `results`
- `id` - Unikalny identyfikator
- `url` - Testowany URL
- `param` - Testowany parametr
- `payload` - Użyty payload
- `reflected` - Czy payload został odbity
- `vulnerable` - Czy wykryto podatność
- `method` - Metoda HTTP
- `response_code` - Kod odpowiedzi
- `response_length` - Długość odpowiedzi
- `timestamp` - Czas testu
- `tool_used` - Użyte narzędzie
- `severity` - Poziom ważności
- `notes` - Dodatkowe notatki

### Tabela `custom_payloads`
- `id` - Unikalny identyfikator
- `payload` - Treść payload
- `category` - Kategoria
- `description` - Opis
- `active` - Czy aktywny

### Tabela `resume`
- `id` - Unikalny identyfikator
- `url` - URL do przetestowania
- `status` - Status (pending/completed)
- `timestamp` - Czas dodania

## Zaawansowane Workflow

### 1. Pełne Skanowanie Domeny
```bash
#!/bin/bash
DOMAIN="example.com"

# 1. Zbierz URL-e
python -m reconcli.xsscli gather-urls --domain $DOMAIN --output ${DOMAIN}_urls.txt

# 2. Filtruj potencjalne XSS
python -m reconcli.xsscli gf --input ${DOMAIN}_urls.txt --pattern xss --output ${DOMAIN}_xss_candidates.txt

# 3. Skanuj z różnymi narzędziami
python -m reconcli.xsscli dalfox --target-file ${DOMAIN}_xss_candidates.txt --output ${DOMAIN}_dalfox.txt
python -m reconcli.xsscli kxss --input ${DOMAIN}_xss_candidates.txt --output ${DOMAIN}_kxss.txt

# 4. Eksportuj wyniki
python -m reconcli.xsscli export --format json --output ${DOMAIN}_xss_results.json

# 5. Pokaż statystyki
python -m reconcli.xsscli stats --vulnerable-only
```

### 2. CI/CD Integration
```yaml
# .github/workflows/xss-scan.yml
name: XSS Security Scan
on: [push, pull_request]

jobs:
  xss-scan:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v2
    - name: Setup Python
      uses: actions/setup-python@v2
      with:
        python-version: 3.9
    - name: Install dependencies
      run: |
        pip install -r requirements.txt
        go install github.com/hahwul/dalfox/v2@latest
    - name: Run XSS scan
      run: |
        python -m reconcli.xsscli manual-test --target "${{ env.TARGET_URL }}"
        python -m reconcli.xsscli stats --vulnerable-only
```

## Najlepsze Praktyki

1. **Zawsze sprawdź zależności** przed rozpoczęciem skanowania
2. **Używaj różnych narzędzi** - każde ma swoje mocne strony
3. **Zapisuj wszystkie wyniki** do bazy danych
4. **Regularnie czyść bazę** z nieaktualnych wyników
5. **Testuj ręcznie** podejrzane przypadki
6. **Używaj niestandardowych payloadów** dla konkretnych aplikacji
7. **Monitoruj statystyki** aby śledzić postępy

## Rozwiązywanie Problemów

### Brak narzędzi
```bash
# Sprawdź czy wszystkie narzędzia są zainstalowane
python -m reconcli.xsscli check-deps

# Zainstaluj brakujące narzędzia zgodnie z instrukcjami
```

### Błędy bazy danych
```bash
# Usuń i zreinicjalizuj bazę
rm ~/.reconcli/xsscli.db
python -m reconcli.xsscli stats  # To zreinicjalizuje bazę
```

### Timeout-y
- Zwiększ timeout w kodzie dla wolnych aplikacji
- Używaj mniejszej liczby wątków
- Testuj pojedyncze URL-e przed masowym skanowaniem

## Bezpieczeństwo

⚠️ **UWAGA**: To narzędzie jest przeznaczone tylko do testów autoryzowanych!

- Nigdy nie testuj aplikacji bez zgody właściciela
- Używaj tylko w środowiskach testowych lub własnych aplikacjach
- Przestrzegaj lokalnych przepisów dotyczących testów bezpieczeństwa
- Dokumentuj wszystkie testy i ich wyniki
