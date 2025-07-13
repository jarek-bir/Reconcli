# 🔍 DirBCLI - Przykłady użycia

## Podstawowe skanowanie

### 1. Proste skanowanie z ffuf
```bash
python3 main.py dirbcli --url https://example.com --wordlist test_wordlist.txt
```

### 2. Skanowanie z detekcją technologii
```bash
python3 main.py dirbcli --url https://example.com --wordlist test_wordlist.txt --tech-detect --verbose
```

### 3. Skanowanie z inteligentnymi wordlistami
```bash
python3 main.py dirbcli --url https://example.com --wordlist test_wordlist.txt --tech-detect --smart-wordlist --verbose
```

## Zaawansowane skanowanie

### 4. Rekurencyjne skanowanie z feroxbuster
```bash
python3 main.py dirbcli \
    --url https://example.com \
    --wordlist test_wordlist.txt \
    --tool feroxbuster \
    --recursive \
    --max-depth 2 \
    --verbose
```

### 5. Skanowanie z filtrowaniem statusów
```bash
python3 main.py dirbcli \
    --url https://example.com \
    --wordlist test_wordlist.txt \
    --filter-status 200,301,403 \
    --verbose
```

### 6. Skanowanie z rozszerzeniami plików
```bash
python3 main.py dirbcli \
    --url https://example.com \
    --wordlist test_wordlist.txt \
    --include-ext php,html,txt,js \
    --verbose
```

## Profesjonalne skanowanie

### 7. Pełne skanowanie z raportami
```bash
python3 main.py dirbcli \
    --url https://example.com \
    --wordlist test_wordlist.txt \
    --tool ffuf \
    --threads 25 \
    --rate-limit 5 \
    --include-ext php,html,txt,js,css \
    --tech-detect \
    --smart-wordlist \
    --filter-status 200,301,302,403 \
    --auto-calibrate \
    --json-report \
    --markdown-report \
    --verbose
```

### 8. Skanowanie przez proxy
```bash
python3 main.py dirbcli \
    --url https://example.com \
    --wordlist test_wordlist.txt \
    --proxy http://127.0.0.1:8080 \
    --verbose
```

### 9. Skanowanie z niestandardowymi nagłówkami
```bash
python3 main.py dirbcli \
    --url https://example.com \
    --wordlist test_wordlist.txt \
    --custom-headers "Authorization: Bearer token123,X-API-Key: secret456" \
    --verbose
```

## Skanowanie z notyfikacjami

### 10. Skanowanie z powiadomieniami Slack
```bash
python3 main.py dirbcli \
    --url https://example.com \
    --wordlist test_wordlist.txt \
    --json-report \
    --markdown-report \
    --slack-webhook https://hooks.slack.com/services/YOUR/WEBHOOK/URL \
    --verbose
```

### 11. Skanowanie z powiadomieniami Discord
```bash
python3 main.py dirbcli \
    --url https://example.com \
    --wordlist test_wordlist.txt \
    --json-report \
    --markdown-report \
    --discord-webhook https://discord.com/api/webhooks/YOUR/WEBHOOK/URL \
    --verbose
```

## Skanowanie z różnymi narzędziami

### 12. Gobuster
```bash
python3 main.py dirbcli \
    --url https://example.com \
    --wordlist test_wordlist.txt \
    --tool gobuster \
    --threads 50 \
    --include-ext php,html,txt \
    --verbose
```

### 13. Dirsearch
```bash
python3 main.py dirbcli \
    --url https://example.com \
    --wordlist test_wordlist.txt \
    --tool dirsearch \
    --delay 0.5 \
    --recursive \
    --verbose
```

## Optymalizacja wydajności

### 14. Szybkie skanowanie
```bash
python3 main.py dirbcli \
    --url https://example.com \
    --wordlist test_wordlist.txt \
    --threads 100 \
    --rate-limit 50 \
    --timeout 5 \
    --auto-calibrate \
    --verbose
```

### 15. Ostrożne skanowanie
```bash
python3 main.py dirbcli \
    --url https://example.com \
    --wordlist test_wordlist.txt \
    --threads 5 \
    --rate-limit 1 \
    --delay 1 \
    --timeout 30 \
    --verbose
```

## Filtrowanie zaawansowane

### 16. Filtrowanie według rozmiaru odpowiedzi
```bash
python3 main.py dirbcli \
    --url https://example.com \
    --wordlist test_wordlist.txt \
    --filter-size 100-50000 \
    --verbose
```

### 17. Wykluczanie określonych długości
```bash
python3 main.py dirbcli \
    --url https://example.com \
    --wordlist test_wordlist.txt \
    --exclude-length 1234,5678 \
    --verbose
```

### 18. Dopasowywanie wzorca regex
```bash
python3 main.py dirbcli \
    --url https://example.com \
    --wordlist test_wordlist.txt \
    --match-regex "admin|config|backup" \
    --verbose
```

## Obsługa wznowienia

### 19. Skanowanie z możliwością wznowienia
```bash
python3 main.py dirbcli \
    --url https://example.com \
    --wordlist test_wordlist.txt \
    --tool feroxbuster \
    --resume \
    --verbose
```

## Przykład pełnego skryptu

### 20. Skrypt automatyzujący
```bash
#!/bin/bash
# Skrypt skanowania katalogów dla wielu domen

DOMAINS_FILE="domains.txt"
WORDLIST="/usr/share/wordlists/dirb/common.txt"
OUTPUT_BASE="results"

while IFS= read -r domain; do
    echo "Skanowanie domeny: $domain"

    python3 main.py dirbcli \
        --url "https://$domain" \
        --wordlist "$WORDLIST" \
        --output-dir "$OUTPUT_BASE/$domain" \
        --tech-detect \
        --smart-wordlist \
        --tool ffuf \
        --threads 25 \
        --rate-limit 10 \
        --include-ext php,html,txt,js,css,json \
        --filter-status 200,301,302,403 \
        --auto-calibrate \
        --json-report \
        --markdown-report \
        --verbose

    echo "Skanowanie zakończone dla: $domain"
    echo "---"
done < "$DOMAINS_FILE"
```

## Analiza wyników

### Struktura katalogu wyników
```
output/dirbcli/
├── ffuf.json              # Surowe wyniki z ffuf
├── dirbcli_report.json    # Szczegółowy raport JSON
└── dirbcli_report.md      # Raport Markdown
```

### Przykład analizy JSON
```bash
# Liczba znalezionych katalogów
jq '.findings.total' output/dirbcli/dirbcli_report.json

# Katalogi wysokiego ryzyka
jq '.findings.by_category.admin_panels' output/dirbcli/dirbcli_report.json

# Wykryte technologie
jq '.target_info.technology_stack[]' output/dirbcli/dirbcli_report.json
```

## Wskazówki bezpieczeństwa

1. **Autoryzacja**: Zawsze uzyskaj zezwolenie przed skanowaniem
2. **Ograniczenia**: Używaj odpowiednich limitów prędkości
3. **Monitoring**: Monitoruj logi serwera podczas skanowania
4. **Poufność**: Chroń wyniki skanowania przed nieautoryzowanym dostępem

## Rozwiązywanie problemów

### Błędy połączenia
```bash
# Sprawdź dostępność celu
curl -I https://example.com

# Skanuj z większym timeout
python3 main.py dirbcli --url https://example.com --wordlist test_wordlist.txt --timeout 30
```

### Problemy z narzędziami
```bash
# Sprawdź czy ffuf jest zainstalowany
which ffuf

# Sprawdź czy feroxbuster jest zainstalowany
which feroxbuster
```

### Debugowanie
```bash
# Włącz verbose dla szczegółowych informacji
python3 main.py dirbcli --url https://example.com --wordlist test_wordlist.txt --verbose

# Sprawdź surowe wyniki
cat output/dirbcli/ffuf.json
```

## User-Agent Management

### 21. Używanie wbudowanych User-Agentów
```bash
# Użyj wszystkich wbudowanych User-Agentów (25+)
python3 main.py dirbcli \
    --url https://example.com \
    --wordlist test_wordlist.txt \
    --builtin-ua \
    --verbose
```

### 22. Losowy User-Agent z wbudowanych
```bash
# Użyj losowego User-Agenta z kolekcji wbudowanej
python3 main.py dirbcli \
    --url https://example.com \
    --wordlist test_wordlist.txt \
    --builtin-ua \
    --random-ua \
    --verbose
```

### 23. User-Agenty z pliku
```bash
# Użyj User-Agentów z pliku
python3 main.py dirbcli \
    --url https://example.com \
    --wordlist test_wordlist.txt \
    --user-agent-file user_agents.txt \
    --verbose
```

### 24. Losowy User-Agent z pliku
```bash
# Użyj losowego User-Agenta z pliku
python3 main.py dirbcli \
    --url https://example.com \
    --wordlist test_wordlist.txt \
    --user-agent-file user_agents.txt \
    --random-ua \
    --verbose
```

### 25. Niestandardowy User-Agent
```bash
# Użyj niestandardowego User-Agenta
python3 main.py dirbcli \
    --url https://example.com \
    --wordlist test_wordlist.txt \
    --user-agent "MyCustomBot/1.0 (Security Scanner)" \
    --verbose
```

### 26. Wiele niestandardowych User-Agentów
```bash
# Użyj wielu niestandardowych User-Agentów
python3 main.py dirbcli \
    --url https://example.com \
    --wordlist test_wordlist.txt \
    --user-agent "Mozilla/5.0 (Windows NT 10.0)" \
    --user-agent "Mozilla/5.0 (Macintosh; Intel)" \
    --user-agent "Mozilla/5.0 (X11; Linux)" \
    --verbose
```
