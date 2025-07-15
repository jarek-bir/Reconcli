# 🎯 VulnCLI - Zaawansowane skanowanie podatności z selektywnym wyborem sygnatur Jaeles

## 🔧 Opcje Jaeles

VulnCLI teraz obsługuje zaawansowany wybór sygnatur Jaeles:

### Podstawowe opcje:
- `--jaeles-signatures /path/to/custom/signatures/` - Użyj niestandardowych sygnatur
- `--jaeles-select 'pattern'` - Wybierz sygnatury według wzorca regex
- `--jaeles-exclude 'pattern'` - Wyklucz sygnatury według wzorca regex
- `--jaeles-level N` - Filtruj sygnatury według poziomu (1-5)

### Przykłady użycia:

#### 1. Tylko sygnatury wrażliwe (sensitive):
```bash
reconcli vulncli -i urls.txt -o results --run-jaeles --jaeles-select 'sensitive/.*'
```

#### 2. Tylko sygnatury SQL injection fuzzing:
```bash
reconcli vulncli -i urls.txt -o results --run-jaeles --jaeles-select 'fuzz/sqli/.*'
```

#### 3. Tylko wspólne podatności:
```bash
reconcli vulncli -i urls.txt -o results --run-jaeles --jaeles-select 'common/.*'
```

#### 4. Fuzzing i sensitive, ale bez eksperymentalnych:
```bash
reconcli vulncli -i urls.txt -o results --run-jaeles \
  --jaeles-select 'fuzz/.*|sensitive/.*' \
  --jaeles-exclude 'experimental/.*'
```

#### 5. Tylko wysokiej jakości sygnatury (level 2+):
```bash
reconcli vulncli -i urls.txt -o results --run-jaeles \
  --jaeles-select 'common/.*' \
  --jaeles-level 2
```

#### 6. Użyj niestandardowego katalogu sygnatur:
```bash
reconcli vulncli -i urls.txt -o results --run-jaeles \
  --jaeles-signatures ~/my-custom-signatures/
```

### Dostępne kategorie sygnatur (~/Documents/pro-signatures/):

- **common/** - Podstawowe podatności i misconfigurations
- **sensitive/** - Wrażliwe pliki i informacje
- **fuzz/** - Fuzzing (sqli, xss, crlf, etc.)
- **cves/** - Konkretne CVE
- **passives/** - Pasywne skanowanie
- **discovery/** - Discovery i reconnaissance
- **probe/** - Probes i testy

### Automatyczne wykrywanie:

Jeśli nie określisz sygnatur, VulnCLI:
1. Sprawdzi czy istnieje `~/Documents/pro-signatures/`
2. Jeśli tak, użyje `sensitive/.*` (bezpieczne, produktywne)
3. Jeśli nie, przełączy się na tryb `--passive`

### Przykład pełnego skanowania:
```bash
reconcli vulncli -i urls.txt -o full_scan \
  --run-dalfox --run-jaeles --run-nuclei \
  --jaeles-select 'common/.*|sensitive/.*' \
  --jaeles-exclude 'experimental/.*' \
  --jaeles-level 2 \
  --nuclei-tags tech,info,exposure \
  --verbose --json --markdown
```
