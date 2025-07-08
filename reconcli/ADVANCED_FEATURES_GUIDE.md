# 🚀 Advanced MakeWordListCLI Features Guide

## New Advanced Features

### 1. 📁 Resume Functionality (`--resume-from`)

Pozwala na wznowienie generowania dużych wordlist z punktu kontrolnego. Przydatne przy długotrwałych procesach.

```bash
# Pierwsze uruchomienie (może być przerwane)
python main.py makewordlist --name admin --full --crunch-min 8 --crunch-max 12 --output-prefix big_list

# Wznowienie z punktu kontrolnego
python main.py makewordlist --resume-from big_list_resume.json --output-prefix big_list
```

**Kiedy używać:**
- Generowanie bardzo dużych wordlist (>100k słów)
- Długotrwałe procesy (crunch, deep crawling)
- Gdy proces może być przerwany

### 2. 🚀 Word Boost Profiles (`--word-boost`)

Wzmacnia określone kategorie słów, dodając specjalistyczne wzorce i warianty.

```bash
# Profile dostępne: admin, auth, panel, qa, api

# Wzmocnienie słów administracyjnych
python main.py makewordlist --name app --word-boost admin --output-prefix admin_focused

# Wzmocnienie słów uwierzytelnienia
python main.py makewordlist --company acme --word-boost auth --output-prefix auth_words

# Wzmocnienie słów paneli kontrolnych
python main.py makewordlist --domain example.com --word-boost panel --output-prefix panel_hunt
```

**Profile boost:**
- **admin**: administrator, root, manager, chief + wzorce
- **auth**: login, password, credential, access + wzorce  
- **panel**: dashboard, control, console, interface + wzorce
- **qa**: test, debug, dev, staging, beta + wzorce
- **api**: rest, endpoint, service, webservice + wzorce

### 3. 🔗 Wordlist Combination (`--combine-with`)

Łączy dwie wordlisty używając różnych metod kombinacji.

```bash
# Metody: merge, intersect, combine, permute

# Proste połączenie (suma)
python main.py makewordlist --name admin --combine-with rockyou.txt --combine-method merge --output-prefix merged

# Część wspólna
python main.py makewordlist --name admin --combine-with custom.txt --combine-method intersect --output-prefix common

# Kombinacje kartezjańskie (jak pydictor -C)
python main.py makewordlist --name api --combine-with endpoints.txt --combine-method combine --output-prefix combined

# Permutacje słów
python main.py makewordlist --domain target.com --combine-with subdomains.txt --combine-method permute --output-prefix permuted
```

**Metody kombinacji:**
- **merge**: Prosta suma list (A ∪ B)
- **intersect**: Część wspólna (A ∩ B)  
- **combine**: Kombinacje kartezjańskie (A×B: admin+api, api+admin, admin_api, etc.)
- **permute**: Permutacje słów z obu list

### 4. 🎲 Markov Chain Generation (`--markovify`)

Generuje słowa używając modelu Markova trenowanego na istniejącej wordliście.

```bash
# Trenowanie na rockyou.txt i generowanie 1000 słów
python main.py makewordlist --markovify rockyou.txt --markov-count 1000 --output-prefix markov_words

# Różne długości łańcucha (1-4)
python main.py makewordlist --markovify passwords.txt --markov-length 3 --markov-count 500 --output-prefix markov_l3

# Kombinacja z innymi technikami
python main.py makewordlist --name admin --markovify common_passwords.txt --word-boost admin --output-prefix hybrid_markov
```

**Parametry Markov:**
- **markov-count**: Liczba słów do wygenerowania (default: 1000)
- **markov-length**: Długość łańcucha (1-4, default: 2)
  - 1: Bardzo losowe
  - 2: Wyważone (zalecane)  
  - 3: Bardziej zgodne z oryginałem
  - 4: Bardzo podobne do treningu

## 🔥 Kombinowanie Funkcji

### Przykład 1: Kompletny Recon Target
```bash
python main.py makewordlist \
  --domain target.com \
  --company "Target Corp" \
  --word-boost admin \
  --combine-with custom_subdomains.txt \
  --combine-method combine \
  --markovify rockyou.txt \
  --markov-count 2000 \
  --advanced \
  --output-prefix target_complete
```

### Przykład 2: API Hunting Wordlist
```bash
python main.py makewordlist \
  --name api \
  --tech-stack api \
  --word-boost api \
  --pattern endpoint \
  --markovify api_endpoints.txt \
  --output-prefix api_hunting
```

### Przykład 3: Panel Discovery
```bash
python main.py makewordlist \
  --profile corp \
  --word-boost panel \
  --combine-with admin_panels.txt \
  --combine-method merge \
  --pattern directory \
  --output-prefix panel_discovery
```

## 📊 Zalecenia

### Dla małych celów (< 10k słów):
```bash
--word-boost [profile] --combine-method merge
```

### Dla średnich celów (10k-100k słów):
```bash
--word-boost [profile] --markovify training.txt --combine-method combine
```

### Dla dużych celów (> 100k słów):
```bash
--advanced --markovify large_dataset.txt --resume-from checkpoint
```

## 🔧 Tips & Tricks

1. **Resume state**: Automatycznie zapisywany co większy krok generacji
2. **Word boost**: Można łączyć z innymi technikami dla lepszych rezultatów
3. **Markov training**: Większy dataset = lepsze słowa (min. 1000 słów treningowych)
4. **Combination limits**: Automatyczne limity zapobiegają eksplozji kombinacji
5. **Memory management**: Duże listy są automatycznie limitowane

## 🚨 Uwagi Bezpieczeństwa

- Resume pliki zawierają zebrane słowa - usuń po użyciu
- Markov może generować słowa podobne do treningu - sprawdź wrażliwość
- Kombinacje mogą tworzyć bardzo duże pliki - ustaw `--max-words`
- Training files są ładowane do pamięci - sprawdź rozmiar pliku

## 📈 Wydajność

- **Resume**: Oszczędza czas przy przerwanych sesjach
- **Word boost**: +20-50% słów specjalistycznych  
- **Markov**: Generuje unikalne słowa podobne do treningu
- **Combine**: Eksponencjalny wzrost - ustaw limity
