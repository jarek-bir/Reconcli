# 🎯 Advanced MakeWordListCLI - Kompletny Przewodnik z Przykładami

## 📖 Spis Treści

1. [Wprowadzenie](#wprowadzenie)
2. [Nowe Zaawansowane Funkcje](#nowe-zaawansowane-funkcje)
3. [Szczegółowe Przykłady](#szczegółowe-przykłady)
4. [Scenariusze Rzeczywiste](#scenariusze-rzeczywiste)
5. [Zaawansowane Kombinacje](#zaawansowane-kombinacje)
6. [Tips & Tricks](#tips--tricks)
7. [Troubleshooting](#troubleshooting)

---

## 📋 Wprowadzenie

MakeWordListCLI to najbardziej zaawansowany generator wordlist w ekosystemie ReconCLI. W najnowszej wersji (2025) dodano cztery rewolucyjne funkcje, które przekształcają sposób generowania wordlist z prostego łączenia słów w inteligentny, AI-wspierany proces tworzenia specjalistycznych list słów.

### 🚀 Co Nowego?

**Przed (wersja klasyczna):**
```bash
# Proste łączenie słów
python main.py makewordlist --name admin --company acme --output-prefix basic
# Rezultat: ~50 podstawowych kombinacji
```

**Teraz (wersja 2025):**
```bash
# Inteligentne generowanie z AI
python main.py makewordlist --name admin --company acme \
  --word-boost admin \
  --markovify rockyou.txt \
  --combine-with subdomains.txt \
  --advanced \
  --output-prefix intelligent
# Rezultat: ~10,000+ wyspecjalizowanych słów
```

---

## 🎯 Nowe Zaawansowane Funkcje

### 1. 📁 Resume Functionality (`--resume-from`)

#### 🤔 Dlaczego potrzebne?

Podczas generowania bardzo dużych wordlist (np. z crunch dla 8-12 znaków) proces może trwać godzinami. Bez funkcji resume, każde przerwanie oznacza start od nowa.

#### 💡 Jak działa?

System automatycznie zapisuje stan generacji w plikach JSON. Każdy ważny krok (zakończenie źródła danych) tworzy checkpoint.

#### 📝 Struktura Resume File

```json
{
  "completed_sources": [
    {"name": "pydictor", "words_count": 1543, "timestamp": 1625748123},
    {"name": "markov_generation", "words_count": 2000, "timestamp": 1625748234}
  ],
  "current_step": 5,
  "total_steps": 8,
  "collected_words": ["admin", "password", "..."],
  "checkpoint_time": 1625748234.567,
  "parameters": {
    "min_length": 4,
    "max_length": 15,
    "profiles": ["admin"]
  }
}
```

#### 🔧 Praktyczne Przykłady

**Przykład 1: Generowanie Masywnej Wordlist**
```bash
# Krok 1: Start generacji (może być przerwane po 30 min)
python main.py makewordlist \
  --name admin \
  --full \
  --crunch-min 8 \
  --crunch-max 12 \
  --markovify /usr/share/wordlists/rockyou.txt \
  --markov-count 5000 \
  --word-boost admin \
  --output-prefix massive_wordlist \
  --verbose

# System automatycznie zapisuje: massive_wordlist_resume.json

# Krok 2: Po przerwaniu - kontynuacja
python main.py makewordlist \
  --resume-from massive_wordlist_resume.json \
  --output-prefix massive_wordlist \
  --verbose

# Rezultat: Kontynuacja dokładnie z miejsca przerwania
```

**Przykład 2: Rozłożenie Generacji na Etapy**
```bash
# Dzień 1: Podstawowe źródła
python main.py makewordlist \
  --company "Target Corp" \
  --domain target.com \
  --word-boost admin \
  --output-prefix target_day1

# Dzień 2: Dodanie Markov i kombinacji
python main.py makewordlist \
  --resume-from target_day1_resume.json \
  --markovify custom_passwords.txt \
  --combine-with subdomains.txt \
  --output-prefix target_final
```

---

### 2. 🚀 Word Boost Profiles (`--word-boost`)

#### 🎯 Koncepcja

Word Boost to inteligentny system wzmacniania określonych kategorii słów. Zamiast generować losowe kombinacje, system skupia się na konkretnych obszarach ataku.

#### 📚 Dostępne Profile

**🔐 Admin Profile (`--word-boost admin`)**
```
Bazowe słowa: administrator, root, manager, chief, owner, master, superuser
Wzorce: {word}admin, admin{word}, {word}_admin, admin_{word}, {word}-admin
Sufiksy: 123, !, 2024, 2025, _dev, _test, _prod
Przykłady: adminpanel, rootadmin, admin_corp, manager2024, chief!
```

**🔑 Auth Profile (`--word-boost auth`)**
```
Bazowe słowa: auth, login, signin, logon, access, credential, password, pass, pwd
Wzorce: {word}auth, auth{word}, {word}_login, login_{word}, {word}pass
Kombinacje z datami: login2024, auth2025, password!, pass123
Przykłady: authpanel, loginadmin, access_corp, credential2024
```

**🎛️ Panel Profile (`--word-boost panel`)**
```
Bazowe słowa: panel, dashboard, control, console, interface, ui, gui, menu
Wzorce: {word}panel, panel{word}, {word}_dash, dash_{word}
Kombinacje: adminpanel, panel_admin, dashboard123, control2024
Przykłady: managementpanel, panel_control, dash_admin, console!
```

**🧪 QA Profile (`--word-boost qa`)**
```
Bazowe słowa: qa, test, testing, debug, dev, development, staging, beta, alpha
Wzorce: {word}qa, qa{word}, {word}_test, test_{word}, {word}dev
Środowiska: dev, test, staging, beta, alpha, demo
Przykłady: qa_admin, test_panel, dev_api, staging_login, beta123
```

**🔌 API Profile (`--word-boost api`)**
```
Bazowe słowa: api, rest, graphql, endpoint, service, webservice, ws, json, xml
Wzorce: {word}api, api{word}, {word}_api, api_{word}, {word}/api
Wersje: v1, v2, v3, v1.0, v2.0
Przykłady: api_admin, rest_auth, api/v1, endpoint_panel, service2024
```

#### 🔍 Jak Działa Word Boost?

```python
# Przykładowy przepływ dla --word-boost admin
Bazowe słowa: ['target', 'corp']

Krok 1: Dodaj słowa z profilu admin
+ ['administrator', 'root', 'manager', 'chief', 'owner', 'master']

Krok 2: Zastosuj wzorce
target + admin patterns:
- targetadmin, admintarget
- target_admin, admin_target
- target-admin, admin-target

Krok 3: Multiplier effect (x3 dla admin)
Dla każdego ważnego słowa dodaj warianty:
- admin -> ADMIN, Admin, admin123, admin!, admin2024, admin2025

Wynik: 118+ nowych słów z profilu admin
```

#### 💼 Praktyczne Przykłady Word Boost

**Przykład 1: Corporate Admin Hunting**
```bash
python main.py makewordlist \
  --company "Acme Corporation" \
  --domain acme.com \
  --word-boost admin \
  --pattern subdomain \
  --output-prefix acme_admin \
  --verbose

# Wygeneruje m.in.:
# acme-admin.com, admin.acme.com, acmeadmin123
# administrator.acme.com, root-acme, manager.acme.com
# acme_admin2024, admincorp!, chief_acme
```

**Przykład 2: Authentication Bypass Wordlist**
```bash
python main.py makewordlist \
  --name api \
  --company secure \
  --word-boost auth \
  --pattern endpoint \
  --tech-stack security \
  --output-prefix auth_bypass

# Wygeneruje m.in.:
# /api/auth, /auth/secure, /login/api
# /secure_auth, /auth2024, /credential/api
# /access/secure, /signin_api, /pass/secure
```

**Przykład 3: QA Environment Discovery**
```bash
python main.py makewordlist \
  --domain production.com \
  --word-boost qa \
  --pattern subdomain \
  --dates \
  --output-prefix qa_discovery

# Wygeneruje m.in.:
# qa.production.com, test.production.com
# dev-production.com, staging.production.com
# beta2024.production.com, qa_production123
```

---

### 3. 🔗 Wordlist Combination (`--combine-with`)

#### 🎯 Filozofia

Zamiast tworzyć wordlisty od zera, wykorzystaj istniejące, sprawdzone listy i połącz je inteligentnie.

#### 🔧 Metody Kombinacji

**📚 Merge (--combine-method merge)**
```
Lista A: [admin, user, guest]
Lista B: [panel, login, auth]
Wynik: [admin, user, guest, panel, login, auth]

Przypadek użycia: Połączenie różnych źródeł w jedną kompletną listę
```

**🔍 Intersect (--combine-method intersect)**
```
Lista A: [admin, user, panel, guest]
Lista B: [admin, panel, login, auth]
Wynik: [admin, panel]

Przypadek użycia: Znajdowanie wspólnych elementów, weryfikacja overlap
```

**🎲 Combine (--combine-method combine)**
```
Lista A: [admin, user]
Lista B: [panel, api]
Wynik: [
  adminpanel, adminapi, useradmin, userpanel, userapi,
  admin_panel, admin_api, user_panel, user_api,
  admin-panel, admin-api, user-panel, user-api,
  panel_admin, api_admin, panel_user, api_user
]

Przypadek użycia: Kartezjański iloczyn, maksymalne kombinacje
```

**🔄 Permute (--combine-method permute)**
```
Lista A: [admin, user]
Lista B: [panel, api]
Wszystkie słowa: [admin, user, panel, api]
Wynik: [
  adminuser, adminpanel, adminapi,
  useradmin, userpanel, userapi,
  admin_user, admin_panel, admin_api,
  user_admin, user_panel, user_api,
  // + wszystkie permutacje 3-słowne
]

Przypadek użycia: Wszystkie możliwe kombinacje, discovery mode
```

#### 💡 Praktyczne Przykłady Combination

**Przykład 1: Subdomain Discovery Enhancement**
```bash
# Mamy podstawową listę subdomen
echo -e "admin\napi\ntest\ndev\nstaging" > base_subdomains.txt

# Mamy custom listę od klienta
echo -e "portal\ndashboard\nmanagement\ncontrol" > client_subdomains.txt

# Połączenie metodą merge
python main.py makewordlist \
  --domain target.com \
  --combine-with client_subdomains.txt \
  --combine-method merge \
  --pattern subdomain \
  --output-prefix subdomain_discovery

# Rezultat: Kompletna lista subdomen z obu źródeł
```

**Przykład 2: API Endpoint Brute Force**
```bash
# Bazowa lista endpointów
echo -e "users\nprofile\nsettings\nconfig" > api_endpoints.txt

# Lista akcji
echo -e "create\nread\nupdate\ndelete\nlist" > api_actions.txt

# Kombinacja kartezjańska
python main.py makewordlist \
  --name api \
  --combine-with api_actions.txt \
  --combine-method combine \
  --pattern endpoint \
  --output-prefix api_bruteforce

# Rezultat: /api/users_create, /api/profile_read, itp.
```

**Przykład 3: Password Spray z Rockyou**
```bash
# Kombinujemy target-specific słowa z top passwords
python main.py makewordlist \
  --company "Target Corp" \
  --name john \
  --surname smith \
  --birth 1985 \
  --combine-with /usr/share/wordlists/rockyou.txt \
  --combine-method intersect \
  --min-length 8 \
  --max-length 15 \
  --max-words 10000 \
  --output-prefix password_spray

# Rezultat: Tylko hasła z rockyou które zawierają elementy target
```

**Przykład 4: Technology Stack Combination**
```bash
# Lista technologii firmy
echo -e "django\npostgres\nredis\nnginx\ndocker" > tech_stack.txt

# Kombinacja z profilami
python main.py makewordlist \
  --domain techcorp.com \
  --word-boost admin \
  --combine-with tech_stack.txt \
  --combine-method combine \
  --tech-stack web \
  --output-prefix tech_discovery

# Rezultat: djangoadmin, admin_postgres, nginx-admin, itp.
```

---

### 4. 🎲 Markov Chain Generation (`--markovify`)

#### 🧠 Koncepcja AI

Markov Chain to model AI, który analizuje wzorce w istniejących danych i generuje nowe, podobne słowa. W kontekście wordlist - trenujemy model na sprawdzonych hasłach/słowach i generujemy nowe, realistyczne kandydatów.

#### 🔬 Jak Działa?

```
1. Analiza Training Data:
   Input: ["password123", "admin2024", "user123"]

2. Budowa N-gram Patterns:
   Chain Length 2: "pa" -> "s", "as" -> "s", "ss" -> "w", etc.

3. Generacja Nowych Słów:
   Start: "pa" -> wybierz najczęstszy następny znak -> "s"
   Kontynuj: "as" -> "s" -> "sw" -> "w" -> "wo" -> etc.

4. Output: "password", "admin124", "user124", etc.
```

#### ⚙️ Parametry Markov

**Chain Length (--markov-length)**
```
Length 1: Bardzo losowe, mało podobne do oryginału
Length 2: Wyważone, zalecane (default)
Length 3: Bardziej podobne do treningu
Length 4: Bardzo podobne, mniej kreatywne

Przykład z "password123":
Length 1: "pasword124" (losowe)
Length 2: "password124" (podobne)
Length 3: "password123" (bardzo podobne)
```

**Word Count (--markov-count)**
```
100-500: Szybko, podstawowe słowa
1000: Zrównoważone (default)
5000+: Pełna różnorodność, może zawierać duplikaty
```

#### 🗂️ Training Data Sources

**Rockyou.txt (Klasyczny)**
```bash
# 14 milionów prawdziwych haseł
python main.py makewordlist \
  --markovify /usr/share/wordlists/rockyou.txt \
  --markov-count 2000 \
  --min-length 8 \
  --max-length 15 \
  --output-prefix rockyou_markov

# Przykładowe wyjście:
# password124, admin2025, user1234, welcome123, etc.
```

**SecLists (Specjalistyczne)**
```bash
# Subdomains
python main.py makewordlist \
  --markovify /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
  --markov-count 1000 \
  --output-prefix subdomain_markov

# API Endpoints
python main.py makewordlist \
  --markovify /usr/share/seclists/Discovery/Web-Content/api/objects.txt \
  --markov-count 500 \
  --pattern endpoint \
  --output-prefix api_markov
```

**Custom Training Sets**
```bash
# Stwórz custom training z target research
echo -e "targetcorp\nacmesystems\ncorporatelogin\nbusinesspanel" > custom_training.txt

python main.py makewordlist \
  --markovify custom_training.txt \
  --markov-length 3 \
  --markov-count 1000 \
  --output-prefix custom_markov

# Przykładowe wyjście:
# targetlogin, acmepanel, corporatesystem, businesscorp
```

#### 🎯 Praktyczne Przykłady Markov

**Przykład 1: Corporate Password Patterns**
```bash
# Stwórz training set z corporate patterns
cat << EOF > corporate_patterns.txt
welcome2024
company123
business2024
corporate!
enterprise2024
organization123
management2024
administration!
EOF

python main.py makewordlist \
  --name target \
  --company "Target Systems" \
  --markovify corporate_patterns.txt \
  --markov-count 1500 \
  --markov-length 2 \
  --word-boost admin \
  --output-prefix corporate_passwords

# Rezultat: ~2000 słów brzmiących jak corporate passwords
```

**Przykład 2: Subdomain Generation z Real Data**
```bash
# Użyj prawdziwych subdomen jako training
python main.py makewordlist \
  --domain target.com \
  --markovify /opt/wordlists/subdomains_real.txt \
  --markov-count 3000 \
  --pattern subdomain \
  --min-length 3 \
  --max-length 12 \
  --output-prefix subdomain_ai

# Rezultat: AI-generated subdomains brzmiące realistycznie
```

**Przykład 3: API Endpoint Discovery**
```bash
# Training na prawdziwych API endpoints
cat << EOF > api_training.txt
/api/v1/users
/api/v2/profiles
/rest/admin/config
/graphql/users/query
/api/auth/login
/v1/admin/settings
/api/users/profile
/rest/config/system
EOF

python main.py makewordlist \
  --name api \
  --markovify api_training.txt \
  --markov-count 1000 \
  --pattern endpoint \
  --tech-stack api \
  --output-prefix api_discovery

# Rezultat: /api/v1/config, /rest/admin/users, etc.
```

---

## 🏗️ Zaawansowane Kombinacje

### 💎 Przykład 1: Complete Corporate Assessment

**Scenariusz:** Penetration test dużej korporacji "TechCorp Solutions"

**Intelligence Gathering:**
```bash
# Faza 1: Podstawowy research
Domain: techcorp.com
Employees: John Smith (CTO), Sarah Wilson (Admin)
Technologies: Django, PostgreSQL, Redis, AWS
Known subdomains: admin.techcorp.com, api.techcorp.com
```

**Generacja Wordlist:**
```bash
# Stwórz training set z research
cat << EOF > techcorp_training.txt
techcorp
solutions
django
postgresql
redis
aws
cloud
enterprise
business
corporate
johnsmith
sarahwilson
admin123
password2024
welcome123
EOF

# Stwórz tech stack
cat << EOF > techcorp_tech.txt
django
postgresql
redis
aws
nginx
docker
kubernetes
prometheus
grafana
jenkins
EOF

# Generacja kompletnej wordlist
python main.py makewordlist \
  --company "TechCorp Solutions" \
  --domain techcorp.com \
  --name john \
  --surname smith \
  --word-boost admin \
  --combine-with techcorp_tech.txt \
  --combine-method combine \
  --markovify techcorp_training.txt \
  --markov-count 2000 \
  --tech-stack web \
  --pattern subdomain \
  --advanced \
  --export-json \
  --export-md \
  --verbose \
  --max-words 5000 \
  --output-prefix techcorp_complete

# Rezultat: 5000 wysoce targeted słów
```

### 🎯 Przykład 2: API Security Testing

**Scenariusz:** Testing API endpoints dla fintech aplikacji

**Setup:**
```bash
# API endpoints z recon
cat << EOF > fintech_api_endpoints.txt
/api/v1/accounts
/api/v1/transactions
/api/v2/payments
/rest/users/profile
/graphql/query
/api/auth/login
/api/admin/config
/webhook/payments
EOF

# Financial terms training
cat << EOF > fintech_training.txt
account
transaction
payment
transfer
balance
credit
debit
wallet
banking
finance
money
currency
bitcoin
ethereum
trading
investment
loan
mortgage
insurance
EOF

# Complete API wordlist
python main.py makewordlist \
  --name api \
  --company fintech \
  --word-boost api \
  --combine-with fintech_api_endpoints.txt \
  --combine-method permute \
  --markovify fintech_training.txt \
  --markov-count 1500 \
  --pattern endpoint \
  --tech-stack api \
  --transform-rules "caps,lower" \
  --file-extensions "web,config" \
  --output-prefix fintech_api_complete

# Rezultat: Comprehensive API testing wordlist
```

### 🛡️ Przykład 3: Infrastructure Discovery

**Scenariusz:** Network infrastructure enumeration

```bash
# Infrastructure services
cat << EOF > infrastructure_services.txt
router
switch
firewall
proxy
gateway
dns
dhcp
ntp
snmp
monitoring
backup
storage
database
cache
queue
EOF

# Network naming patterns training
cat << EOF > network_training.txt
router01
switch-main
fw-external
proxy-internal
gateway-dmz
dns-primary
dhcp-server
monitoring-01
backup-storage
db-cluster-01
cache-redis-01
queue-rabbit-01
EOF

# Generate infrastructure wordlist
python main.py makewordlist \
  --company infrastructure \
  --word-boost admin \
  --combine-with infrastructure_services.txt \
  --combine-method combine \
  --markovify network_training.txt \
  --markov-count 1000 \
  --pattern subdomain \
  --keyboard-patterns \
  --dates \
  --mutations \
  --output-prefix infrastructure_discovery

# Rezultat: Network device discovery wordlist
```

---

## 💡 Tips & Tricks

### 🚀 Performance Optimization

**1. Resume dla Długich Procesów**
```bash
# Zamiast jednej długiej sesji
python main.py makewordlist --full --crunch-min 10 --crunch-max 15  # Może trwać godziny

# Użyj etapowego podejścia
python main.py makewordlist --basic-sources --output-prefix step1
python main.py makewordlist --resume-from step1_resume.json --markov-sources --output-prefix step2
python main.py makewordlist --resume-from step2_resume.json --crunch-min 8 --crunch-max 10 --output-prefix final
```

**2. Memory Management**
```bash
# Dla bardzo dużych training sets
python main.py makewordlist \
  --markovify huge_wordlist.txt \
  --markov-count 1000 \      # Ogranicz output
  --max-words 10000 \        # Ogranicz końcowy rozmiar
  --similarity-filter 0.9    # Usuń bardzo podobne słowa
```

### 🎯 Quality Improvement

**1. Smart Filtering Pipeline**
```bash
# Maksymalna jakość słów
python main.py makewordlist \
  --advanced \
  --min-length 6 \
  --max-length 15 \
  --similarity-filter 0.8 \
  --entropy-sort \
  --frequency-analysis \
  --output-prefix high_quality
```

**2. Target-Specific Enhancement**
```bash
# Każdy target jest inny - dostosuj podejście
python main.py makewordlist \
  --domain $TARGET_DOMAIN \
  --word-boost $(choose_best_profile) \
  --markovify $(find_relevant_training) \
  --pattern $(choose_attack_vector) \
  --output-prefix ${TARGET}_custom
```

### 🔧 Debugging & Validation

**1. Verbose Mode Analysis**
```bash
python main.py makewordlist \
  --verbose \
  --export-md \     # Szczegółowe statystyki
  [your options] \
  --output-prefix debug_run

# Analizuj debug_run.md dla optymalizacji
```

**2. Progressive Testing**
```bash
# Test z małymi danymi
python main.py makewordlist --markovify small_sample.txt --markov-count 50 --output-prefix test

# Jeśli OK, skaluj
python main.py makewordlist --markovify full_dataset.txt --markov-count 5000 --output-prefix production
```

---

## 🔧 Troubleshooting

### ❌ Problemy i Rozwiązania

**Problem: Markov nie generuje słów**
```bash
# Przyczyna: Za mały training set
# Rozwiązanie: Minimum 50+ unikalnych słów

# Sprawdź rozmiar
wc -l training.txt

# Jeśli za mało, połącz z większym
cat training.txt additional_words.txt > combined_training.txt
```

**Problem: Resume nie działa**
```bash
# Przyczyna: Brak uprawnień lub uszkodzony plik
# Rozwiązanie: Sprawdź plik resume

ls -la *_resume.json
cat wordlist_resume.json | jq .  # Validate JSON

# Jeśli uszkodzony, usuń i zacznij od nowa
rm *_resume.json
```

**Problem: Combine generuje za dużo słów**
```bash
# Przyczyna: Eksplozja kombinacyjna
# Rozwiązanie: Ogranicz input

# Zamiast:
python main.py makewordlist --combine-with huge_list.txt --combine-method combine

# Użyj:
head -100 huge_list.txt > limited_list.txt
python main.py makewordlist --combine-with limited_list.txt --combine-method combine --max-words 5000
```

**Problem: Word Boost nie dodaje słów**
```bash
# Przyczyna: Profil nie pasuje do base words
# Rozwiązanie: Sprawdź compatibility

# Sprawdź co masz:
python main.py makewordlist --name test --word-boost admin --verbose --output-prefix debug

# Jeśli za mało, dodaj więcej base words:
python main.py makewordlist --name admin --company corp --domain admin.com --word-boost admin
```

### 📊 Quality Validation

**Sprawdzenie Jakości Wordlist:**
```bash
# Użyj frequency analysis
python main.py makewordlist \
  [your options] \
  --frequency-analysis \
  --export-md \
  --output-prefix quality_check

# Sprawdź quality_check.md dla:
# - Length distribution (czy rozsądna?)
# - Character frequency (czy naturalna?)
# - Most common words (czy sensowne?)
```

**A/B Testing Wordlists:**
```bash
# Wersja A: Bez AI
python main.py makewordlist --basic-approach --output-prefix version_a

# Wersja B: Z AI
python main.py makewordlist --advanced --markovify training.txt --output-prefix version_b

# Compare rozmiary i quality
wc -l version_a.txt version_b.txt
```

---

## 🏆 Najlepsze Praktyki

### 1. 📋 Methodology

```bash
# 1. Research Phase
# - Zbierz informacje o target
# - Identyfikuj technologie
# - Znajdź naming patterns

# 2. Training Preparation
# - Stwórz custom training sets
# - Znajdź relevant external wordlists
# - Przygotuj combination lists

# 3. Generation Strategy
# - Zacznij od basic generation
# - Dodaj AI enhancement
# - Zastosuj smart filtering

# 4. Quality Assurance
# - Sprawdź output statistics
# - Validate przeciw known positives
# - Optimize dla false positive ratio
```

### 2. 🎯 Target Kategoryzacja

**Small Targets (< 1000 słów):**
```bash
python main.py makewordlist \
  --basic-inputs \
  --word-boost relevant_profile \
  --output-prefix small_target
```

**Medium Targets (1000-10000 słów):**
```bash
python main.py makewordlist \
  --extended-inputs \
  --word-boost profile \
  --markovify relevant_training.txt \
  --combine-with additional.txt \
  --output-prefix medium_target
```

**Large Targets (10000+ słów):**
```bash
python main.py makewordlist \
  --advanced \
  --multiple-sources \
  --resume-checkpoints \
  --output-prefix large_target
```

### 3. 🔄 Iterative Improvement

```bash
# Iteration 1: Basic
python main.py makewordlist --basic --output-prefix v1

# Test v1, then enhance
# Iteration 2: Add AI
python main.py makewordlist --basic --markovify training.txt --output-prefix v2

# Test v2, then specialize
# Iteration 3: Target-specific
python main.py makewordlist --v2-approach --word-boost specific_profile --output-prefix v3_final
```

---

## 📈 Podsumowanie

Nowe funkcje MakeWordListCLI przekształciły go z prostego generatora w zaawansowany, AI-wspierany system tworzenia wyspecjalizowanych wordlist. Każda z czterech funkcji rozwiązuje konkretny problem:

- **Resume**: Eliminuje frustrację związaną z przerywanymi długimi procesami
- **Word Boost**: Fokusuje generację na rzeczywiste attack vectors
- **Combination**: Wykorzystuje istniejącą wiedzę i wordlisty
- **Markov**: Dodaje AI intelligence dla realistycznych słów

Razem tworzą potężny toolkit, który może generować wordlisty dopasowane do każdego scenariusza - od prostych corporate targets po złożone infrastructure assessments.

**Kluczowe Takeaways:**
1. Zawsze zacznij od research i intelligence gathering
2. Użyj odpowiednich profili boost dla target type
3. Trenuj Markov na relevant data dla lepszych rezultatów
4. Łącz multiple sources dla comprehensive coverage
5. Zastosuj smart filtering dla high-quality output

Z tymi narzędziami i technikami, twoje wordlisty będą bardziej targeted, comprehensive i effective niż kiedykolwiek wcześniej.

---

**Status: 🚀 PRODUCTION READY - Advanced Wordlist Generation 2025**
