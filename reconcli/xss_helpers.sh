#!/bin/bash

# XSSCLI Helper Scripts
# Pomocnicze skrypty dla modułu XSSCLI

# Kolory dla output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Funkcja logowania
log() {
    echo -e "${BLUE}[$(date '+%Y-%m-%d %H:%M:%S')]${NC} $1"
}

success() {
    echo -e "${GREEN}[+]${NC} $1"
}

warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

error() {
    echo -e "${RED}[-]${NC} $1"
}

# Sprawdź czy wszystkie narzędzia są zainstalowane
check_tools() {
    log "Sprawdzanie narzędzi XSS..."
    
    tools=("dalfox" "nuclei" "katana" "hakrawler" "gau" "waybackurls" "httpx" "gf")
    missing_tools=()
    
    for tool in "${tools[@]}"; do
        if command -v "$tool" &> /dev/null; then
            success "$tool zainstalowany"
        else
            error "$tool nie znaleziony"
            missing_tools+=("$tool")
        fi
    done
    
    if [ ${#missing_tools[@]} -eq 0 ]; then
        success "Wszystkie narzędzia są dostępne!"
        return 0
    else
        warning "Brakujące narzędzia: ${missing_tools[*]}"
        return 1
    fi
}

# Instaluj brakujące narzędzia Go
install_go_tools() {
    log "Instalowanie narzędzi Go..."
    
    go install -v github.com/hahwul/dalfox/v2@latest
    go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest  
    go install -v github.com/projectdiscovery/katana/cmd/katana@latest
    go install -v github.com/hakluke/hakrawler@latest
    go install -v github.com/lc/gau/v2/cmd/gau@latest
    go install -v github.com/tomnomnom/waybackurls@latest
    go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
    go install -v github.com/tomnomnom/gf@latest
    
    success "Narzędzia Go zainstalowane!"
}

# Pełne skanowanie domeny
full_domain_scan() {
    local domain="$1"
    local output_dir="$2"
    
    if [ -z "$domain" ] || [ -z "$output_dir" ]; then
        error "Użycie: full_domain_scan <domain> <output_directory>"
        return 1
    fi
    
    log "Rozpoczynanie pełnego skanowania XSS dla domeny: $domain"
    mkdir -p "$output_dir"
    
    # 1. Zbieranie URL-i
    log "Krok 1: Zbieranie URL-i..."
    python -m reconcli.xsscli gather-urls \
        --domain "$domain" \
        --output "$output_dir/${domain}_all_urls.txt" \
        --sources wayback,gau,hakrawler
    
    # 2. Filtrowanie potencjalnych XSS URL-i
    log "Krok 2: Filtrowanie URL-i z parametrami..."
    if [ -f "$output_dir/${domain}_all_urls.txt" ]; then
        cat "$output_dir/${domain}_all_urls.txt" | gf xss > "$output_dir/${domain}_xss_candidates.txt" 2>/dev/null || true
        success "Znaleziono $(wc -l < "$output_dir/${domain}_xss_candidates.txt") potencjalnych URL-i XSS"
    fi
    
    # 3. Skanowanie z kxss (szybkie)
    log "Krok 3: Szybkie skanowanie z kxss..."
    if [ -f "$output_dir/${domain}_xss_candidates.txt" ]; then
        python -m reconcli.xsscli kxss \
            --input "$output_dir/${domain}_xss_candidates.txt" \
            --output "$output_dir/${domain}_kxss_results.txt"
    fi
    
    # 4. Skanowanie z Dalfox (dokładne)
    log "Krok 4: Dokładne skanowanie z Dalfox..."
    if [ -f "$output_dir/${domain}_xss_candidates.txt" ]; then
        head -50 "$output_dir/${domain}_xss_candidates.txt" | while read -r url; do
            if [ -n "$url" ]; then
                python -m reconcli.xsscli dalfox \
                    --target "$url" \
                    --threads 20 \
                    --output "$output_dir/${domain}_dalfox_results.txt"
            fi
        done
    fi
    
    # 5. Skanowanie z Nuclei
    log "Krok 5: Skanowanie z templates Nuclei..."
    if [ -f "$output_dir/${domain}_xss_candidates.txt" ]; then
        python -m reconcli.xsscli nuclei-xss \
            --input "$output_dir/${domain}_xss_candidates.txt" \
            --output "$output_dir/${domain}_nuclei_results.txt"
    fi
    
    # 6. Generowanie raportu
    log "Krok 6: Generowanie raportów..."
    python -m reconcli.xsscli export \
        --format json \
        --output "$output_dir/${domain}_final_report.json"
    
    python -m reconcli.xsscli stats --vulnerable-only > "$output_dir/${domain}_stats.txt"
    
    success "Skanowanie zakończone! Wyniki w: $output_dir"
    warning "Sprawdź plik ${domain}_final_report.json dla szczegółowych wyników"
}

# Szybkie testowanie pojedynczego URL
quick_test() {
    local url="$1"
    
    if [ -z "$url" ]; then
        error "Użycie: quick_test <url>"
        return 1
    fi
    
    log "Szybkie testowanie: $url"
    
    # Test z podstawowymi payloadami
    python -m reconcli.xsscli manual-test --target "$url"
    
    # Test z kxss
    echo "$url" | python -m reconcli.xsscli kxss --input /dev/stdin
    
    # Pokaż wyniki
    python -m reconcli.xsscli results --limit 5
}

# Monitoring podatności w czasie rzeczywistym
monitor_domain() {
    local domain="$1"
    local interval="${2:-3600}" # domyślnie co godzinę
    
    if [ -z "$domain" ]; then
        error "Użycie: monitor_domain <domain> [interval_seconds]"
        return 1
    fi
    
    log "Rozpoczynanie monitoringu domeny: $domain (co $interval sekund)"
    
    while true; do
        timestamp=$(date '+%Y%m%d_%H%M%S')
        output_dir="monitoring_${domain}_${timestamp}"
        
        log "Skanowanie w czasie: $(date)"
        full_domain_scan "$domain" "$output_dir"
        
        # Sprawdź czy znaleziono nowe podatności
        vuln_count=$(python -m reconcli.xsscli stats --vulnerable-only | grep "Vulnerable:" | cut -d':' -f2 | tr -d ' ')
        
        if [ "$vuln_count" -gt 0 ]; then
            warning "Znaleziono $vuln_count podatności! Sprawdź wyniki."
            # Tutaj można dodać powiadomienia (email, slack, etc.)
        fi
        
        log "Następne skanowanie za $interval sekund..."
        sleep "$interval"
    done
}

# Instalacja pełnego środowiska
setup_environment() {
    log "Konfigurowanie środowiska XSSCLI..."
    
    # Sprawdź Go
    if ! command -v go &> /dev/null; then
        error "Go nie jest zainstalowany. Zainstaluj Go i spróbuj ponownie."
        return 1
    fi
    
    # Sprawdź Python
    if ! command -v python3 &> /dev/null; then
        error "Python3 nie jest zainstalowany."
        return 1
    fi
    
    # Instaluj narzędzia Go
    install_go_tools
    
    # Konfiguruj gf patterns
    log "Konfigurowanie gf patterns..."
    if command -v gf &> /dev/null; then
        gf -save xss -HanrE 'xss|eval|alert|confirm|prompt|javascript:|onerror|onload|onclick'
        success "Wzorce gf skonfigurowane"
    fi
    
    # Pobierz nuclei templates
    if command -v nuclei &> /dev/null; then
        log "Aktualizowanie templates Nuclei..."
        nuclei -update-templates
        success "Templates Nuclei zaktualizowane"
    fi
    
    # Test instalacji
    check_tools
    
    success "Środowisko XSSCLI skonfigurowane!"
}

# Backup i restore bazy danych
backup_database() {
    local backup_dir="${1:-./xss_backups}"
    
    mkdir -p "$backup_dir"
    timestamp=$(date '+%Y%m%d_%H%M%S')
    backup_file="$backup_dir/xsscli_backup_${timestamp}.db"
    
    if [ -f "$HOME/.reconcli/xsscli.db" ]; then
        cp "$HOME/.reconcli/xsscli.db" "$backup_file"
        success "Backup zapisany: $backup_file"
    else
        warning "Baza danych nie istnieje"
    fi
}

restore_database() {
    local backup_file="$1"
    
    if [ -z "$backup_file" ]; then
        error "Użycie: restore_database <backup_file>"
        return 1
    fi
    
    if [ ! -f "$backup_file" ]; then
        error "Plik backup nie istnieje: $backup_file"
        return 1
    fi
    
    cp "$backup_file" "$HOME/.reconcli/xsscli.db"
    success "Baza danych przywrócona z: $backup_file"
}

# Czyszczenie środowiska
cleanup_environment() {
    log "Czyszczenie środowiska XSSCLI..."
    
    # Czyść bazę danych
    python -m reconcli.xsscli cleanup
    
    # Usuń tymczasowe pliki
    find . -name "*_urls.txt" -mtime +7 -delete 2>/dev/null || true
    find . -name "*_results.txt" -mtime +7 -delete 2>/dev/null || true
    
    success "Środowisko wyczyszczone"
}

# Menu główne
show_menu() {
    echo
    echo "=== XSSCLI Helper Scripts ==="
    echo "1. Sprawdź narzędzia"
    echo "2. Zainstaluj środowisko"
    echo "3. Pełne skanowanie domeny"
    echo "4. Szybki test URL"
    echo "5. Monitoring domeny"
    echo "6. Backup bazy danych"
    echo "7. Przywróć bazę danych"
    echo "8. Wyczyść środowisko"
    echo "9. Wyjście"
    echo
}

# Main script
main() {
    case "$1" in
        "check")
            check_tools
            ;;
        "setup")
            setup_environment
            ;;
        "scan")
            full_domain_scan "$2" "$3"
            ;;
        "test")
            quick_test "$2"
            ;;
        "monitor")
            monitor_domain "$2" "$3"
            ;;
        "backup")
            backup_database "$2"
            ;;
        "restore")
            restore_database "$2"
            ;;
        "cleanup")
            cleanup_environment
            ;;
        "menu"|"")
            while true; do
                show_menu
                read -p "Wybierz opcję (1-9): " choice
                case $choice in
                    1) check_tools ;;
                    2) setup_environment ;;
                    3) 
                        read -p "Podaj domenę: " domain
                        read -p "Podaj katalog wyników: " output_dir
                        full_domain_scan "$domain" "$output_dir"
                        ;;
                    4)
                        read -p "Podaj URL: " url
                        quick_test "$url"
                        ;;
                    5)
                        read -p "Podaj domenę: " domain
                        read -p "Interwał w sekundach (domyślnie 3600): " interval
                        monitor_domain "$domain" "${interval:-3600}"
                        ;;
                    6)
                        read -p "Katalog backup (domyślnie ./xss_backups): " backup_dir
                        backup_database "${backup_dir:-./xss_backups}"
                        ;;
                    7)
                        read -p "Ścieżka do pliku backup: " backup_file
                        restore_database "$backup_file"
                        ;;
                    8) cleanup_environment ;;
                    9) log "Do widzenia!"; exit 0 ;;
                    *) warning "Nieprawidłowa opcja!" ;;
                esac
                echo
                read -p "Naciśnij Enter aby kontynuować..."
            done
            ;;
        *)
            echo "Użycie: $0 {check|setup|scan|test|monitor|backup|restore|cleanup|menu}"
            echo
            echo "Opcje:"
            echo "  check                          - Sprawdź zainstalowane narzędzia"
            echo "  setup                          - Zainstaluj środowisko"
            echo "  scan <domain> <output_dir>     - Pełne skanowanie domeny"
            echo "  test <url>                     - Szybki test URL"
            echo "  monitor <domain> [interval]    - Monitoring domeny"
            echo "  backup [backup_dir]            - Backup bazy danych"
            echo "  restore <backup_file>          - Przywróć bazę danych"
            echo "  cleanup                        - Wyczyść środowisko"
            echo "  menu                          - Interaktywne menu"
            ;;
    esac
}

# Uruchom skrypt
main "$@"
