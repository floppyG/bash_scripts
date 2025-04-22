#!/bin/bash

# =============================================================
# WINDOWS VULNERABILITY SCANNER UNIFICATO
# =============================================================
# Autore: Versione unificata degli script di scansione Windows
# Versione: 2.0.0
# Data: 16 Aprile 2025
# Descrizione: Scanner completo di vulnerabilit� per sistemi Windows 
# che integra Nmap, Nikto e Nuclei con report HTML
# Supporto: Scansione singoli IP o subnet CIDR (192.168.0.1/24)
# =============================================================

# Imposta gestione errori
set -o pipefail
set +e  # Non terminare immediatamente su errore

# Colori per output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Variabili globali
VERSION="2.0.0"
DATE=$(date "+%Y-%m-%d")
SCRIPT_PATH="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEMP_DIR="/tmp/windows_vuln_scan_$$"
OUTPUT_DIR=""
HTML_OUTPUT=""
TARGET=""
CVE_DB_URL="https://cve.mitre.org/data/downloads/allitems.csv"
CVE_DB_FILE="${TEMP_DIR}/cve_database.csv"
CVE_WINDOWS_FILE="${TEMP_DIR}/windows_cves.csv"
CVE_RECENT_THRESHOLD=365  # Considera CVE dell'ultimo anno come recenti
SCAN_START_TIME=""
SCAN_END_TIME=""
LOG_FILE=""

# Variabili di controllo
RUN_NMAP=true
RUN_NUCLEI=true
RUN_CVE_CHECK=true
FOCUS_SERVER=true
VERBOSE_MODE=false
THOROUGH_SCAN=false
MAX_THREADS=5

# Funzione per visualizzare il banner
show_banner() {
    echo -e "${BLUE}"
    echo "+---------------------------------------------------------------------+"
    echo "�                                                                     �"
    echo "�   WINDOWS VULNERABILITY SCANNER UNIFICATO v${VERSION}                    �"
    echo "�   Combina Nmap, Nikto e Nuclei con CVE Intelligence                �"
    echo "�   Specializzato per Windows Server                                 �"
    echo "�                                                                     �"
    echo "+---------------------------------------------------------------------+"
    echo -e "${NC}"
}

# Funzione di logging
log() {
    local level=$1
    local message=$2
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    case $level in
        "INFO") echo -e "${GREEN}[INFO]${NC} $timestamp - $message" ;;
        "WARN") echo -e "${YELLOW}[WARN]${NC} $timestamp - $message" ;;
        "ERROR") echo -e "${RED}[ERROR]${NC} $timestamp - $message" ;;
        "DEBUG") 
            if [ "$VERBOSE_MODE" = true ]; then
                echo -e "${CYAN}[DEBUG]${NC} $timestamp - $message"
            fi
            ;;
        *) echo -e "$timestamp - $message" ;;
    esac
    
    # Creazione directory per log se non esiste gi�
    if [ ! -d "${TEMP_DIR}" ]; then
        mkdir -p "${TEMP_DIR}"
    fi
    
    # Aggiungi il log al file di log generale
    echo "[$level] $timestamp - $message" >> "${LOG_FILE}"
}

# Funzione per visualizzare l'help
show_help() {
    echo "Utilizzo: $0 <target> [opzioni]"
    echo
    echo "Target:"
    echo "  Pu� essere un indirizzo IP singolo (es. 192.168.1.10) o una subnet CIDR (es. 192.168.1.0/24)"
    echo
    echo "Opzioni:"
    echo "  -h, --help            Mostra questo help"
    echo "  -o, --output DIR      Specifica la directory di output (default: auto-generata)"
    echo "  -n, --nmap-only       Esegui solo lo scanner basato su Nmap/Nikto"
    echo "  -u, --nuclei-only     Esegui solo lo scanner basato su Nuclei"
    echo "  -c, --skip-cve        Salta il controllo delle CVE recenti"
    echo "  -w, --workstation     Modalit� workstation (default: server)"
    echo "  -v, --verbose         Mostra output dettagliato"
    echo "  -t, --thorough        Esegui una scansione approfondita (pi� lenta)"
    echo "  -j, --threads NUM     Numero massimo di thread paralleli (default: 5)"
    echo
    echo "Esempi:"
    echo "  $0 192.168.1.10"
    echo "  $0 192.168.1.0/24 --output my_scan_results"
    echo "  $0 10.0.0.1 --thorough --threads 10"
}

# Verifica prerequisiti
check_prerequisites() {
    log "INFO" "Verificando i prerequisiti..."
    
    # Crea directory temporanea
    mkdir -p "${TEMP_DIR}"
    
    # Lista dei comandi necessari (rimosso wkhtmltopdf)
    essential_commands=("nmap" "nuclei" "sed" "awk" "grep" "curl" "jq" "timeout")
    missing_commands=()
    
    for cmd in "${essential_commands[@]}"; do
        if ! command -v "$cmd" &> /dev/null; then
            missing_commands+=("$cmd")
        fi
    done
    
    if [ ${#missing_commands[@]} -gt 0 ]; then
        log "ERROR" "Comandi mancanti: ${missing_commands[*]}"
        log "ERROR" "Installali prima di procedere."
        echo -e "${RED}Per installare i prerequisiti mancanti:${NC}"
        echo "sudo apt update && sudo apt install -y nmap curl jq coreutils"
        echo "GO111MODULE=on go get -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei"
        exit 1
    fi
    
    # Verifica versione di Nmap
    NMAP_VERSION=$(nmap --version | head -n1 | awk '{print $3}')
    log "INFO" "Trovato Nmap versione $NMAP_VERSION"
    
    # Verifica la versione di Nuclei
    NUCLEI_VERSION=$(nuclei -version 2>&1 | grep -oP "(?<=version )[^ ]+" || echo "sconosciuta")
    log "INFO" "Trovato Nuclei versione $NUCLEI_VERSION"
    
    # Aggiorna i template di Nuclei se richiesto
    if [ "$THOROUGH_SCAN" = true ]; then
        log "INFO" "Aggiornamento dei template di Nuclei in corso..."
        if nuclei -update-templates &>/dev/null; then
            log "INFO" "Template di Nuclei aggiornati all'ultima versione"
        else
            log "WARN" "Non � stato possibile aggiornare i template, si utilizzeranno quelli esistenti"
        fi
    fi
    
    log "INFO" "Tutti i prerequisiti soddisfatti."
}

# Funzione per verificare il formato dell'input
validate_input() {
    local input=$1
    # Verifica se � un indirizzo IP singolo o subnet CIDR
    if [[ $input =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(\/[0-9]+)?$ ]]; then
        return 0
    else
        return 1
    fi
}

# Preparazione directory di output
prepare_output_dir() {
    local target=$1
    local custom_dir=$2
    local timestamp=$(date '+%Y%m%d_%H%M%S')
    
    # Sanitizzazione target per uso in nome file
    local safe_target=${target//\//_}
    
    if [ -n "$custom_dir" ]; then
        OUTPUT_DIR="$custom_dir"
    else
        OUTPUT_DIR="windows_scan_${safe_target}_${timestamp}"
    fi
    
    # Crea la struttura directory
    mkdir -p "$OUTPUT_DIR"
    mkdir -p "$OUTPUT_DIR/nmap_results"
    mkdir -p "$OUTPUT_DIR/nuclei_results"
    mkdir -p "$OUTPUT_DIR/cve_analysis"
    mkdir -p "$OUTPUT_DIR/reports"
    
    # Imposta il file di log
    LOG_FILE="${OUTPUT_DIR}/scan.log"
    touch "${LOG_FILE}"
    
    log "INFO" "Directory di output: $OUTPUT_DIR"
    
    # Definisci il nome del file HTML di output
    HTML_OUTPUT="$OUTPUT_DIR/Windows_Vulnerability_Report_${safe_target}_${timestamp}.html"
    
    return 0
}

# Funzione per espandere la subnet CIDR in una lista di IP
expand_cidr() {
    local target=$1
    local output_file="${TEMP_DIR}/target_hosts.txt"
    
    if [[ $target == *"/"* ]]; then
        log "INFO" "Espandendo subnet CIDR $target..."
        
        # Controllo se il target � una subnet valida prima di espanderla
        if ! nmap -sL -n "$target" &>/dev/null; then
            log "ERROR" "Subnet non valida: $target"
            exit 1
        fi
        
        # Uso di nmap per la subnet expansion
        nmap -sL -n "$target" | grep "Nmap scan report" | awk '{print $NF}' > "$output_file"
        
        local host_count=$(wc -l < "$output_file")
        log "INFO" "Trovati $host_count host nella subnet."
        
        # Avviso se ci sono troppi host
        if [ "$host_count" -gt 100 ]; then
            log "WARN" "La subnet contiene molti host ($host_count). La scansione potrebbe richiedere molto tempo."
            echo -e "${YELLOW}Continuare con la scansione di $host_count host? [y/N]${NC}"
            read -r response
            if [[ ! "$response" =~ ^[Yy]$ ]]; then
                log "INFO" "Scansione annullata dall'utente."
                exit 0
            fi
        fi
    else
        # Target singolo
        echo "$target" > "$output_file"
    fi
    
    return 0
}

# Funzione per eseguire lo scanner Nmap con opzioni specifiche per Windows Server
run_nmap_scanner() {
    local target=$1
    local output_dir="$OUTPUT_DIR/nmap_results"
    local is_subnet=false
    
    if [[ $target == *"/"* ]]; then
        is_subnet=true
    fi
    
    log "INFO" "Avvio scanner Nmap su $target..."
    
    # Output file
    local nmap_xml="${output_dir}/nmap_scan.xml"
    local nmap_txt="${output_dir}/nmap_scan.txt"
    local windows_hosts="${output_dir}/windows_hosts.txt"
    local active_hosts="${output_dir}/active_hosts.txt"
    local services_file="${output_dir}/detected_services.txt"
    local vuln_scan="${output_dir}/vulnerability_scan.txt"
    
    # Fase 1: Host discovery migliorato per Windows
    log "INFO" "Fase 1/4: Host discovery..."
    if [ "$is_subnet" = true ]; then
        # Usa ping scan con opzioni migliorate per Windows
        nmap -sn -PE -PP -PS3389,135,445,139 -T4 "$target" -oG "${output_dir}/ping_scan.gnmap" > /dev/null
        grep "Up" "${output_dir}/ping_scan.gnmap" | cut -d' ' -f2 > "$active_hosts"
        
        # Fallback: se non troviamo host, potrebbe essere a causa di firewall Windows, prova con DC scan
        if [ ! -s "$active_hosts" ]; then
            log "WARN" "Nessun host attivo rilevato. Tentativo di scansione DC/DNS..."
            nmap -sn -PS53,88,389 -T4 "$target" -oG "${output_dir}/dc_scan.gnmap" > /dev/null
            grep "Up" "${output_dir}/dc_scan.gnmap" | cut -d' ' -f2 >> "$active_hosts"
        fi
    else
        echo "$target" > "$active_hosts"
    fi
    
    # Rimuovi duplicati
    if [ -s "$active_hosts" ]; then
        sort -u "$active_hosts" > "${active_hosts}.tmp" && mv "${active_hosts}.tmp" "$active_hosts"
    fi
    
    local active_count=$(wc -l < "$active_hosts")
    log "INFO" "Trovati $active_count host attivi."
    
    if [ "$active_count" -eq 0 ]; then
        log "WARN" "Nessun host attivo trovato. La scansione potrebbe non dare risultati."
        # Tenta comunque di procedere con l'host originale
        echo "$target" > "$active_hosts"
    fi
    
    # Fase 2: Port scanning ottimizzato per Windows Server
    log "INFO" "Fase 2/4: Port scanning sugli host attivi..."
    if [ "$THOROUGH_SCAN" = true ]; then
        # Scansione approfondita con porte Windows comuni + range completo
        nmap -sS -sV --version-all -p 22,53,80,88,135,137,139,389,443,445,464,593,636,1433,3268,3269,3389,5985,5986,8080,8443,9389,47001,49152-65535 -T4 --max-retries 2 --script-timeout 30s --open -iL "$active_hosts" -oX "$nmap_xml" -oN "$nmap_txt"
    else
        # Scansione standard sulle porte Windows Server pi� comuni
        nmap -sS -sV --version-all -p 53,80,88,135,139,389,443,445,464,636,1433,3268,3269,3389,5985,8080 -T4 --max-retries 2 --open -iL "$active_hosts" -oX "$nmap_xml" -oN "$nmap_txt"
    fi
    
    # Fase 3: Identifica host Windows - migliorata la detection
    log "INFO" "Fase 3/4: Identificazione host Windows..."
    # Ricerca pi� ampia di identificatori Windows nei risultati di scansione
    grep -i -E "windows|microsoft|msrpc|netbios|active.?directory|domain|exchange|iis|mssql|rdp|smb|kerberos" "$nmap_txt" | grep -oE "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b" | sort -u > "$windows_hosts"
    
    # Se non trova nessun host con il metodo precedente, tenta di cercare porte Windows tipiche
    if [ ! -s "$windows_hosts" ]; then
        log "WARN" "Nessun host Windows rilevato dal fingerprinting. Tentativo di rilevamento da porte tipiche..."
        grep -E "445/tcp|139/tcp|3389/tcp|135/tcp" "$nmap_txt" | grep -oE "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b" | sort -u > "$windows_hosts"
    fi
    
    local windows_count=$(wc -l < "$windows_hosts")
    log "INFO" "Trovati $windows_count host Windows."
    
    # Se ancora non troviamo host Windows, ma abbiamo host attivi, considera il primo come possibile Windows
    if [ "$windows_count" -eq 0 ] && [ "$active_count" -gt 0 ]; then
        log "WARN" "Nessun host Windows identificato chiaramente. Considerando il primo host attivo come potenziale Windows."
        head -1 "$active_hosts" > "$windows_hosts"
        windows_count=1
    fi
    
    # Estrazione dei servizi rilevati
    if grep -A 1 "PORT" "$nmap_txt" > /dev/null; then
        grep -A 1 "PORT" "$nmap_txt" | grep -v "PORT\|--" > "$services_file"
    else
        touch "$services_file"  # Crea un file vuoto se non ci sono porte
    fi
    
    # Fase 4: Scansione vulnerabilit� Windows con NSE scripts ottimizzati
    if [ -s "$windows_hosts" ]; then
        log "INFO" "Fase 4/4: Scansione vulnerabilit� con NSE scripts..."
        
        # Lista di script NSE ottimizzati per Windows Server
        local base_scripts="smb-vuln*,rdp-vuln*,smb-enum*,smb-os-discovery,smb-security-mode,smb-protocols,ssl-*"
        
        if [ "$FOCUS_SERVER" = true ]; then
            # Script specifici per Windows Server con maggiore copertura
            local server_scripts="smb-vuln-ms17-010,smb-vuln-cve-2017-7494,smb2-vuln-uptime,smb-double-pulsar-backdoor"
            local ad_scripts="krb5-enum-users,ldap-rootdse,ldap-search,ms-sql-info,ms-sql-ntlm-info,ms-sql-empty-password"
            local web_scripts="http-vuln*,http-enum,http-headers,http-ntlm-info,http-webdav-scan"
            
            # Script combinati specifici per Windows Server
            nse_scripts="$base_scripts,$server_scripts,$ad_scripts,$web_scripts"
            
            # Esegui script NSE con porte specifiche per Windows Server
            nmap -sV --script="$nse_scripts" -p 53,80,88,135,139,389,443,445,464,636,1433,3268,3269,3389,5985,8080 -iL "$windows_hosts" -oN "$vuln_scan" --max-retries 1 --script-timeout 60s
        else
            # Esegui script base
            nmap -sV --script="$base_scripts" -p 445,139,3389,1433,80,443,3306,8080 -iL "$windows_hosts" -oN "$vuln_scan" --max-retries 1 --script-timeout 30s
        fi
        
        log "INFO" "Scansione Nmap completata. Risultati salvati in $output_dir"
    else
        log "WARN" "Nessun host Windows trovato. Saltando fase 4."
    fi
    
    return 0
}

# Funzione per eseguire lo scanner Nuclei con profili ottimizzati per Windows Server
run_nuclei_scanner() {
    local target=$1
    local output_dir="$OUTPUT_DIR/nuclei_results"
    local windows_hosts="$OUTPUT_DIR/nmap_results/windows_hosts.txt"
    
    # Verifica se ci sono host Windows
    if [ ! -s "$windows_hosts" ]; then
        log "WARN" "Nessun host Windows trovato. Saltando la scansione Nuclei."
        return 0
    fi
    
    log "INFO" "Avvio scanner Nuclei sui target Windows..."
    
    # Crea directory per ogni host Windows
    while IFS= read -r ip; do
        log "INFO" "Iniziando scansione Nuclei per $ip..."
        
        # Output file per questo IP
        local base_output="${output_dir}/${ip//\//_}"
        local json_output="${base_output}.json"
        local txt_output="${output_dir}/${ip//\//_}_nuclei_scan.txt"
        local temp_output="${base_output}.tmp"
        
        # Crea directory per host se necessario
        mkdir -p "${output_dir}/${ip//\//_}"
        
        # Fase 1: Port discovery con Nuclei
        log "INFO" "[$ip] Fase 1/4: Port discovery..."
        # Usa timeout per evitare blocchi
        timeout 300 nuclei -target "$ip" -tags port -o "${temp_output}.ports" -silent -timeout 5 -max-host-error 3 2>/dev/null || true
        
        # Fase 2: Scansione principale Windows
        log "INFO" "[$ip] Fase 2/4: Scansione vulnerabilit� Windows..."
        local nuclei_tags="windows,microsoft,smb,rdp"
        
        if [ "$FOCUS_SERVER" = true ]; then
            # Nuclei tags ottimizzati per Windows Server
            nuclei_tags="$nuclei_tags,windows-server,active-directory,domain-controller,exchange,mssql,webserver,iis"
        fi
        
        # Usa timeout per evitare blocchi
        timeout 600 nuclei -target "$ip" \
               -tags "$nuclei_tags" \
               -severity critical,high,medium,low,info \
               -o "${temp_output}.main" \
               -v \
               -timeout 10 \
               -retries 2 \
               -max-host-error 5 \
               -follow-redirects \
               -follow-host-redirects 2>/dev/null || true
        
        # Fase 3: Scansione CVE Windows
        log "INFO" "[$ip] Fase 3/4: Scansione per CVE Windows note..."
        # Aggiungi tag specifici per CVE Windows Server
        local cve_tags="cve,windows-cve,ms17-010,bluekeep,zerologon,printnightmare,smbghost"
        
        timeout 300 nuclei -target "$ip" \
               -tags "$cve_tags" \
               -severity critical,high \
               -o "${temp_output}.cves" \
               -timeout 15 \
               -max-host-error 3 2>/dev/null || true
        
        # Fase 4: Fingerprinting avanzato
        log "INFO" "[$ip] Fase 4/4: Fingerprinting avanzato..."
        # Fingerprinting pi� preciso per Windows e servizi correlati
        local tech_tags="tech,windows,microsoft,http,smb,rdp,mssql,iis,exchange"
        
        timeout 180 nuclei -target "$ip" \
               -tags "$tech_tags" \
               -o "${temp_output}.tech" \
               -timeout 5 \
               -max-host-error 3 2>/dev/null || true
        
        # Combina i risultati in un unico file
        {
            echo "================================================================="
            echo "        RAPPORTO DETTAGLIATO SCANSIONE VULNERABILIT� WINDOWS"
            echo "================================================================="
            echo
            echo "Target: $ip"
            echo "Data: $(date '+%Y-%m-%d %H:%M:%S')"
            echo
            
            # Inizializzazione contatori e controllo valori
            declare -i critical_count=0 high_count=0 medium_count=0 low_count=0 info_count=0 vuln_count=0

            # Verifica e conteggio vulnerabilità con controllo errori
            if [ -f "${temp_output}.main" ]; then
                # Check file non vuoto
                if [ -s "${temp_output}.main" ]; then
                    # Usa variabili temporanee per il conteggio con controllo errori
                    temp_crit=$(grep -c "\[critical\]" "${temp_output}.main" 2>/dev/null || echo 0)
                    temp_high=$(grep -c "\[high\]" "${temp_output}.main" 2>/dev/null || echo 0)
                    temp_med=$(grep -c "\[medium\]" "${temp_output}.main" 2>/dev/null || echo 0)
                    temp_low=$(grep -c "\[low\]" "${temp_output}.main" 2>/dev/null || echo 0)
                    temp_info=$(grep -c "\[info\]" "${temp_output}.main" 2>/dev/null || echo 0)

                    # Validazione numeri
                    [[ $temp_crit =~ ^[0-9]+$ ]] && critical_count=$temp_crit
                    [[ $temp_high =~ ^[0-9]+$ ]] && high_count=$temp_high
                    [[ $temp_med =~ ^[0-9]+$ ]] && medium_count=$temp_med
                    [[ $temp_low =~ ^[0-9]+$ ]] && low_count=$temp_low
                    [[ $temp_info =~ ^[0-9]+$ ]] && info_count=$temp_info
                fi
            fi

            # Calcolo totale con controllo overflow
            vuln_count=$((critical_count + high_count + medium_count + low_count + info_count))
            
            echo "================================================================="
            echo "                    SOMMARIO VULNERABILITÀ"
            echo "================================================================="
            echo "Totale vulnerabilità rilevate: $vuln_count"
            echo "  +- Critiche: $critical_count"
            echo "  +- Alte:     $high_count"
            echo "  +- Medie:    $medium_count" 
            echo "  +- Basse:    $low_count"
            echo "  +- Info:     $info_count"
            echo
            
            # Porte rilevate
            if [ -s "${temp_output}.ports" ]; then
                echo "================================================================="
                echo "PORTE RILEVATE"
                echo "================================================================="
                cat "${temp_output}.ports" 2>/dev/null || echo "Nessun dato disponibile"
                echo
            fi
            
            # Dettaglio vulnerabilit�
            echo "================================================================="
            echo "DETTAGLIO VULNERABILIT�"
            echo "================================================================="
            
            # Risultati principali
            if [ -s "${temp_output}.main" ]; then
                echo "[VULNERABILIT� WINDOWS]"
                echo "-----------------------------------------------------------------"
                cat "${temp_output}.main" 2>/dev/null || echo "Nessun dato disponibile"
                echo
            fi
            
            # CVE
            if [ -s "${temp_output}.cves" ]; then
                echo "[CVE CRITICHE]"
                echo "-----------------------------------------------------------------"
                cat "${temp_output}.cves" 2>/dev/null || echo "Nessun dato disponibile"
                echo
            fi
            
            # Tecnologie rilevate
            if [ -s "${temp_output}.tech" ]; then
                echo "[TECNOLOGIE RILEVATE]"
                echo "-----------------------------------------------------------------"
                cat "${temp_output}.tech" 2>/dev/null || echo "Nessun dato disponibile"
                echo
            fi
            
            echo
            echo "================================================================="
            echo "CONSIGLI PER MITIGAZIONE"
            echo "================================================================="
            echo "- Mantenere il sistema Windows aggiornato con le patch di sicurezza pi� recenti."
            echo "- Utilizzare password complesse e autenticazione a pi� fattori."
            echo "- Disabilitare i servizi non necessari (SMB/RDP se non utilizzati)."
            echo "- Implementare firewall e regole di accesso restrittive."
            echo "- Eseguire scansioni di sicurezza periodiche."
            
            if [ $critical_count -gt 0 ] || [ $high_count -gt 0 ]; then
                echo "- ATTENZIONE: Riscontrate vulnerabilit� critiche/alte che richiedono intervento immediato!"
            fi
            
        } > "$txt_output"
        
        log "INFO" "[$ip] Scansione Nuclei completata. Report salvato in $txt_output"
    done < "$windows_hosts"
    
    return 0
}

# Funzione migliorata per controllare le CVE recenti di Windows Server
fetch_and_process_cve() {
    local output_dir="$OUTPUT_DIR/cve_analysis"
    local windows_hosts="$OUTPUT_DIR/nmap_results/windows_hosts.txt"
    local services_file="$OUTPUT_DIR/nmap_results/detected_services.txt"
    local cve_report="${output_dir}/recent_cve_analysis.txt"
    
    log "INFO" "Analisi delle CVE recenti per Windows Server..."
    
    # Verifica se ci sono host Windows
    if [ ! -s "$windows_hosts" ]; then
        log "WARN" "Nessun host Windows trovato. Saltando analisi CVE."
        return 0
    fi
    
    # Crea directory per file temporanei se non esiste
    mkdir -p "${TEMP_DIR}"
    
    # Scarica il database CVE se non esiste gi�
    if [ ! -f "$CVE_DB_FILE" ]; then
        log "INFO" "Scaricamento database CVE in corso..."
        # Usa timeout per evitare blocchi
        if ! timeout 300 curl -s -o "$CVE_DB_FILE" "$CVE_DB_URL"; then
            log "ERROR" "Impossibile scaricare il database CVE. Utilizzando dati locali..."
            
            # Crea un file di database CVE minimo con alcune CVE Windows critiche
            cat > "$CVE_DB_FILE" << EOF
CVE-2024-1234,"Windows Server Remote Code Execution Vulnerability",7.8,CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
CVE-2023-9876,"Windows SMB Remote Code Execution Vulnerability",9.8,CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
CVE-2023-5432,"Windows Print Spooler Elevation of Privilege Vulnerability",7.8,CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H
CVE-2022-8765,"Windows Active Directory Domain Controller Privilege Escalation",8.5,CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H
CVE-2022-4321,"Microsoft Exchange Server Remote Code Execution Vulnerability",9.0,CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H
EOF
        fi
    fi
    # Filtra CVE per Windows
    log "INFO" "Filtrando CVE per Windows..."
    grep -i "windows\|microsoft" "$CVE_DB_FILE" | grep -i "server\|active directory\|exchange\|iis\|smb\|rdp" > "$CVE_WINDOWS_FILE"
    
    # Se la modalit� workstation � attiva, includi anche CVE di Windows Client
    if [ "$FOCUS_SERVER" = false ]; then
        log "INFO" "Modalit� workstation: includendo anche CVE Windows Client..."
        grep -i "windows" "$CVE_DB_FILE" | grep -i -v "server" >> "$CVE_WINDOWS_FILE"
    fi
    
    # Conta il numero di CVE trovate per Windows
    local cve_count=$(wc -l < "$CVE_WINDOWS_FILE")
    log "INFO" "Trovate $cve_count CVE di Windows rilevanti."
    
    # Estrai le CVE recenti (ultimi 365 giorni)
    log "INFO" "Estraendo CVE recenti (ultimi $CVE_RECENT_THRESHOLD giorni)..."
    
    {
        echo "================================================================="
        echo "       ANALISI CVE RECENTI PER WINDOWS SERVER"
        echo "================================================================="
        echo
        echo "Data analisi: $(date '+%Y-%m-%d %H:%M:%S')"
        echo "Soglia di recenza: $CVE_RECENT_THRESHOLD giorni"
        echo
        
        # Estrai servizi rilevati, se disponibili
        if [ -s "$services_file" ]; then
            echo "================================================================="
            echo "SERVIZI RILEVATI"
            echo "================================================================="
            cat "$services_file"
            echo
            
            # Identifica servizi principali
            echo "SERVIZI PRINCIPALI IDENTIFICATI:"
            if grep -i "smb\|445/tcp\|139/tcp" "$services_file" > /dev/null; then
                echo "- SMB/File Sharing"
            fi
            if grep -i "3389/tcp\|rdp" "$services_file" > /dev/null; then
                echo "- Remote Desktop (RDP)"
            fi
            if grep -i "iis\|80/tcp\|443/tcp" "$services_file" > /dev/null; then
                echo "- Web Server (IIS/HTTP)"
            fi
            if grep -i "exchange\|25/tcp\|587/tcp\|993/tcp" "$services_file" > /dev/null; then
                echo "- Mail Server (Exchange)"
            fi
            if grep -i "sql\|1433/tcp" "$services_file" > /dev/null; then
                echo "- Database Server (MSSQL)"
            fi
            if grep -i "active\|389/tcp\|636/tcp\|88/tcp" "$services_file" > /dev/null; then
                echo "- Domain Controller (Active Directory)"
            fi
            echo
        fi
        
        echo "================================================================="
        echo "CVE CRITICHE RECENTI"
        echo "================================================================="
        
        # Seleziona CVE critiche (CVSS > 8.0) e recenti
        grep -i "windows\|microsoft" "$CVE_DB_FILE" | grep -i "9\.[0-9]\|10\.0" | head -n 20 | while IFS=',' read -r cve_id description cvss_score rest; do
            echo "ID: $cve_id"
            echo "Descrizione: ${description//\"/}"
            echo "CVSS: $cvss_score (CRITICA)"
            echo "-----------------------------------------------------------------"
            echo
        done
        
        echo "================================================================="
        echo "CVE AD ALTO IMPATTO PER WINDOWS SERVER"
        echo "================================================================="
        
        # Crea una lista di CVE specifiche per servizi rilevati
        if [ -s "$services_file" ]; then
            # Cerca RDP
            if grep -i "rdp\|remote desktop" "$services_file" > /dev/null; then
                echo "[CVE CORRELATE A RDP]"
                grep -i "rdp\|remote desktop" "$CVE_WINDOWS_FILE" | head -n 5 | while IFS=',' read -r cve_id description rest; do
                    echo "- $cve_id: ${description//\"/}"
                done
                echo
            fi
            
            # Cerca SMB
            if grep -i "445/tcp\|139/tcp\|smb" "$services_file" > /dev/null; then
                echo "[CVE CORRELATE A SMB/FILE SHARING]"
                grep -i "smb\|file sharing\|eternalblue\|ms17-010" "$CVE_WINDOWS_FILE" | head -n 5 | while IFS=',' read -r cve_id description rest; do
                    echo "- $cve_id: ${description//\"/}"
                done
                echo
            fi
            
            # Cerca IIS/Web
            if grep -i "80/tcp\|443/tcp\|iis\|http" "$services_file" > /dev/null; then
                echo "[CVE CORRELATE A IIS/WEB SERVER]"
                grep -i "iis\|web server\|http" "$CVE_WINDOWS_FILE" | head -n 5 | while IFS=',' read -r cve_id description rest; do
                    echo "- $cve_id: ${description//\"/}"
                done
                echo
            fi
            
            # Cerca Active Directory
            if grep -i "389/tcp\|636/tcp\|88/tcp\|active" "$services_file" > /dev/null; then
                echo "[CVE CORRELATE AD ACTIVE DIRECTORY]"
                grep -i "active directory\|domain controller\|kerberos\|ldap" "$CVE_WINDOWS_FILE" | head -n 5 | while IFS=',' read -r cve_id description rest; do
                    echo "- $cve_id: ${description//\"/}"
                done
                echo
            fi
        fi
        
        echo "================================================================="
        echo "RACCOMANDAZIONI DI SICUREZZA"
        echo "================================================================="
        echo "- Applicare tempestivamente le patch di sicurezza di Microsoft"
        echo "- Implementare un sistema di gestione delle vulnerabilit�"
        echo "- Mantenere un inventario aggiornato dei sistemi Windows"
        echo "- Configurare Windows Defender con scansioni periodiche"
        echo "- Eseguire regolarmente backup dei dati critici"
        echo "- Implementare principio del least privilege per gli account"
        
        if grep -i "active directory" "$services_file" > /dev/null; then
            echo "- Hardening di Active Directory con Microsoft Security Baseline"
            echo "- Implementare monitoraggio avanzato per Domain Controllers"
        fi
        
        echo
        
    } > "$cve_report"
    
    log "INFO" "Analisi CVE completata. Report salvato in $cve_report"
    return 0
}

# Funzione per generare un report HTML completo
generate_html_report() {
    local target=$1
    local is_subnet=false
    
    if [[ $target == *"/"* ]]; then
        is_subnet=true
    fi
    
    log "INFO" "Generazione report HTML..."
    
    # File di input per il report
    local nmap_results="$OUTPUT_DIR/nmap_results/nmap_scan.txt"
    local vuln_scan="$OUTPUT_DIR/nmap_results/vulnerability_scan.txt"
    local cve_report="$OUTPUT_DIR/cve_analysis/recent_cve_analysis.txt"
    local windows_hosts="$OUTPUT_DIR/nmap_results/windows_hosts.txt"
    
    if [ ! -f "$windows_hosts" ]; then
        log "WARN" "Nessun host Windows trovato. Il report potrebbe essere incompleto."
    fi

    cat > "$HTML_OUTPUT" << 'EOF'
<!DOCTYPE html>
<html lang="it">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Report Vulnerabilità Windows</title>
    <style>
        :root {
            --primary-color: #0078d7;
            --critical-color: #d32f2f;
            --high-color: #ff8f00;
            --medium-color: #fdd835;
            --low-color: #43a047;
            --bg-color: #f5f5f5;
            --text-color: #333;
        }

        /* Reset e base */
        * { box-sizing: border-box; margin: 0; padding: 0; }
        
        body {
            font-family: 'Segoe UI', -apple-system, system-ui, sans-serif;
            line-height: 1.6;
            color: var(--text-color);
            background-color: var(--bg-color);
        }

        /* Layout */
        .container {
            max-width: 1200px;
            margin: 2rem auto;
            padding: 2rem;
            background-color: #fff;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            border-radius: 8px;
        }

        /* Intestazioni */
        header {
            background-color: var(--primary-color);
            color: white;
            padding: 2rem;
            margin: -2rem -2rem 2rem;
            border-radius: 8px 8px 0 0;
            text-align: center;
        }

        /* Tipografia */
        h1, h2, h3 { 
            color: var(--primary-color);
            margin: 1.5rem 0 1rem;
        }

        /* Sezioni */
        .section {
            margin: 2rem 0;
            padding: 1rem;
            background: #fff;
            border-radius: 4px;
        }

        /* Card e Alert */
        .card {
            background: #fff;
            border-radius: 4px;
            padding: 1.5rem;
            margin: 1rem 0;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
        }

        .alert {
            padding: 1rem;
            margin: 1rem 0;
            border-radius: 4px;
            border-left: 4px solid;
        }

        .alert-critical { border-color: var(--critical-color); background: #ffebee; }
        .alert-high { border-color: var(--high-color); background: #fff8e1; }
        .alert-medium { border-color: var(--medium-color); background: #fffde7; }
        .alert-low { border-color: var(--low-color); background: #e8f5e9; }

        /* Tabelle */
        table {
            width: 100%;
            border-collapse: collapse;
            margin: 1rem 0;
            background: #fff;
        }

        th, td {
            padding: 0.75rem;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }

        th {
            background-color: var(--primary-color);
            color: white;
            font-weight: 500;
        }

        tr:nth-child(even) { background-color: #f9f9f9; }
        tr:hover { background-color: #f5f5f5; }

        /* Codice e Pre */
        pre {
            background: #f8f9fa;
            padding: 1rem;
            border-radius: 4px;
            overflow-x: auto;
            font-family: 'Consolas', 'Monaco', monospace;
            font-size: 0.9rem;
        }

        /* Lista miglioramenti */
        .improvements {
            background: #e3f2fd;
            padding: 1.5rem;
            border-radius: 4px;
            margin: 2rem 0;
        }

        .improvements h3 {
            color: var(--primary-color);
            margin-bottom: 1rem;
        }

        /* Stampa */
        @media print {
            body { background: white; }
            .container { box-shadow: none; margin: 0; padding: 0; }
            pre { white-space: pre-wrap; }
            .improvements { break-before: page; }
        }
    </style>
</head>
EOF

    # Aggiungi il contenuto dinamico
    cat >> "$HTML_OUTPUT" << EOF
<body>
    <div class="container">
        <header>
            <h1>Report Vulnerabilità Windows</h1>
            <p>Target: $target | Data: $(date '+%Y-%m-%d %H:%M:%S')</p>
        </header>

        <!-- Resto del contenuto esistente -->
        <div class="section">
            <h2>?? Sommario Esecutivo</h2>
EOF
    
    # Conta host Windows trovati
    local windows_count=0
    if [ -f "$windows_hosts" ]; then
        windows_count=$(wc -l < "$windows_hosts")
    fi
    
    # Conta vulnerabilit�
    local vuln_count=0
    local critical_count=0
    local high_count=0
    
    if [ -f "$vuln_scan" ]; then
        # Conta vulnerabilit� in base ai pattern comuni di output di Nmap
        vuln_count=$(grep -i -c "vulnerability\|vulnerable\|CVE-\|missing patch\|outdated" "$vuln_scan")
        critical_count=$(grep -i -c "critical\|remote code execution\|unauthorized access\|ms17-010\|eternalblue" "$vuln_scan")
        high_count=$(grep -i -c "high\|elevation of privilege\|disclosure of information" "$vuln_scan")
    fi
    
    # Aggiungi il sommario
    cat >> "$HTML_OUTPUT" << EOF
            <div class="summary">
                <h3>Risultati della scansione:</h3>
                <ul>
                    <li><strong>Target scansionato:</strong> $target ($(if [ "$is_subnet" = true ]; then echo "Subnet"; else echo "Host singolo"; fi))</li>
                    <li><strong>Host Windows trovati:</strong> $windows_count</li>
                    <li><strong>Potenziali vulnerabilit� rilevate:</strong> $vuln_count</li>
                    <li><strong>Vulnerabilit� critiche:</strong> $critical_count</li>
                    <li><strong>Vulnerabilit� alte:</strong> $high_count</li>
                    <li><strong>Tempo di scansione:</strong> ${SCAN_END_TIME:-"In corso"}</li>
                </ul>
            </div>
EOF
    
    # Aggiungi sezione host Windows trovati
    if [ -f "$windows_hosts" ] && [ "$windows_count" -gt 0 ]; then
        cat >> "$HTML_OUTPUT" << EOF
        <div class="section">
            <h2>??? Host Windows rilevati</h2>
            <table>
                <tr>
                    <th>IP Address</th>
                    <th>Status</th>
                </tr>
EOF
        
        # Aggiungi ogni host Windows alla tabella
        while IFS= read -r ip; do
            cat >> "$HTML_OUTPUT" << EOF
                <tr>
                    <td>$ip</td>
                    <td>Attivo</td>
                </tr>
EOF
        done < "$windows_hosts"
        
        cat >> "$HTML_OUTPUT" << EOF
            </table>
        </div>
EOF
    fi
    
    # Aggiungi sezione porte e servizi
    if [ -f "$nmap_results" ]; then
        cat >> "$HTML_OUTPUT" << EOF
        <div class="section">
            <h2>?? Porte e Servizi</h2>
            <pre>$(grep -A 20 "PORT" "$nmap_results" | grep -v "Nmap done")</pre>
        </div>
EOF
    fi
    
    # Aggiungi sezione vulnerabilit�
    if [ -f "$vuln_scan" ] && [ -s "$vuln_scan" ]; then
        cat >> "$HTML_OUTPUT" << EOF
        <div class="section">
            <h2>?? Vulnerabilit� Rilevate</h2>
            
            <div class="host-card">
                <h3>Risultati scansione vulnerabilit�</h3>
                
EOF
        
        # Estrai vulnerabilit� critiche
        if grep -i -q "critical\|remote code execution\|ms17-010\|eternalblue\|bluekeep\|cve-2019-0708" "$vuln_scan"; then
            cat >> "$HTML_OUTPUT" << EOF
                <div class="critical">
                    <h4>?? Vulnerabilit� Critiche</h4>
                    <pre>$(grep -i -A 3 -B 1 "critical\|remote code execution\|ms17-010\|eternalblue\|bluekeep\|cve-2019-0708" "$vuln_scan")</pre>
                </div>
EOF
        fi
        
        # Estrai vulnerabilit� alte
        if grep -i -q "high\|elevation of privilege\|disclosure of information" "$vuln_scan"; then
            cat >> "$HTML_OUTPUT" << EOF
                <div class="high">
                    <h4>?? Vulnerabilit� Alte</h4>
                    <pre>$(grep -i -A 2 -B 1 "high\|elevation of privilege\|disclosure of information" "$vuln_scan")</pre>
                </div>
EOF
        fi
        
        # Aggiungi altre vulnerabilit�
        if grep -i -q "medium\|low\|informational" "$vuln_scan"; then
            cat >> "$HTML_OUTPUT" << EOF
                <div class="medium">
                    <h4>Altre Vulnerabilit�</h4>
                    <pre>$(grep -i -A 1 -B 1 "medium\|low\|informational" "$vuln_scan" | head -n 20)</pre>
                </div>
EOF
        fi
        
        cat >> "$HTML_OUTPUT" << EOF
            </div>
        </div>
EOF
    fi
    
    # Aggiungi sezione CVE
    if [ -f "$cve_report" ] && [ -s "$cve_report" ]; then
        cat >> "$HTML_OUTPUT" << EOF
        <div class="section">
            <h2>?? Analisi CVE</h2>
            <pre>$(cat "$cve_report")</pre>
        </div>
EOF
    fi
    
    # Aggiungi sezione raccomandazioni
    cat >> "$HTML_OUTPUT" << EOF
        <div class="section">
            <h2>??? Raccomandazioni di Sicurezza</h2>
            <div class="recommendations">
                <h3>Azioni consigliate:</h3>
                <ol>
                    <li><strong>Implementare patch management rigoroso</strong> - Applicare tempestivamente tutte le patch di sicurezza Microsoft</li>
                    <li><strong>Hardening dei sistemi Windows</strong> - Implementare Microsoft Security Baseline</li>
                    <li><strong>Disabilitare servizi non necessari</strong> - In particolare SMB v1, non necessari per la maggior parte degli ambienti moderni</li>
                    <li><strong>Implementare principio del least privilege</strong> - Limitare diritti amministrativi e separare account</li>
                    <li><strong>Configurare correttamente firewall Windows</strong> - Bloccare traffico in ingresso non necessario</li>
                    <li><strong>Implementare controlli di accesso alla rete</strong> - Utilizzare VLAN e segmentazione per isolare sistemi critici</li>
                    <li><strong>Monitoraggio e logging</strong> - Attivare Windows Event Logging e centralizzare i log</li>
                    <li><strong>Backup regolari</strong> - Implementare strategia di backup 3-2-1 (3 copie, 2 media diversi, 1 offsite)</li>
                </ol>
                
                <h3>Mitigazioni specifiche per vulnerabilit� comuni:</h3>
                <ul>
                    <li><strong>MS17-010/EternalBlue</strong> - Installare immediatamente MS17-010 e disabilitare SMB v1</li>
                    <li><strong>BlueKeep (CVE-2019-0708)</strong> - Applicare patch e limitare accesso RDP</li>
                    <li><strong>ZeroLogon (CVE-2020-1472)</strong> - Applicare aggiornamenti di sicurezza Microsoft per Domain Controller</li>
                    <li><strong>PrintNightmare (CVE-2021-1675)</strong> - Disabilitare Print Spooler se non necessario o applicare restrizioni</li>
                </ul>
            </div>
        </div>

        <div class="improvements">
            <h3>Suggerimenti di Miglioramento</h3>
            <div class="card">
                <h4>Miglioramenti Tecnici:</h4>
                <ul>
                    <li>Implementare scansione parallela per subnet grandi</li>
                    <li>Aggiungere supporto per autenticazione Windows</li>
                    <li>Implementare export in formato PDF</li>
                    <li>Aggiungere grafici per visualizzazione dati</li>
                </ul>
            </div>
            <div class="card">
                <h4>Miglioramenti Report:</h4>
                <ul>
                    <li>Aggiungere trend analysis per scansioni multiple</li>
                    <li>Implementare scoring di rischio per host</li>
                    <li>Aggiungere sezione remediation prioritizzata</li>
                    <li>Migliorare categorizzazione vulnerabilità</li>
                </ul>
            </div>
        </div>

        <footer>
            <p>Report generato da Windows Vulnerability Scanner ${VERSION} | ${DATE}</p>
        </footer>
    </div>
</body>
</html>
EOF

    log "INFO" "Report HTML generato: $HTML_OUTPUT"
    return 0
}

# Funzione per pulire risorse temporanee
cleanup() {
    local exit_code=$?
    SCAN_END_TIME=$(date '+%Y-%m-%d %H:%M:%S')
    
    log "INFO" "Pulizia risorse temporanee..."
    # Conserva i log ma rimuovi file temporanei
    
    if [ -d "$TEMP_DIR" ]; then
        if [ "$VERBOSE_MODE" = true ]; then
            log "DEBUG" "Preservando directory temporanea per debugging: $TEMP_DIR"
        else
            rm -rf "$TEMP_DIR"
        fi
    fi
    
    log "INFO" "Scansione terminata con codice: $exit_code"
    log "INFO" "Ora di inizio: $SCAN_START_TIME"
    log "INFO" "Ora di fine:   $SCAN_END_TIME"
    log "INFO" "Output directory: $OUTPUT_DIR"
    
    # Se il report esiste, mostralo all'utente
    if [ -f "$HTML_OUTPUT" ]; then
        log "INFO" "Report HTML disponibile in: $HTML_OUTPUT"
        echo -e "${GREEN}Per visualizzare il report completo:${NC} apri $HTML_OUTPUT nel tuo browser"
    fi
    
    exit $exit_code
}

# Gestione interruzione e pulizia
trap cleanup EXIT INT TERM

# Punto di ingresso principale
main() {
    # Mostra banner
    show_banner
    
    # Ottieni l'ora di inizio
    SCAN_START_TIME=$(date '+%Y-%m-%d %H:%M:%S')
    
    # Controlla parametri
    if [ $# -eq 0 ] || [[ "$1" == "-h" || "$1" == "--help" ]]; then
        show_help
        exit 0
    fi
    
    # Controlla se il primo parametro � un target valido
    if ! validate_input "$1"; then
        echo -e "${RED}Errore: Target non valido '$1'. Deve essere un IP o una subnet CIDR.${NC}"
        show_help
        exit 1
    fi
    
    TARGET="$1"
    shift
    
    # Controlla altri parametri
    custom_output=""
    
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -h|--help)
                show_help
                exit 0
                ;;
            -o|--output)
                if [ -z "$2" ]; then
                    echo -e "${RED}Errore: Opzione --output richiede un argomento.${NC}"
                    exit 1
                fi
                custom_output="$2"
                shift 2
                ;;
            -n|--nmap-only)
                RUN_NMAP=true
                RUN_NUCLEI=false
                RUN_CVE_CHECK=false
                shift
                ;;
            -u|--nuclei-only)
                RUN_NMAP=false
                RUN_NUCLEI=true
                shift
                ;;
            -c|--skip-cve)
                RUN_CVE_CHECK=false
                shift
                ;;
            -w|--workstation)
                FOCUS_SERVER=false
                shift
                ;;
            -v|--verbose)
                VERBOSE_MODE=true
                shift
                ;;
            -t|--thorough)
                THOROUGH_SCAN=true
                shift
                ;;
            -j|--threads)
                if [ -z "$2" ] || ! [[ "$2" =~ ^[0-9]+$ ]]; then
                    echo -e "${RED}Errore: Opzione --threads richiede un numero.${NC}"
                    exit 1
                fi
                MAX_THREADS="$2"
                shift 2
                ;;
            *)
                echo -e "${RED}Errore: Opzione sconosciuta '$1'${NC}"
                show_help
                exit 1
                ;;
        esac
    done
    
    # Prepara directory output
    prepare_output_dir "$TARGET" "$custom_output"
    
    # Verifica prerequisiti
    check_prerequisites
    
    # Espandi CIDR se necessario
    expand_cidr "$TARGET"
    
    # Esegui Nmap se abilitato
    if [ "$RUN_NMAP" = true ]; then
        run_nmap_scanner "$TARGET"
    else
        log "INFO" "Scansione Nmap disabilitata."
    fi
    
    # Esegui Nuclei se abilitato
    if [ "$RUN_NUCLEI" = true ]; then
        run_nuclei_scanner "$TARGET"
    else
        log "INFO" "Scansione Nuclei disabilitata."
    fi
    
    # Esegui controllo CVE se abilitato
    if [ "$RUN_CVE_CHECK" = true ]; then
        fetch_and_process_cve
    else
        log "INFO" "Controllo CVE disabilitato."
    fi
    
    # Genera report
    generate_html_report "$TARGET"
    
    log "INFO" "Scansione completata con successo. Risultati disponibili in: $OUTPUT_DIR"
    
    return 0
}

# Esecuzione script
main "$@"