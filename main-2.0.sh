#!/bin/bash

# =============================================================
# WINDOWS VULNERABILITY SCANNER UNIFICATO
# =============================================================
# Autore: Versione unificata degli script di scansione Windows
# Versione: 1.0.0
# Data: 16 Aprile 2025
# Descrizione: Scanner completo di vulnerabilità per sistemi Windows 
# che integra Nmap, Nikto e Nuclei con report PDF
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
VERSION="1.0.0"
DATE=$(date "+%Y-%m-%d")
SCRIPT_PATH="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEMP_DIR="/tmp/windows_vuln_scan_$$"
OUTPUT_DIR=""
PDF_OUTPUT=""
TARGET=""
CVE_DB_URL="https://cve.mitre.org/data/downloads/allitems.csv"
CVE_DB_FILE="${TEMP_DIR}/cve_database.csv"
CVE_WINDOWS_FILE="${TEMP_DIR}/windows_cves.csv"
CVE_RECENT_THRESHOLD=365  # Considera CVE dell'ultimo anno come recenti
SCAN_START_TIME=""
SCAN_END_TIME=""

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
    echo "╔═════════════════════════════════════════════════════════════════════╗"
    echo "║                                                                     ║"
    echo "║   WINDOWS VULNERABILITY SCANNER UNIFICATO v${VERSION}                    ║"
    echo "║   Combina Nmap, Nikto e Nuclei con CVE Intelligence                ║"
    echo "║   Specializzato per Windows Server                                 ║"
    echo "║                                                                     ║"
    echo "╚═════════════════════════════════════════════════════════════════════╝"
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
    
    # Aggiungi il log al file di log generale
    echo "[$level] $timestamp - $message" >> "${TEMP_DIR}/scan.log"
}

# Funzione per visualizzare l'help
show_help() {
    echo "Utilizzo: $0 <target> [opzioni]"
    echo
    echo "Target:"
    echo "  Può essere un indirizzo IP singolo (es. 192.168.1.10) o una subnet CIDR (es. 192.168.1.0/24)"
    echo
    echo "Opzioni:"
    echo "  -h, --help            Mostra questo help"
    echo "  -o, --output DIR      Specifica la directory di output (default: auto-generata)"
    echo "  -n, --nmap-only       Esegui solo lo scanner basato su Nmap/Nikto"
    echo "  -u, --nuclei-only     Esegui solo lo scanner basato su Nuclei"
    echo "  -c, --skip-cve        Salta il controllo delle CVE recenti"
    echo "  -w, --workstation     Modalità workstation (default: server)"
    echo "  -v, --verbose         Mostra output dettagliato"
    echo "  -t, --thorough        Esegui una scansione approfondita (più lenta)"
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
    
    # Lista dei comandi necessari aggiornata
    essential_commands=("nmap" "nuclei" "sed" "awk" "grep" "pandoc" "curl" "jq" "timeout")
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
        echo "sudo apt update && sudo apt install -y nmap pandoc texlive-latex-base texlive-fonts-recommended texlive-latex-extra curl jq coreutils"
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
            log "WARN" "Non è stato possibile aggiornare i template, si utilizzeranno quelli esistenti"
        fi
    fi
    
    # Verifica versione di Pandoc
    PANDOC_VERSION=$(pandoc --version | head -n1 | awk '{print $2}')
    log "INFO" "Trovato Pandoc versione $PANDOC_VERSION"
    
    log "INFO" "Tutti i prerequisiti soddisfatti."
}

# Funzione per verificare il formato dell'input
validate_input() {
    local input=$1
    # Verifica se è un indirizzo IP singolo o subnet CIDR
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
    mkdir -p "$OUTPUT_DIR/reports/images"
    
    log "INFO" "Directory di output: $OUTPUT_DIR"
    
    # Definisci il nome del file PDF di output
    PDF_OUTPUT="$OUTPUT_DIR/Windows_Vulnerability_Report_${safe_target}_${timestamp}.pdf"
    
    return 0
}

# Funzione per espandere la subnet CIDR in una lista di IP
expand_cidr() {
    local target=$1
    local output_file="${TEMP_DIR}/target_hosts.txt"
    
    if [[ $target == *"/"* ]]; then
        log "INFO" "Espandendo subnet CIDR $target..."
        
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

# Funzione per eseguire lo scanner Nmap
run_nmap_scanner() {
    local target=$1
    local output_dir="$OUTPUT_DIR/nmap_results"
    local is_subnet=false
    
    if ([[ $target == *"/"* ]]); then
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
    
    # Fase 1: Host discovery
    log "INFO" "Fase 1/4: Host discovery..."
    if [ "$is_subnet" = true ]; then
        nmap -sn -T4 "$target" -oG "${output_dir}/ping_scan.gnmap" > /dev/null
        grep "Up" "${output_dir}/ping_scan.gnmap" | cut -d' ' -f2 > "$active_hosts"
    else
        echo "$target" > "$active_hosts"
    fi
    
    local active_count=$(wc -l < "$active_hosts")
    log "INFO" "Trovati $active_count host attivi."
    
    # Fase 2: Port scanning
    log "INFO" "Fase 2/4: Port scanning sugli host attivi..."
    if [ "$THOROUGH_SCAN" = true ]; then
        # Scansione approfondita su tutte le porte
        nmap -sS -sV -p- -T4 --max-retries 2 --script-timeout 30s --open -iL "$active_hosts" -oX "$nmap_xml" -oN "$nmap_txt"
    else
        # Scansione standard sulle porte più comuni
        nmap -sS -sV -T4 --max-retries 2 --open -iL "$active_hosts" -oX "$nmap_xml" -oN "$nmap_txt"
    fi
    
    # Fase 3: Identifica host Windows
    log "INFO" "Fase 3/4: Identificazione host Windows..."
    grep -i "windows\|microsoft" "$nmap_txt" | grep -oE "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b" | sort -u > "$windows_hosts"
    
    local windows_count=$(wc -l < "$windows_hosts")
    log "INFO" "Trovati $windows_count host Windows."
    
    # Estrazione dei servizi rilevati
    grep -A 1 "PORT" "$nmap_txt" | grep -v "PORT\|--" > "$services_file"
    
    # Fase 4: Scansione vulnerabilità Windows con NSE scripts
    if [ -s "$windows_hosts" ]; then
        log "INFO" "Fase 4/4: Scansione vulnerabilità con NSE scripts..."
        
        # Lista di script NSE per Windows, più completa e mirata a Windows Server
        local nse_scripts="smb-vuln*,rdp-vuln*,ms-sql-info,smb-enum*,smb-os-discovery,smb-security-mode,smb-protocols,ssl-*"
        
        if [ "$FOCUS_SERVER" = true ]; then
            # Aggiungi script specifici per Windows Server
            nse_scripts="$nse_scripts,http-vuln*,http-enum,ssl-heartbleed,ssl-poodle,ssl-ccs-injection"
        fi
        
        # Esegui script NSE
        nmap -sV --script="$nse_scripts" -p 445,139,3389,1433,80,443,3306,8080 -iL "$windows_hosts" -oN "$vuln_scan"
        
        log "INFO" "Scansione Nmap completata. Risultati salvati in $output_dir"
    else
        log "WARN" "Nessun host Windows trovato. Saltando fase 4."
    fi
    
    return 0
}

# Funzione per eseguire lo scanner Nuclei
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
        nuclei -target "$ip" -tags port -o "${temp_output}.ports" -silent 2>/dev/null || true
        
        # Fase 2: Scansione principale Windows
        log "INFO" "[$ip] Fase 2/4: Scansione vulnerabilità Windows..."
        local nuclei_tags="windows,microsoft,smb,rdp"
        
        if [ "$FOCUS_SERVER" = true ]; then
            nuclei_tags="$nuclei_tags,windows-server,active-directory,domain-controller,exchange"
        fi
        
        nuclei -target "$ip" \
               -tags "$nuclei_tags" \
               -severity critical,high,medium,low,info \
               -o "${temp_output}.main" \
               -v \
               -timeout 10 \
               -retries 2 \
               -follow-redirects \
               -follow-host-redirects 2>/dev/null || true
        
        # Fase 3: Scansione CVE Windows
        log "INFO" "[$ip] Fase 3/4: Scansione per CVE Windows note..."
        nuclei -target "$ip" \
               -tags cve \
               -severity critical,high \
               -o "${temp_output}.cves" \
               -timeout 15 2>/dev/null || true
        
        # Fase 4: Fingerprinting
        log "INFO" "[$ip] Fase 4/4: Fingerprinting avanzato..."
        nuclei -target "$ip" \
               -tags tech \
               -o "${temp_output}.tech" \
               -timeout 5 2>/dev/null || true
        
        # Combina i risultati in un unico file
        {
            echo "================================================================="
            echo "        RAPPORTO DETTAGLIATO SCANSIONE VULNERABILITÀ WINDOWS"
            echo "================================================================="
            echo
            echo "Target: $ip"
            echo "Data: $(date '+%Y-%m-%d %H:%M:%S')"
            echo
            
            # Conteggio vulnerabilità
            local critical_count=0
            local high_count=0
            local medium_count=0
            local low_count=0
            local info_count=0
            
            if [ -f "${temp_output}.main" ]; then
                critical_count=$(grep -c "\[critical\]" "${temp_output}.main" || echo "0")
                high_count=$(grep -c "\[high\]" "${temp_output}.main" || echo "0")
                medium_count=$(grep -c "\[medium\]" "${temp_output}.main" || echo "0")
                low_count=$(grep -c "\[low\]" "${temp_output}.main" || echo "0")
                info_count=$(grep -c "\[info\]" "${temp_output}.main" || echo "0")
            fi
            
            if [ -f "${temp_output}.cves" ]; then
                critical_count=$((critical_count + $(grep -c "\[critical\]" "${temp_output}.cves" || echo "0")))
                high_count=$((high_count + $(grep -c "\[high\]" "${temp_output}.cves" || echo "0")))
            fi
            
            local vuln_count=$((critical_count + high_count + medium_count + low_count + info_count))
            
            echo "================================================================="
            echo "SOMMARIO VULNERABILITÀ"
            echo "================================================================="
            echo "Totale vulnerabilità rilevate: $vuln_count"
            echo "  ├─ Critiche: $critical_count"
            echo "  ├─ Alte:     $high_count"
            echo "  ├─ Medie:    $medium_count" 
            echo "  ├─ Basse:    $low_count"
            echo "  └─ Info:     $info_count"
            echo
            
            # Porte rilevate
            if [ -s "${temp_output}.ports" ]; then
                echo "================================================================="
                echo "PORTE RILEVATE"
                echo "================================================================="
                cat "${temp_output}.ports" 2>/dev/null || echo "Nessun dato disponibile"
                echo
            fi
            
            # Dettaglio vulnerabilità
            echo "================================================================="
            echo "DETTAGLIO VULNERABILITÀ"
            echo "================================================================="
            
            # Risultati principali
            if [ -s "${temp_output}.main" ]; then
                echo "[VULNERABILITÀ WINDOWS]"
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
            echo "- Mantenere il sistema Windows aggiornato con le patch di sicurezza più recenti."
            echo "- Utilizzare password complesse e autenticazione a più fattori."
            echo "- Disabilitare i servizi non necessari (SMB/RDP se non utilizzati)."
            echo "- Implementare firewall e regole di accesso restrittive."
            echo "- Eseguire scansioni di sicurezza periodiche."
            
            if [ $critical_count -gt 0 ] || [ $high_count -gt 0 ]; then
                echo "- ATTENZIONE: Riscontrate vulnerabilità critiche/alte che richiedono intervento immediato!"
            fi
            
        } > "$txt_output"
        
        log "INFO" "[$ip] Scansione Nuclei completata. Report salvato in $txt_output"
    done < "$windows_hosts"
    
    return 0
}

# Funzione per controllare le CVE recenti
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
    
    # Scarica il database CVE se non esiste già
    if [ ! -f "$CVE_DB_FILE" ]; then
        log "INFO" "Scaricamento database CVE in corso..."
        curl -s "$CVE_DB_URL" > "$CVE_DB_FILE" || {
            log "ERROR" "Impossibile scaricare il database CVE. Saltando analisi CVE."
            return 1
        }
    fi
    
    # Filtra CVE per Windows
    log "INFO" "Filtrando CVE per Windows..."
    grep -i "windows\|microsoft" "$CVE_DB_FILE" > "$CVE_WINDOWS_FILE"
    
    # Calcola la data di un anno fa
    local year_ago=$(date -d "-${CVE_RECENT_THRESHOLD} days" +%Y)
    
    # Estrai le CVE Windows recenti
    log "INFO" "Estraendo CVE Windows recenti (ultimi ${CVE_RECENT_THRESHOLD} giorni)..."
    grep -i "CVE-${year_ago}" "$CVE_WINDOWS_FILE" > "${TEMP_DIR}/recent_windows_cves.csv"
    
    # Estrai i servizi rilevati
    local detected_services=()
    if [ -f "$services_file" ]; then
        while IFS= read -r line; do
            service=$(echo "$line" | awk '{print $3}' | tr -d '[:space:]' | tr '[:upper:]' '[:lower:]')
            detected_services+=("$service")
        done < "$services_file"
    fi
    
    # Genera report delle CVE rilevanti
    {
        echo "================================================================="
        echo "        ANALISI CVE RECENTI PER WINDOWS SERVER"
        echo "================================================================="
        echo 
        echo "Data: $(date '+%Y-%m-%d %H:%M:%S')"
        echo "Periodo considerato: CVE degli ultimi ${CVE_RECENT_THRESHOLD} giorni"
        echo
        
        echo "================================================================="
        echo "SERVIZI WINDOWS VULNERABILI RILEVATI"
        echo "================================================================="
        
        # Elenca i servizi rilevati
        if [ ${#detected_services[@]} -gt 0 ]; then
            for service in "${detected_services[@]}"; do
                echo "- $service"
                
                # Trova CVE recenti correlate a questo servizio
                if grep -i "$service" "${TEMP_DIR}/recent_windows_cves.csv" > "${TEMP_DIR}/service_cves.tmp"; then
                    echo "  CVE recenti correlate:"
                    while IFS= read -r cve_line; do
                        cve_id=$(echo "$cve_line" | grep -oE "CVE-[0-9]+-[0-9]+" | head -1)
                        echo "  * $cve_id - $(echo "$cve_line" | cut -d',' -f2- | tr -d '"')"
                    done < "${TEMP_DIR}/service_cves.tmp"
                    echo
                else
                    echo "  Nessuna CVE recente correlata trovata."
                    echo
                fi
            done
        else
            echo "Nessun servizio specifico rilevato."
            echo
        fi
        
        echo "================================================================="
        echo "TOP 10 CVE WINDOWS SERVER RECENTI (CRITICHE)"
        echo "================================================================="
        
        # Per Windows Server
        grep -i "windows server\|domain controller\|active directory" "${TEMP_DIR}/recent_windows_cves.csv" | head -10 | while IFS= read -r cve_line; do
            cve_id=$(echo "$cve_line" | grep -oE "CVE-[0-9]+-[0-9]+" | head -1)
            echo "* $cve_id - $(echo "$cve_line" | cut -d',' -f2- | tr -d '"')"
        done
        
        echo
        echo "================================================================="
        echo "RACCOMANDAZIONI SPECIFICHE"
        echo "================================================================="
        echo "- Verificare se i sistemi Windows sono vulnerabili alle CVE elencate"
        echo "- Prioritizzare l'applicazione delle patch per le CVE critiche"
        echo "- Implementare mitigazioni temporanee per le vulnerabilità non patchabili"
        echo "- Monitorare regolarmente il rilascio di nuove CVE Windows"
        echo "- Configurare Windows Update per l'installazione automatica degli aggiornamenti di sicurezza"
        echo
        
    } > "$cve_report"
    
    log "INFO" "Analisi CVE completata. Report salvato in $cve_report"
    return 0
}

# Funzione per generare grafici per il report
generate_charts() {
    local output_dir="$OUTPUT_DIR/reports/images"
    local nuclei_results="$OUTPUT_DIR/nuclei_results"
    local vuln_summary="${TEMP_DIR}/vuln_summary.txt"
    
    log "INFO" "Generazione grafici per il report..."
    
    # Raccolta statistiche vulnerabilità
    local critical=0
    local high=0
    local medium=0
    local low=0
    local info=0
    
    # Analizza i file di report Nuclei
    find "$nuclei_results" -name "*_nuclei_scan.txt" -type f | while IFS= read -r file; do
        local c=$(grep -A6 "SOMMARIO VULNERABILITÀ" "$file" | grep "Critiche" | grep -oE "[0-9]+" || echo "0")
        local h=$(grep -A6 "SOMMARIO VULNERABILITÀ" "$file" | grep "Alte" | grep -oE "[0-9]+" || echo "0")
        local m=$(grep -A6 "SOMMARIO VULNERABILITÀ" "$file" | grep "Medie" | grep -oE "[0-9]+" || echo "0")
        local l=$(grep -A6 "SOMMARIO VULNERABILITÀ" "$file" | grep "Basse" | grep -oE "[0-9]+" || echo "0")
        local i=$(grep -A6 "SOMMARIO VULNERABILITÀ" "$file" | grep "Info" | grep -oE "[0-9]+" || echo "0")
        
        critical=$((critical + c))
        high=$((high + h))
        medium=$((medium + m))
        low=$((low + l))
        info=$((info + i))
    done
    
    # Salva i dati in un file temporaneo
    echo "critical:$critical" > "$vuln_summary"
    echo "high:$high" >> "$vuln_summary"
    echo "medium:$medium" >> "$vuln_summary"
    echo "low:$low" >> "$vuln_summary"
    echo "info:$info" >> "$vuln_summary"
    
    # Crea un grafico delle vulnerabilità con HTML/CSS
    cat > "${output_dir}/vuln_chart.html" << EOF
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Vulnerabilità Rilevate</title>
    <style>
        .chart-container {
            width: 600px;
            margin: 20px auto;
            font-family: Arial, sans-serif;
        }
        .chart-title {
            text-align: center;
            font-size: 18px;
            font-weight: bold;
            margin-bottom: 20px;
        }
        .bar {
            height: 40px;
            margin: 10px 0;
            color: white;
            font-weight: bold;
            line-height: 40px;
            padding-left: 10px;
            border-radius: 4px;
        }
        .critical { background-color: #d9534f; }
        .high { background-color: #f0ad4e; }
        .medium { background-color: #5bc0de; }
        .low { background-color: #5cb85c; }
        .info { background-color: #777777; }
        .label {
            display: inline-block;
            width: 100px;
        }
        .count {
            float: right;
            margin-right: 10px;
        }
    </style>
</head>
<body>
    <div class="chart-container">
        <div class="chart-title">Distribuzione Vulnerabilità per Severità</div>
        <div class="bar critical"><span class="label">Critiche</span><span class="count">${critical}</span></div>
        <div class="bar high"><span class="label">Alte</span><span class="count">${high}</span></div>
        <div class="bar medium"><span class="label">Medie</span><span class="count">${medium}</span></div>
        <div class="bar low"><span class="label">Basse</span><span class="count">${low}</span></div>
        <div class="bar info"><span class="label">Info</span><span class="count">${info}</span></div>
    </div>
</body>
</html>
EOF

    # Genera PNG dal HTML
    wkhtmltoimage --width 700 "${output_dir}/vuln_chart.html" "${output_dir}/vuln_chart.png"
    
    # Crea un grafico a torta per la distribuzione dei sistemi operativi Windows
    local win_versions="${TEMP_DIR}/win_versions.txt"
    
    # Estrai versioni Windows dai file di scansione
    grep -i "windows" "$OUTPUT_DIR/nmap_results/nmap_scan.txt" | grep -oE "Windows [0-9]+|Windows Server [0-9]+|Windows [0-9]+ R2|Windows Server [0-9]+ R2" | sort | uniq -c | sort -nr > "$win_versions"
    
    # Crea un grafico HTML per le versioni Windows
    cat > "${output_dir}/os_chart.html" << EOF
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Distribuzione Sistemi Operativi</title>
    <style>
        .chart-container {
            width: 600px;
            margin: 20px auto;
            font-family: Arial, sans-serif;
        }
        .chart-title {
            text-align: center;
            font-size: 18px;
            font-weight: bold;
            margin-bottom: 20px;
        }
        .os-list {
            border: 1px solid #ddd;
            border-radius: 4px;
            padding: 15px;
        }
        .os-item {
            margin: 10px 0;
            padding: 8px;
            background-color: #f1f1f1;
            border-radius: 4px;
        }
        .os-name {
            font-weight: bold;
        }
        .os-count {
            float: right;
            background-color: #337ab7;
            color: white;
            padding: 2px 8px;
            border-radius: 10px;
        }
    </style>
</head>
<body>
    <div class="chart-container">
        <div class="chart-title">Distribuzione Sistemi Operativi Windows</div>
        <div class="os-list">
EOF

    # Aggiungi i dati delle versioni al grafico
    if [ -s "$win_versions" ]; then
        while IFS= read -r line; do
            count=$(echo "$line" | awk '{print $1}')
            os=$(echo "$line" | cut -d' ' -f2-)
            echo "<div class=\"os-item\"><span class=\"os-name\">$os</span><span class=\"os-count\">$count</span></div>" >> "${output_dir}/os_chart.html"
        done < "$win_versions"
    else
        echo "<div class=\"os-item\">Nessuna informazione sul sistema operativo disponibile</div>" >> "${output_dir}/os_chart.html"
    fi

    # Chiudi il file HTML
    cat >> "${output_dir}/os_chart.html" << EOF
        </div>
    </div>
</body>
</html>
EOF

    # Genera PNG dal HTML
    wkhtmltoimage --width 700 "${output_dir}/os_chart.html" "${output_dir}/os_chart.png"
    
    log "INFO" "Generazione grafici completata."
    return 0
}

# Funzione per generare il report finale in PDF
generate_pdf_report() {
    local target=$1
    local output_file="$PDF_OUTPUT"
    local report_md="${TEMP_DIR}/final_report.md"
    local images_dir="$OUTPUT_DIR/reports/images"
    
    log "INFO" "Generazione report PDF finale..."
    
    # Crea il report in formato Markdown
    {
        echo "---"
        echo "title: Report di Sicurezza Windows"
        echo "author: Windows Vulnerability Scanner v${VERSION}"
        echo "date: ${DATE}"
        echo "geometry: margin=2cm"
        echo "colorlinks: true"
        echo "header-includes:"
        echo "  - \\usepackage{fancyhdr}"
        echo "  - \\pagestyle{fancy}"
        echo "  - \\fancyhead[L]{Windows Security Scan}"
        echo "  - \\fancyhead[R]{${DATE}}"
        echo "  - \\fancyfoot[C]{Pagina \\thepage}"
        echo "---"
        echo
        echo "# Report di Sicurezza Windows - ${target}"
        echo
        echo "## Sommario Esecutivo"
        echo
        echo "Questa scansione di sicurezza è stata eseguita su **${target}** in data ${DATE}."
        echo "La scansione ha utilizzato strumenti avanzati come Nmap e Nuclei per identificare vulnerabilità nei sistemi Windows."
        echo
        echo "## Statistiche della Scansione"
        echo
        echo "* **Target:** ${target}"
        echo "* **Data:** ${DATE}"
        echo "* **Durata:** $(( ($(date +%s) - $(date -d "$SCAN_START_TIME" +%s)) / 60 )) minuti"
        echo
        echo "## Vulnerabilità Rilevate"
        echo
        echo "![Distribuzione Vulnerabilità](${images_dir}/vuln_chart.png)"
        echo
        echo "## Sistemi Operativi"
        echo
        echo "![Sistemi Operativi Windows](${images_dir}/os_chart.png)"
        echo
        
        # Aggiungi risultati Nuclei
        echo "## Dettagli Vulnerabilità"
        echo
        find "$OUTPUT_DIR/nuclei_results" -name "*_nuclei_scan.txt" -type f | while IFS= read -r file; do
            local host=$(basename "$file" | sed 's/_nuclei_scan.txt//')
            echo "### Host: ${host}"
            echo
            echo "\`\`\`"
            grep -A 5 "SOMMARIO VULNERABILITÀ" "$file" || echo "Nessuna vulnerabilità trovata"
            echo "\`\`\`"
            echo
        done
        
        # Aggiungi risultati CVE
        if [ -f "$OUTPUT_DIR/cve_analysis/recent_cve_analysis.txt" ]; then
            echo "## Analisi CVE"
            echo
            echo "\`\`\`"
            grep -A 10 "TOP 10 CVE WINDOWS SERVER RECENTI" "$OUTPUT_DIR/cve_analysis/recent_cve_analysis.txt"
            echo "\`\`\`"
            echo
        fi
        
        # Raccomandazioni
        echo "## Raccomandazioni"
        echo
        echo "1. **Aggiornamento Sistema:**"
        echo "   * Installare immediatamente le patch di sicurezza Microsoft"
        echo "   * Mantenere aggiornato il sistema Windows"
        echo
        echo "2. **Hardening:**"
        echo "   * Disabilitare servizi non necessari"
        echo "   * Implementare principi di minimo privilegio"
        echo "   * Rafforzare le policy di password"
        echo
        echo "3. **Monitoraggio:**"
        echo "   * Configurare logging degli eventi di sicurezza"
        echo "   * Implementare sistemi di monitoraggio attivo"
        echo
        echo "---"
        echo
        echo "*Questo report è stato generato automaticamente da Windows Vulnerability Scanner v${VERSION}*"
        
    } > "$report_md"
    
    # Genera PDF usando pandoc
    log "INFO" "Conversione Markdown in PDF..."
    pandoc "$report_md" \
           --pdf-engine=xelatex \
           --from markdown \
           --template eisvogel \
           --toc \
           --highlight-style zenburn \
           -o "$output_file"
    
    log "INFO" "Report PDF generato con successo: $output_file"
    return 0
}

# Funzione principale
main() {
    # Mostra banner
    show_banner
    
    # Registra ora di inizio
    SCAN_START_TIME=$(date '+%Y-%m-%d %H:%M:%S')
    
    # Gestisci gli argomenti
    local target=""
    local custom_output_dir=""
    
    # Controlla se ci sono abbastanza argomenti
    if [ $# -lt 1 ]; then
        show_help
        exit 1
    fi
    
    # Gestione dei parametri
    target=$1
    shift
    
    while [ $# -gt 0 ]; do
        case "$1" in
            -h|--help)
                show_help
                exit 0
                ;;
            -o|--output)
                custom_output_dir="$2"
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
                RUN_CVE_CHECK=true
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
                MAX_THREADS="$2"
                shift 2
                ;;
            *)
                echo "Opzione non riconosciuta: $1"
                show_help
                exit 1
                ;;
        esac
    done
    
    # Validazione target
    if ! validate_input "$target"; then
        log "ERROR" "Formato target non valido: $target"
        show_help
        exit 1
    fi
    
    # Verifica prerequisiti
    check_prerequisites
    
    # Preparazione directory di output
    prepare_output_dir "$target" "$custom_output_dir"
    
    # Espandi CIDR se necessario
    expand_cidr "$target"
    
    # Esegui il flusso di scansione
    if [ "$RUN_NMAP" = true ]; then
        run_nmap_scanner "$target"
    fi
    
    if [ "$RUN_NUCLEI" = true ]; then
        run_nuclei_scanner "$target"
    fi
    
    if [ "$RUN_CVE_CHECK" = true ]; then
        fetch_and_process_cve
    fi
    
    # Genera grafici per il report
    generate_charts
    
    # Registra ora di fine
    SCAN_END_TIME=$(date '+%Y-%m-%d %H:%M:%S')
    
    # Genera report finale
    generate_pdf_report "$target"
    
    # Stampa riepilogo
    echo
    echo -e "${GREEN}╔═════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║                   SCANSIONE COMPLETATA CON SUCCESSO                 ║${NC}"
    echo -e "${GREEN}╚═════════════════════════════════════════════════════════════════════╝${NC}"
    echo
    echo -e "📊 ${BLUE}Riepilogo della scansione:${NC}"
    echo -e "   ${CYAN}▪ Target:${NC} $target"
    echo -e "   ${CYAN}▪ Data:${NC} $DATE"
    echo -e "   ${CYAN}▪ Directory output:${NC} $OUTPUT_DIR"
    echo -e "   ${CYAN}▪ Report PDF:${NC} $PDF_OUTPUT"
    echo
    echo -e "🔍 ${BLUE}Per visualizzare i risultati dettagliati:${NC}"
    echo -e "   ${YELLOW}▪ Report PDF completo:${NC} $PDF_OUTPUT"
    echo -e "   ${YELLOW}▪ Report Nmap:${NC} $OUTPUT_DIR/nmap_results/"
    echo -e "   ${YELLOW}▪ Report Nuclei:${NC} $OUTPUT_DIR/nuclei_results/"
    echo -e "   ${YELLOW}▪ Analisi CVE:${NC} $OUTPUT_DIR/cve_analysis/"
    echo
    
    # Pulizia file temporanei
    if [ "$VERBOSE_MODE" = false ]; then
        log "INFO" "Pulizia file temporanei..."
        rm -rf "$TEMP_DIR"
    else
        log "INFO" "File temporanei conservati in: $TEMP_DIR"
    fi
    
    return 0
}

# Esecuzione script
main "$@"