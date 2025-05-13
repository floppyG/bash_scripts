#!/bin/bash
# SCRIPT CREATO PER SIEM eDOK Srl
# === CONFIGURAZIONE ===
# Percorsi Log Wazuh
WAZUH_LOGS_BASE_DIR="/var/ossec/logs" # Directory base per i log di Wazuh
ALERTS_SUBDIR="alerts"
ARCHIVES_SUBDIR="archives"

# Backup Locale
LOCAL_BACKUP_BASE_DIR="/opt/wazuh_fs_backups_temp" # Directory base locale per i backup
BACKUP_FILENAME_PREFIX="wazuh_logs" # Prefisso per la denominazione dei backup
KEEP_LOCAL_BACKUP_DAYS=14 # Giorni per cui conservare i backup localmente

# Share di Rete (SMB/CIFS)
REMOTE_SHARE_IP="y.y.y.y"
REMOTE_SHARE_NAME="share_name" # Nome della share
REMOTE_MOUNT_POINT="/mnt/wazuh_remote_backup"
CREDENTIALS_FILE="/etc/wazuh_backup_smb.cred" # File con username e password per la share
# Contenuto di CREDENTIALS_FILE (proteggilo con chmod 600):
# username=TUO_DOMINIO\nomeutente
# password=latuapassword
# domain=TUO_DOMINIO (opzionale)

# Configurazione Cluster
WAZUH_CONFIG="/var/ossec/etc/ossec.conf"
CLUSTER_ENABLED=false
IS_MASTER=false

# Logging
LOG_FILE="/var/log/wazuh_fs_backup.log"
MAX_LOG_SIZE_KB=10240 # 10MB - per una rotazione semplice

# === FINE CONFIGURAZIONE ===

# Esci immediatamente se un comando fallisce, tratta variabili non impostate come errori,
# e gestisci correttamente gli errori nelle pipeline.
# Rimuovi 'u' se alcune variabili potrebbero legittimamente non essere impostate in certi scenari.
set -euo pipefail

# File di lock per evitare esecuzioni multiple
LOCK_FILE="/tmp/wazuh_fs_backup.lock"

# Funzione di Logging
log_this() {
    local timestamp
    timestamp=$(date +"%Y-%m-%d %H:%M:%S")
    # Scrivi sia nel file di log che sullo standard output
    echo "[$timestamp] $1" | tee -a "$LOG_FILE"
}

# Funzione di cleanup e chiusura (viene chiamata dal trap)
cleanup_and_exit() {
    local exit_status="${1:-1}" # Default a 1 (errore) se non specificato
    log_this "Esecuzione cleanup..."
    # Smonta la share se ancora montata (best effort)
    if mount | grep -q "on ${REMOTE_MOUNT_POINT} type cifs"; then
        log_this "Tentativo di smontaggio forzato della share in cleanup..."
        # Usare -l per lazy unmount se lo smontaggio normale fallisce
        sudo umount "${REMOTE_MOUNT_POINT}" || sudo umount -l "${REMOTE_MOUNT_POINT}" || log_this "WARN: Smontaggio fallito anche in cleanup."
    fi
    # Rimuovi il file di lock
    rm -f "$LOCK_FILE"
    log_this "Script terminato con codice di uscita: $exit_status."
    # Disabilita il trap per evitare ricorsioni
    trap - INT TERM EXIT
    exit "$exit_status"
}

# Imposta il trap per chiamare cleanup_and_exit all'uscita (normale o per segnale)
# NOTA: Il trap viene impostato DOPO la definizione della funzione cleanup_and_exit
trap 'cleanup_and_exit $?' INT TERM EXIT # Passa l'exit status del comando fallito (se set -e è attivo)

# Rotazione semplice del log
rotate_log() {
    # Verifica se il file esiste ed è più grande della dimensione massima
    if [[ -f "$LOG_FILE" ]] && (($(du -k "$LOG_FILE" | cut -f1) > MAX_LOG_SIZE_KB)); then
        log_this "Rotazione del file di log..."
        mv "$LOG_FILE" "${LOG_FILE}.1" || { log_this "ERRORE: Impossibile ruotare il log."; return 1; } # Aggiunto controllo errore
        log_this "File di log ruotato in ${LOG_FILE}.1."
    fi
    return 0 # Indica successo
}

# Verifica dei comandi necessari
check_commands() {
    local missing_cmds=0
    for cmd in find date mkdir cp sudo mount umount rsync grep cut id wc tee du ps cat; do
        if ! command -v "$cmd" &> /dev/null; then
            # Logghiamo l'errore ma lasciamo che set -e termini lo script se non gestiamo l'uscita qui
            log_this "ERRORE CRITICO: Comando '$cmd' non trovato. Installalo e riprova."
            missing_cmds=1
        fi
    done
    if [[ "$missing_cmds" -eq 1 ]]; then
        # Usciamo esplicitamente per chiarezza, anche se set -e lo farebbe
        return 1 # Ritorna errore, cleanup_and_exit verrà chiamato dal trap
    fi
    log_this "Verifica comandi necessari completata."
    return 0 # Indica successo
}

# Assicura che le directory esistano
ensure_dirs() {
    log_this "Verifica e creazione directory necessarie..."
    mkdir -p "$LOCAL_BACKUP_BASE_DIR" || { log_this "ERRORE: Impossibile creare ${LOCAL_BACKUP_BASE_DIR}"; return 1; }
    if [ ! -d "$REMOTE_MOUNT_POINT" ]; then
        log_this "INFO: La directory di mount '${REMOTE_MOUNT_POINT}' non esiste. Verrà creata."
        # Usare sudo per creare la directory di mount
        sudo mkdir -p "$REMOTE_MOUNT_POINT" || { log_this "ERRORE: Impossibile creare ${REMOTE_MOUNT_POINT}. Verifica i permessi."; return 1; }
    fi
    log_this "Directory verificate/create."
    return 0 # Indica successo
}

# Determina se il nodo è master in un cluster
check_cluster_role() {
    log_this "Verifica ruolo nel cluster Wazuh..."
    # Verifica se il file di configurazione esiste
    if [[ ! -f "$WAZUH_CONFIG" ]]; then
        log_this "ATTENZIONE: File di configurazione Wazuh ($WAZUH_CONFIG) non trovato. Assumo configurazione standalone."
        # Se non c'è config, consideriamo questo nodo come un "master" standalone
        IS_MASTER=true
        CLUSTER_ENABLED=false
        return 0
    fi

    # Verifica se il clustering è abilitato (<disabled>no</disabled> dentro <cluster>)
    if grep -q "<cluster>" "$WAZUH_CONFIG" && grep -q "<disabled>no</disabled>" "$WAZUH_CONFIG"; then
        CLUSTER_ENABLED=true
        log_this "Cluster Wazuh abilitato."
        # Verifica se il nodo è master
        if grep -q "<node_type>master</node_type>" "$WAZUH_CONFIG"; then
            IS_MASTER=true
            log_this "Questo nodo è il MASTER del cluster Wazuh."
        else
            IS_MASTER=false
            log_this "Questo nodo è un WORKER nel cluster Wazuh."
        fi
    else
        CLUSTER_ENABLED=false
        IS_MASTER=true # Se non c'è cluster, consideriamo questo nodo come un "master" standalone
        log_this "Wazuh non è configurato in modalità cluster o il cluster è disabilitato. Trattato come standalone."
    fi
    return 0 # Indica successo
}

# Montaggio della share di rete
mount_remote_share() {
    log_this "Tentativo di montaggio della share di rete '\\\\${REMOTE_SHARE_IP}\\${REMOTE_SHARE_NAME}' su '${REMOTE_MOUNT_POINT}'..."
    if [ ! -f "$CREDENTIALS_FILE" ]; then
        log_this "ERRORE CRITICO: File delle credenziali '$CREDENTIALS_FILE' non trovato!"
        return 1
    fi

    # Verifica se è già montata
    if mount | grep -q "on ${REMOTE_MOUNT_POINT} type cifs"; then
        log_this "Share già montata su '${REMOTE_MOUNT_POINT}'."
        return 0
    fi

    # Verifica l'esistenza dell'utente wazuh
    if ! id "wazuh" &>/dev/null; then
        log_this "ERRORE CRITICO: L'utente o il gruppo 'wazuh' non esiste. Impossibile montare la share di rete."
        return 1
    fi

    # Monta la share usando sudo
    if sudo mount -t cifs "//${REMOTE_SHARE_IP}/${REMOTE_SHARE_NAME}" "${REMOTE_MOUNT_POINT}" \
         -o credentials="${CREDENTIALS_FILE}",vers=2.0,sec=ntlmssp,uid=$(id -u wazuh),gid=$(id -g wazuh); then
        log_this "Share di rete montata con successo."
        return 0
    else
        log_this "ERRORE: Montaggio della share di rete fallito. Controlla i log di sistema (dmesg, /var/log/syslog) e le credenziali."
        return 1
    fi
}

# Smontaggio della share di rete
umount_remote_share() {
    log_this "Tentativo di smontaggio della share '${REMOTE_MOUNT_POINT}'..."
    # Verifica se è montata prima di tentare lo smontaggio
    if mount | grep -q "on ${REMOTE_MOUNT_POINT} type cifs"; then
        sudo umount "${REMOTE_MOUNT_POINT}" \
            || { log_this "ERRORE: Smontaggio della share di rete fallito. Potrebbe essere in uso. Output: $(sudo umount "${REMOTE_MOUNT_POINT}" 2>&1)"; return 1; }
        log_this "Share di rete smontata con successo."
    else
        log_this "Share '${REMOTE_MOUNT_POINT}' non era montata."
    fi
    return 0 # Successo (anche se non era montata)
}

# Funzione per determinare i mesi da elaborare
get_months_to_process() {
    local current_year current_month_num current_month_abbr
    current_year=$(date +%Y)
    current_month_num=$(date +%m) # Teniamo il numero per il calcolo

    # Forza l'abbreviazione inglese del mese corrente (es. May)
    current_month_abbr=$(LC_TIME=C date +%b)

    local previous_year previous_month_abbr
    # Calcola l'anno e l'abbreviazione inglese del mese precedente (es. Apr)
    # Usiamo il numero del mese corrente per il calcolo della data del mese precedente
    previous_year=$(LC_TIME=C date -d "$current_year-$current_month_num-01 -1 month" +%Y)
    previous_month_abbr=$(LC_TIME=C date -d "$current_year-$current_month_num-01 -1 month" +%b)

    # Output: AnnoCorrente AbbrCorrente AnnoPrecedente AbbrPrecedente
    echo "$current_year $current_month_abbr $previous_year $previous_month_abbr"
}

# Copia i file compressi: implementa logica incrementale per mese (CORRETTA per .json.sum)
copy_compressed_files() {
    local source_dir="$1"
    local dest_dir="$2"
    # Essere più specifici sul pattern dei log compressi
    local gz_pattern="*.log.gz"
    local sum_pattern_suffix=".json.sum" # Suffisso corretto per i checksum

    log_this "Processando copia incrementale da '$source_dir' a '$dest_dir' (cercando '${gz_pattern}' e '${sum_pattern_suffix}')..."

    # 1. Controlli preliminari
    if [[ ! -d "$source_dir" ]]; then
        log_this "INFO: Directory sorgente '$source_dir' non trovata. Salto."
        return 0
    fi
    # Trova i file sorgente .log.gz
    local source_gz_files=()
    mapfile -t source_gz_files < <(find "$source_dir" -maxdepth 1 -name "$gz_pattern" -type f -printf "%f\n" | sort -r)

    if [[ ${#source_gz_files[@]} -eq 0 ]]; then
        log_this "INFO: Nessun file '$gz_pattern' trovato in '$source_dir'. Salto."
        return 0
    fi
    local latest_source_gz_file="${source_gz_files[0]}" # Il più recente è il primo dopo sort -r

    mkdir -p "$dest_dir" || { log_this "ERRORE: Impossibile creare directory destinazione '$dest_dir'"; return 1; }

    # 2. Controlla la destinazione
    local dest_gz_files=()
    mapfile -t dest_gz_files < <(find "$dest_dir" -maxdepth 1 -name "$gz_pattern" -type f -printf "%f\n" | sort -r)

    # 3. Decidi se fare copia completa o incrementale
    if [[ ${#dest_gz_files[@]} -eq 0 ]]; then
        # --- Copia Completa (Destinazione vuota) ---
        log_this "INFO: Destinazione '$dest_dir' vuota per '$gz_pattern'. Avvio copia completa."
        # Modificato per includere specificamente *.log.gz e *.json.sum
        log_this "Avvio rsync completo per '$gz_pattern' e '*${sum_pattern_suffix}' da '$source_dir/' a '$dest_dir/'..."
        if rsync -aq --info=progress2 "$source_dir/" "$dest_dir/" --include='*.log.gz' --include="*${sum_pattern_suffix}" --exclude='*' >> "$LOG_FILE" 2>&1; then
            log_this "rsync completo da '$source_dir' a '$dest_dir' completato."
            return 0
        else
            log_this "ERRORE durante rsync completo da '$source_dir' a '$dest_dir'."
            return 1
        fi
    else
        # --- Copia Incrementale (Destinazione contiene già file) ---
        local latest_dest_gz_file="${dest_gz_files[0]}" # Il più recente in destinazione
        log_this "INFO: Destinazione '$dest_dir' contiene file. Sorgente più recente: '$latest_source_gz_file'. Destinazione più recente: '$latest_dest_gz_file'."

        if [[ "$latest_source_gz_file" > "$latest_dest_gz_file" ]]; then
            log_this "INFO: Trovato file più recente ('$latest_source_gz_file') in sorgente. Avvio copia singola..."
            local latest_source_gz_path="$source_dir/$latest_source_gz_file"

            # CORREZIONE: Deriva il nome base corretto per cercare il .json.sum
            # Rimuove .log.gz per ottenere il nome base (es. alerts-YYYY-MM-DD)
            local base_name_for_sum="${latest_source_gz_file%.log.gz}"
            # Costruisce il percorso del file .json.sum corrispondente
            local correct_source_sum_path="$source_dir/${base_name_for_sum}${sum_pattern_suffix}"
            local correct_sum_filename="${base_name_for_sum}${sum_pattern_suffix}" # Solo nome file per log

            # Copia il file .log.gz più recente
            if rsync -aq --info=progress2 "$latest_source_gz_path" "$dest_dir/" >> "$LOG_FILE" 2>&1; then
                log_this "Copia di '$latest_source_gz_file' completata."
                # Copia il file .json.sum corrispondente, se esiste
                if [[ -f "$correct_source_sum_path" ]]; then
                    if rsync -aq "$correct_source_sum_path" "$dest_dir/" >> "$LOG_FILE" 2>&1; then
                         log_this "Copiato anche il file checksum corrispondente: '${correct_sum_filename}'."
                    else
                         log_this "ATTENZIONE: Errore durante la copia del file checksum '$correct_source_sum_path'."
                         # return 1 # Decidi se è errore fatale
                    fi
                else
                    # Log aggiornato per indicare che cercava il .json.sum
                    log_this "INFO: Nessun file checksum ('${correct_sum_filename}') trovato per '$latest_source_gz_file'."
                fi
                return 0 # Successo copia incrementale
            else
                log_this "ERRORE durante la copia del file più recente '$latest_source_gz_file'."
                return 1
            fi
        else
            log_this "INFO: Nessun file più recente trovato in '$source_dir' rispetto a '$dest_dir'. Nessuna copia necessaria."
            return 0 # Successo, nessuna operazione necessaria
        fi
    fi
}

# Verifica integrità dei file copiati confrontando i file sum (se presenti)
verify_file_integrity() {
    local source_dir="$1"
    local dest_dir="$2"
    local file_pattern="$3" # Deve essere il pattern dei file log (es. *.log) non gz

    local log_pattern_base="${file_pattern%.log}" # Rimuove .log se presente
    local sum_pattern="${log_pattern_base}.sum"  # Pattern per i file .sum

    log_this "Verifica integrità (file .sum) per pattern '$sum_pattern' in '$source_dir' vs '$dest_dir'..."

    local sum_files
    mapfile -t sum_files < <(find "$source_dir" -maxdepth 1 -name "$sum_pattern" -type f)

    if [[ ${#sum_files[@]} -eq 0 ]]; then
        log_this "Nessun file .sum trovato in '$source_dir' con pattern '$sum_pattern'. Integrità non verificabile tramite .sum."
        return 0 # Non un errore, solo non verificabile
    fi

    log_this "Trovati ${#sum_files[@]} file .sum per la verifica."
    local error_count=0

    for sum_file_path in "${sum_files[@]}"; do
        local sum_filename
        sum_filename=$(basename "$sum_file_path")
        local log_gz_filename="${sum_filename%.sum}.gz" # Assumiamo che il log sia compresso in .gz
        local dest_log_gz_path="$dest_dir/$log_gz_filename"
        local dest_sum_path="$dest_dir/$sum_filename"

        # 1. Verifica se il file .gz corrispondente esiste nella destinazione
        if [[ ! -f "$dest_log_gz_path" ]]; then
            log_this "ERRORE VERIFICA: File log '$log_gz_filename' non trovato nella destinazione '$dest_dir'!"
            error_count=$((error_count + 1))
            continue # Passa al prossimo file .sum
        fi

        # 2. Copia il file .sum nella destinazione per riferimento futuro
        if ! cp "$sum_file_path" "$dest_sum_path"; then
            log_this "ERRORE VERIFICA: Impossibile copiare il file sum '$sum_filename' in '$dest_dir'."
            # Potrebbe essere un problema di permessi, non necessariamente di integrità del log
            # Decidi se considerarlo un errore fatale per la verifica
            # error_count=$((error_count + 1)) # Commentato: non blocca se solo il .sum non si copia
        else
             log_this "File .sum '$sum_filename' copiato in '$dest_dir'."
        fi

        # 3. Qui potresti aggiungere un controllo effettivo del checksum se necessario
        #     decomprimendo il file .gz e confrontando con il .sum, ma è intensivo.
        #    Per ora, ci limitiamo a verificare la presenza e copiare il .sum.

    done

    if [[ $error_count -eq 0 ]]; then
        log_this "Verifica integrità (presenza file .gz e copia .sum) completata con successo."
        return 0 # Successo
    else
        log_this "ERRORE: $error_count problemi riscontrati durante la verifica dell'integrità."
        return 1 # Errore
    fi
}


# Trasferimento dei backup sulla share (MODIFICATA - rimossa verify_file_integrity)
transfer_backups_to_share() {
    local overall_result=0 # 0 = successo, 1 = fallimento

    # Ottieni i mesi da elaborare (anno e abbreviazione mese)
    local current_year current_month_abbr previous_year previous_month_abbr
    read -r current_year current_month_abbr previous_year previous_month_abbr < <(get_months_to_process)
    log_this "Elaborazione backup per Mese Corrente: $current_year-$current_month_abbr e Mese Precedente: $previous_year-$previous_month_abbr"

    # Pattern per i file compressi (.gz)
    local gz_pattern="*.gz"
    # Nota: i pattern per .sum non servono più qui, gestiti in copy_compressed_files

    # Array delle directory da processare [TYPE, YEAR, MONTH_ABBR, SRC_SUBDIR]
    local dirs_to_process=(
        "current $current_year $current_month_abbr $ALERTS_SUBDIR"
        "current $current_year $current_month_abbr $ARCHIVES_SUBDIR"
        "previous $previous_year $previous_month_abbr $ALERTS_SUBDIR"
        "previous $previous_year $previous_month_abbr $ARCHIVES_SUBDIR"
    )

    # --- Fase 1: Copia (ora incrementale) da Wazuh Logs a Backup Locale ---
    log_this "--- FASE 1: Copia Incrementale da Wazuh Logs a Backup Locale ($LOCAL_BACKUP_BASE_DIR) ---"
    for dir_info in "${dirs_to_process[@]}"; do
        local type year month_abbr subdir
        read -r type year month_abbr subdir <<< "$dir_info"

        local source_dir="$WAZUH_LOGS_BASE_DIR/$subdir/$year/$month_abbr"
        local local_dest_dir="$LOCAL_BACKUP_BASE_DIR/$year/$month_abbr/$subdir"

        # Chiama la nuova funzione di copia incrementale
        if ! copy_compressed_files "$source_dir" "$local_dest_dir"; then # Non serve più passare gz_pattern
            log_this "ATTENZIONE: Problema durante la copia incrementale da '$source_dir'. Controllo log."
            # Potresti voler impostare overall_result=1 qui se la copia fallisce
            # overall_result=1
        fi
        # RIMOSSA chiamata a verify_file_integrity
    done
    log_this "--- FASE 1: Completata. ---"

    # --- Fase 2: Copia da Backup Locale a Share Remota ---
    # Questa fase rimane invariata: rsync sincronizzerà lo stato della cache locale
    # (che ora contiene i file giusti grazie alla Fase 1) sulla share remota.
    log_this "--- FASE 2: Trasferimento da Backup Locale a Share Remota ($REMOTE_MOUNT_POINT) ---"
    if mount | grep -q "on ${REMOTE_MOUNT_POINT} type cifs"; then
        log_this "Avvio rsync da '$LOCAL_BACKUP_BASE_DIR/' a '$REMOTE_MOUNT_POINT/'..."
        if rsync -a --info=progress2 --no-inc-recursive "$LOCAL_BACKUP_BASE_DIR"/ "$REMOTE_MOUNT_POINT"/ >> "$LOG_FILE" 2>&1; then
            log_this "Trasferimento alla share remota completato con successo."
        else
            log_this "ERRORE durante il trasferimento (rsync) da '$LOCAL_BACKUP_BASE_DIR' alla share remota '$REMOTE_MOUNT_POINT'."
            overall_result=1 # Errore nel trasferimento remoto
        fi
    else
        log_this "ERRORE CRITICO: Share remota non montata. Impossibile trasferire i backup dalla cache locale."
        overall_result=1 # Errore, share non montata
    fi
    log_this "--- FASE 2: Completata. ---"

    return $overall_result # Ritorna 0 se tutto OK, 1 se ci sono stati errori
}

# Pulizia vecchi backup locali
cleanup_local_backups() {
    log_this "Pulizia vecchi backup locali in '$LOCAL_BACKUP_BASE_DIR' (più vecchi di $KEEP_LOCAL_BACKUP_DAYS giorni)..."

    local old_files_count
    # Trova e conta i file più vecchi
    old_files_count=$(find "$LOCAL_BACKUP_BASE_DIR" -type f -mtime "+$KEEP_LOCAL_BACKUP_DAYS" -print | wc -l)

    if [[ "$old_files_count" -eq 0 ]]; then
        log_this "Nessun backup locale più vecchio di $KEEP_LOCAL_BACKUP_DAYS giorni trovato da eliminare."
        return 0 # Successo, niente da fare
    fi

    log_this "Trovati $old_files_count file da eliminare (più vecchi di $KEEP_LOCAL_BACKUP_DAYS giorni)."

    # Elimina i file trovati
    # Aggiungere -depth per eliminare prima i file e poi le directory vuote
    if find "$LOCAL_BACKUP_BASE_DIR" -type f -mtime "+$KEEP_LOCAL_BACKUP_DAYS" -delete; then
        log_this "Eliminazione file completata."
        # Rimuovi anche le directory diventate vuote dopo l'eliminazione
        log_this "Rimozione directory vuote..."
        # Usare -depth per assicurarsi che le directory siano processate dopo il loro contenuto
        find "$LOCAL_BACKUP_BASE_DIR" -mindepth 1 -type d -empty -delete || log_this "ATTENZIONE: Potrebbero essere rimaste directory vuote (normale se la base non è vuota)."
        log_this "Pulizia vecchi backup locali completata."
        return 0 # Successo
    else
        log_this "ERRORE durante l'eliminazione dei vecchi backup locali."
        return 1 # Errore
    fi
}

# === SCRIPT PRINCIPALE ===

# Verifica se un'altra istanza è già in esecuzione
# Usare flock per un lock più robusto se disponibile, altrimenti il PID file è un buon inizio
if [ -e "$LOCK_FILE" ] && ps -p "$(cat "$LOCK_FILE")" > /dev/null ; then
    log_this "Script di backup già in esecuzione (PID $(cat "$LOCK_FILE")). Uscita."
    exit 1 # Esce senza chiamare cleanup perché non è questa istanza a dover pulire
fi
# Scrive il PID corrente nel file di lock
echo $$ > "$LOCK_FILE"

# Inizio effettivo dello script
log_this "--- INIZIO SCRIPT BACKUP FILE SYSTEM WAZUH ---"

# Esegui le operazioni preliminari
rotate_log || log_this "Attenzione: Rotazione log fallita." # Non blocca l'esecuzione
check_commands || cleanup_and_exit 1 # Esce se i comandi mancano
ensure_dirs || cleanup_and_exit 1    # Esce se le directory non possono essere create

# Controlla il ruolo nel cluster
check_cluster_role || cleanup_and_exit 1 # Esce se il controllo fallisce

# Verifica se questo nodo deve eseguire il backup
if [[ "$CLUSTER_ENABLED" == true ]] && [[ "$IS_MASTER" == false ]]; then
    log_this "Questo è un nodo worker. Il backup dei log viene eseguito solo sul nodo master. Uscita."
    # Uscita normale (0), non è un errore
    cleanup_and_exit 0
fi

# --- Procedura di Backup ---
backup_success=true # Flag per tracciare il successo generale

# Monta la share di rete
if ! mount_remote_share; then
    log_this "ERRORE CRITICO: Impossibile montare la share di rete. Backup non può essere trasferito alla destinazione remota."
    # Decidi se continuare solo con il backup locale o uscire
    # Per ora usciamo, ma si potrebbe modificare per fare solo copia locale
    backup_success=false
    # Non smontiamo qui, il trap gestirà lo smontaggio se necessario
else
    # Trasferisci i backup (copia locale -> copia remota)
    if ! transfer_backups_to_share; then
        log_this "ERRORE: Si sono verificati problemi durante il trasferimento dei backup."
        backup_success=false
    else
        log_this "Backup e trasferimento completati con successo."
    fi

    # Smonta la share di rete alla fine delle operazioni
    if ! umount_remote_share; then
        log_this "ATTENZIONE: Smontaggio della share fallito alla fine delle operazioni."
        # Non consideriamo questo un errore fatale per il backup stesso
        # backup_success=false # Decommenta se uno smontaggio fallito deve essere considerato errore
    fi
fi

# Pulizia vecchi backup locali (eseguita indipendentemente dal successo del trasferimento remoto)
if ! cleanup_local_backups; then
    log_this "ATTENZIONE: Pulizia dei vecchi backup locali fallita."
    # Non consideriamo questo un errore fatale per il backup corrente
    # backup_success=false # Decommenta se la pulizia fallita deve essere considerata errore
fi

log_this "--- FINE SCRIPT BACKUP FILE SYSTEM WAZUH ---"

# Uscita finale basata sul successo generale
if [[ "$backup_success" == true ]]; then
    cleanup_and_exit 0 # Successo
else
    cleanup_and_exit 1 # Errore
fi

# La fine del file è qui. Nessun codice dopo l'ultima chiamata a cleanup_and_exit
