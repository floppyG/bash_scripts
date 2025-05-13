📦 Wazuh Log Backup Script (wazuh_fs_backup.sh)
📋 Description

This Bash script performs incremental and safe backups of compressed Wazuh log files from a local server to a remote SMB/CIFS share, with verification options and local copy handling. It supports both standalone and clustered Wazuh environments.
🛠️ Features

    Incremental and/or full backup of .log.gz and .json.sum files

    Cluster support: backup is only performed by the master node

    Auto mount/unmount of remote SMB/CIFS share

    Detailed logging with log rotation

    Lock file to prevent concurrent runs

    Temporary local backup with configurable retention

📁 Directory Structure
Type	Path
Wazuh Log Directories	/var/ossec/logs/alerts, /archives
Local Backup Directory	/opt/wazuh_fs_backups_temp
Remote Share Mount Point	/mnt/wazuh_remote_backup
Wazuh Config File	/var/ossec/etc/ossec.conf
SMB Credentials File	/etc/wazuh_backup_smb.cred
⚙️ Configuration (Key Parameters)

All key variables are defined in the # === CONFIGURATION === section of the script. Important ones include:
Variable	Description
WAZUH_LOGS_BASE_DIR	Base directory of Wazuh logs
LOCAL_BACKUP_BASE_DIR	Local temporary backup directory
REMOTE_SHARE_IP	IP address of remote SMB server
REMOTE_SHARE_NAME	Name of the share (e.g., "Costantino")
REMOTE_MOUNT_POINT	Local mount point for remote share
CREDENTIALS_FILE	Path to file with SMB credentials
KEEP_LOCAL_BACKUP_DAYS	Number of days to retain local backups
LOG_FILE	Path to script log file
MAX_LOG_SIZE_KB	Max log size in KB before rotating
📄 SMB Credentials File Example (/etc/wazuh_backup_smb.cred)

username=DOMAIN\\user
password=YourPassword
domain=DOMAIN  # optional

    Security Tip: Ensure the credentials file has strict permissions:

chmod 600 /etc/wazuh_backup_smb.cred

🧪 Advanced Functionality
✅ Cluster Role Detection

    The script checks ossec.conf to determine if the node is part of a cluster.

    If clustered, only the master node performs backups.

🔐 Security

    Credentials file is not hardcoded. It's read securely and passed to mount.cifs.

▶️ Execution

Run the script manually:

sudo /path/to/wazuh_fs_backup.sh

Or schedule it with cron, for example:

0 3 * * * /path/to/wazuh_fs_backup.sh >> /var/log/cron.log 2>&1

🧹 Cleanup

    Local backups older than KEEP_LOCAL_BACKUP_DAYS are automatically deleted.

    Share is unmounted even if the script exits early (trap handler included).

📦 Backed-Up Content

    Compressed Wazuh logs: *.log.gz

    Associated checksums: *.json.sum

    Separate backup of:

        alerts logs

        archives logs

    Only logs from the current and previous month are processed.

🚨 Logging & Diagnostics

The main log file:

/var/log/wazuh_fs_backup.log

Includes:

    All executed actions

    rsync output

    Errors

Log rotation is automatic when the log exceeds MAX_LOG_SIZE_KB (default: 10MB).
⚠️ Requirements

Make sure the following commands are available on your system:

find, date, mkdir, cp, sudo, mount, umount, rsync, grep, cut, id, wc, tee, du, ps, cat

📤 Sample Output

[2025-05-13 03:00:00] Checking Wazuh cluster role...
[2025-05-13 03:00:01] This node is the MASTER in the Wazuh cluster.
[2025-05-13 03:00:02] Mounting network share...
[2025-05-13 03:00:05] Share mounted successfully.
[2025-05-13 03:00:06] Copying logs from current and previous month completed.
[2025-05-13 03:00:07] Share unmounted.
[2025-05-13 03:00:08] Script exited with code: 0.

📌 Final Notes

    Designed for robustness in production environments.

    Can be extended to include:

        Checksum validation

        Cloud uploads

        Archive compression

        Email notifications
