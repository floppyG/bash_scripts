🛡️ Windows Vulnerability Scanner Unified - Technical Summary

Version: 1.0.0
Author: Unified version of Windows scanning scripts
Date: April 16, 2025
Purpose:
A comprehensive automated scanner for identifying vulnerabilities in Windows systems. It integrates multiple security tools (Nmap, Nikto, Nuclei) and combines their outputs with CVE intelligence, producing a final PDF report. It supports scanning single IP addresses or entire CIDR subnets (e.g., 192.168.0.1/24).
🔧 Key Features and Functional Components
1. Error Handling & Output Formatting

    Enables strict pipe failure detection (set -o pipefail) but allows continuation on non-zero exit codes (set +e).

    Defines ANSI color codes for enhanced CLI output formatting.

2. Global Variables & Paths

    Creates a temporary directory for storing intermediate scan data.

    Sets variables for:

        Output folder and PDF report path.

        Target (IP address or CIDR block).

        CVE database download and filtering.

        Scan start/end timestamps.

3. Control Flags

    Toggles execution of major modules:

        RUN_NMAP, RUN_NUCLEI, RUN_CVE_CHECK.

    Optional focus on Windows servers: FOCUS_SERVER.

    Verbose and thorough scan modes are controlled with VERBOSE_MODE and THOROUGH_SCAN.

4. CVE Intelligence Integration

    Downloads the MITRE CVE database (allitems.csv).

    Filters for Windows-specific CVEs, focusing on recent entries (past 365 days).

    Stores and parses relevant CVEs for post-scan matching.

5. Scanner Modules (from further inspection):

    Nmap: Performs port scanning and service/version detection.

    Nikto: (Usually for web server vulnerabilities) optionally integrated.

    Nuclei: Runs custom templates for known CVEs and misconfigurations.

    Results are likely cross-referenced with the CVE list to highlight known issues.

6. User Interface

    Displays a banner showing the script version and purpose.

    Accepts command-line arguments (not shown yet but likely parsed later).

    May include progress feedback and colored output.

7. Report Generation

    Intermediate results are consolidated.

    Final output is a PDF report summarizing findings.

-----------------------------


🔧 Key Functional Highlights
1. Execution Settings

    Uses set -o pipefail to ensure error propagation through piped commands.

    Keeps execution resilient to individual command failures (set +e).

2. Console Output Styling

    ANSI color codes (RED, GREEN, BLUE, etc.) are predefined to visually enhance CLI messages.

3. Global Variables

    Versioning & Paths:

        VERSION, DATE, and SCRIPT_PATH help track and log execution metadata.

        TEMP_DIR holds temporary working data (unique per run).

    Report Output:

        Outputs are saved to a path defined by HTML_OUTPUT.

    Target Handling:

        Accepts single IPs or entire subnets (CIDR notation like 192.168.0.1/24).

    CVE Database Integration:

        Downloads the full CVE list from MITRE (allitems.csv).

        Extracts Windows-specific CVEs from it, focusing on vulnerabilities reported in the last year (CVE_RECENT_THRESHOLD=365).

4. Control Flags

    Enable/disable major scan components:

        RUN_NMAP, RUN_NUCLEI, RUN_CVE_CHECK.

    Target-specific behavior:

        FOCUS_SERVER narrows scanning logic to Windows Server systems.

    Logging and verbosity:

        VERBOSE_MODE enables more detailed output.

        THOROUGH_SCAN likely activates deep scanning modes.

    MAX_THREADS controls concurrency (probably used by nuclei or parallel CVE checks).

5. HTML Report Generation

    Unlike the previous version, this script outputs an HTML-formatted vulnerability report, likely designed for easier sharing or integration with dashboards.

6. Banner Output

    Presents an informational banner at runtime, detailing the tool’s capabilities.
