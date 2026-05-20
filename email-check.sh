#!/bin/bash

# =========================
# Email DNS Assessment Tool (v1)
#
# Author: Charalampos Spanias (mollysec)
# Date: 2026-05-20
#
# Notes:
# This script was developed with AI-assisted coding (M365 Copilot)
# for use in email configuration assessments.
# =========================

OUTPUT_FILE="email_check_$(date +%F_%H-%M-%S).log"

GREEN="\033[0;32m"
RED="\033[0;31m"
YELLOW="\033[1;33m"
NC="\033[0m"

SPOOF=false
TARGET_EMAIL=""

# -------------------------
# Usage
# -------------------------
usage() {
    echo "Usage:"
    echo "  $0 <domain>"
    echo "  $0 <file_with_domains>"
    echo "  $0 <domain> --spoof --to <email>"
    echo
    echo "Examples:"
    echo "  $0 example.com"
    echo "  $0 domains.txt"
    echo "  $0 example.com --spoof --to user@lab.local"
    exit 1
}

# -------------------------
# Domain validation
# -------------------------
valid_domain() {
    [[ "$1" =~ ^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]
}

# -------------------------
# Spoofing
# -------------------------
send_spoof() {
    DOMAIN=$1

    if [[ -z "$TARGET_EMAIL" ]]; then
        echo -e "${RED}[-] Spoofing requires --to <email>${NC}" | tee -a "$OUTPUT_FILE"
        return
    fi

    echo -e "\n${YELLOW}[Spoofing Test]${NC}" | tee -a "$OUTPUT_FILE"
    echo "[*] Spoofing as ceo@$DOMAIN → $TARGET_EMAIL" | tee -a "$OUTPUT_FILE"

    if ! systemctl is-active --quiet postfix; then
        echo "[*] Starting postfix..." | tee -a "$OUTPUT_FILE"
        sudo systemctl start postfix
    fi

    swaks --to "$TARGET_EMAIL" \
          --from "ceo@$DOMAIN" \
          --server localhost \
          --header "Subject: Spoof test - $DOMAIN" \
          --body "This is a spoofing test for $DOMAIN." \
          >> "$OUTPUT_FILE" 2>&1

    echo "[+] Spoof attempt sent (check mailbox)" | tee -a "$OUTPUT_FILE"
}

# -------------------------
# Domain processing
# -------------------------
process_domain() {
    DOMAIN=$1

    echo -e "\n==============================" | tee -a "$OUTPUT_FILE"
    echo "[*] Domain: $DOMAIN" | tee -a "$OUTPUT_FILE"
    echo "==============================" | tee -a "$OUTPUT_FILE"

    # SPF
    echo -e "\n${YELLOW}[SPF]${NC}" | tee -a "$OUTPUT_FILE"
    SPF=$(dig +short "$DOMAIN" TXT | grep '^"v=spf1')

    if [[ -n "$SPF" ]]; then
        echo -e "${GREEN}$SPF${NC}" | tee -a "$OUTPUT_FILE"
    else
        echo -e "${RED}No SPF record found${NC}" | tee -a "$OUTPUT_FILE"
    fi

    # DMARC
    echo -e "\n${YELLOW}[DMARC]${NC}" | tee -a "$OUTPUT_FILE"
    DMARC=$(dig +short "_dmarc.$DOMAIN" TXT)

    if [[ -n "$DMARC" ]]; then
        echo -e "${GREEN}$DMARC${NC}" | tee -a "$OUTPUT_FILE"
    else
        echo -e "${RED}No DMARC record found${NC}" | tee -a "$OUTPUT_FILE"
    fi

    # MTA-STS
    echo -e "\n${YELLOW}[MTA-STS DNS]${NC}" | tee -a "$OUTPUT_FILE"
    MTASTS=$(dig +short "_mta-sts.$DOMAIN" TXT)

    if [[ -n "$MTASTS" ]]; then
        echo -e "${GREEN}$MTASTS${NC}" | tee -a "$OUTPUT_FILE"

        echo -e "\n${YELLOW}[MTA-STS POLICY]${NC}" | tee -a "$OUTPUT_FILE"
        curl -s --max-time 5 "https://mta-sts.$DOMAIN/.well-known/mta-sts.txt" | tee -a "$OUTPUT_FILE"
    else
        echo -e "${RED}No MTA-STS record found${NC}" | tee -a "$OUTPUT_FILE"
    fi

    # -------------------------
    # Quick Assessment
    # -------------------------
    echo -e "\n${YELLOW}[Quick Assessment]${NC}" | tee -a "$OUTPUT_FILE"

    SPF_STRICT=false

    if [[ -n "$SPF" ]]; then
        if [[ "$SPF" == *"~all"* ]]; then
            echo -e "${RED}SPF softfail (~all)${NC}" | tee -a "$OUTPUT_FILE"
        fi
        if [[ "$SPF" == *"-all"* ]]; then
            echo -e "${GREEN}SPF strict (-all)${NC}" | tee -a "$OUTPUT_FILE"
            SPF_STRICT=true
        fi
    else
        echo -e "${RED}No SPF configured${NC}" | tee -a "$OUTPUT_FILE"
    fi

    DMARC_POLICY="none"

    if [[ -n "$DMARC" ]]; then
        [[ "$DMARC" == *"p=none"* ]] && DMARC_POLICY="none"
        [[ "$DMARC" == *"p=quarantine"* ]] && DMARC_POLICY="quarantine"
        [[ "$DMARC" == *"p=reject"* ]] && DMARC_POLICY="reject"

        echo -e "${GREEN}DMARC policy: $DMARC_POLICY${NC}" | tee -a "$OUTPUT_FILE"
    else
        echo -e "${RED}No DMARC configured${NC}" | tee -a "$OUTPUT_FILE"
        DMARC_POLICY="missing"
    fi

    # -------------------------
    # Alignment Assessment
    # -------------------------
    echo -e "\n${YELLOW}[Alignment Assessment]${NC}" | tee -a "$OUTPUT_FILE"

    if [[ "$DMARC_POLICY" == "reject" && "$SPF_STRICT" == true ]]; then
        echo -e "${GREEN}Strong alignment posture${NC}" | tee -a "$OUTPUT_FILE"
    elif [[ "$DMARC_POLICY" == "reject" ]]; then
        echo -e "${YELLOW}DMARC strong but SPF weak${NC}" | tee -a "$OUTPUT_FILE"
    elif [[ "$DMARC_POLICY" == "quarantine" ]]; then
        echo -e "${YELLOW}Moderate protection${NC}" | tee -a "$OUTPUT_FILE"
    else
        echo -e "${RED}Weak / no enforcement (spoofing likely)${NC}" | tee -a "$OUTPUT_FILE"
    fi

    # -------------------------
    # Spoofing
    # -------------------------
    if [[ "$SPOOF" == true ]]; then
        send_spoof "$DOMAIN"
    fi
}

# -------------------------
# Argument Parsing
# -------------------------
if [[ $# -eq 0 ]]; then
    usage
fi

INPUT=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --spoof)
            SPOOF=true
            shift
            ;;
        --to)
            TARGET_EMAIL="$2"
            shift 2
            ;;
        *)
            INPUT="$1"
            shift
            ;;
    esac
done

# Safety check
if [[ "$SPOOF" == true && -z "$TARGET_EMAIL" ]]; then
    echo "[-] --spoof requires --to <email>"
    exit 1
fi

# -------------------------
# Execution
# -------------------------
if [[ -f "$INPUT" ]]; then
    while read -r domain; do
        [[ -z "$domain" ]] && continue
        valid_domain "$domain" && process_domain "$domain"
    done < "$INPUT"
else
    valid_domain "$INPUT" || usage
    process_domain "$INPUT"
fi

echo -e "\n[+] Results saved to: $OUTPUT_FILE"
