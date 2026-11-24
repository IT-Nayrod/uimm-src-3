#!/usr/bin/env bash
#
# prerequis-tp4.sh
# Verifie que la VM est prete a recevoir le SIEM Wazuh (TP4).
# A lancer en root : sudo bash prerequis-tp4.sh
#
set -uo pipefail

if [[ $EUID -ne 0 ]]; then
  echo "Lance ce script en root : sudo bash prerequis-tp4.sh" >&2
  exit 1
fi

GREEN=$'\e[32m'; RED=$'\e[31m'; YELLOW=$'\e[33m'; BOLD=$'\e[1m'; NC=$'\e[0m'
ko=0

ok()   { printf "%s[ OK  ]%s %s\n" "$GREEN" "$NC" "$1"; }
bad()  { printf "%s[ KO  ]%s %s\n" "$RED" "$NC" "$1"; [[ -n "${2:-}" ]] && printf "        -> %s\n" "$2"; ko=$((ko + 1)); }
info() { printf "%s[INFO ]%s %s\n" "$YELLOW" "$NC" "$1"; [[ -n "${2:-}" ]] && printf "        -> %s\n" "$2"; }

TPUSER="${SUDO_USER:-root}"
TPHOME="$(getent passwd "$TPUSER" | cut -d: -f6)"
[[ -z "$TPHOME" ]] && TPHOME=/root
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TP3_DIR="$(cd "$SCRIPT_DIR/../tp3-supervision" 2>/dev/null && pwd || echo "$SCRIPT_DIR/../tp3-supervision")"

WAZUH_INSTALLED=0
[[ -d /var/ossec ]] && WAZUH_INSTALLED=1

echo "${BOLD}=== Prerequis du TP4 : SIEM Wazuh ===${NC}"

# 1. Systeme
# shellcheck disable=SC1091
. /etc/os-release 2>/dev/null || true
case "${ID:-}-${VERSION_ID:-}" in
  ubuntu-22.04|ubuntu-24.04) ok "Systeme : ${PRETTY_NAME}" ;;
  *) bad "Systeme non prevu : ${PRETTY_NAME:-inconnu}" "Le TP est prevu pour Ubuntu Server 22.04 ou 24.04 LTS." ;;
esac

# 2. Memoire (l'installeur Wazuh exige au moins 3700 Mo visibles)
ram_mb=$(free -m | awk 'FNR == 2 {print $2}')
if (( ram_mb >= 7500 )); then
  ok "Memoire : ${ram_mb} Mo"
elif (( ram_mb >= 3700 )); then
  ok "Memoire : ${ram_mb} Mo"
  info "Moins de 8 Go de RAM" "Tu desactiveras la detection de vulnerabilites juste apres l'installation (Partie 1)."
else
  bad "Memoire : ${ram_mb} Mo, insuffisant" "Eteins la VM et donne-lui 8 Go de RAM (4 Go minimum), puis relance ce script."
fi

# 3. Processeurs
cpus=$(nproc)
if (( cpus >= 2 )); then
  ok "Processeurs : ${cpus} vCPU"
else
  bad "Processeurs : ${cpus} vCPU, insuffisant" "Eteins la VM et donne-lui 4 vCPU (2 minimum), puis relance ce script."
fi

# 4. Espace disque
free_gb=$(df -BG --output=avail / | tail -1 | tr -dc '0-9')
if (( free_gb >= 10 )); then
  ok "Espace libre sur / : ${free_gb} Go"
else
  vg_free=$(vgs --noheadings --units g --nosuffix -o vg_free 2>/dev/null | head -1 | tr -d ' ' | cut -d. -f1)
  root_src=$(findmnt -n -o SOURCE /)
  if [[ -n "${vg_free:-}" ]] && (( vg_free >= 1 )); then
    bad "Espace libre sur / : ${free_gb} Go (10 Go minimum)" \
        "${vg_free} Go ne sont pas encore utilises sur ton disque. Agrandis la partition : sudo lvextend -r -l +100%FREE ${root_src}"
  else
    bad "Espace libre sur / : ${free_gb} Go (10 Go minimum)" \
        "Agrandis le disque virtuel de la VM (annexe du sujet), puis relance ce script."
  fi
fi

# 5. Acces Internet (installation : environ 1,7 Go a telecharger)
code=$(curl -s -o /dev/null -m 15 -w '%{http_code}' https://packages.wazuh.com/4.14/wazuh-install.sh 2>/dev/null)
if [[ "$code" == "200" ]]; then
  ok "Acces au depot Wazuh (packages.wazuh.com)"
else
  bad "Depot Wazuh injoignable (code HTTP ${code:-000})" "Verifie l'acces Internet de la VM (carte NAT)."
fi
code=$(curl -s -o /dev/null -m 15 -w '%{http_code}' https://raw.githubusercontent.com/ 2>/dev/null)
if [[ -n "$code" && "$code" != "000" ]]; then
  ok "Acces a GitHub (raw.githubusercontent.com)"
else
  bad "GitHub injoignable" "L'installeur Wazuh telecharge un fichier sur raw.githubusercontent.com."
fi

# 6. Ports utilises par Wazuh
if (( WAZUH_INSTALLED )); then
  info "Wazuh semble deja installe (/var/ossec existe)" "Si c'est toi qui l'as installe, passe directement a la suite du sujet."
else
  ports_ko=0
  for p in 443 1514 1515 9200 55000; do
    if ss -ltnH "sport = :$p" 2>/dev/null | grep -q .; then
      proc=$(ss -ltnpH "sport = :$p" 2>/dev/null | grep -o 'users:(("[^"]*' | head -1 | cut -d'"' -f2)
      bad "Port $p deja utilise${proc:+ par $proc}" "Arrete ce service avant d'installer Wazuh."
      ports_ko=1
    fi
  done
  (( ports_ko == 0 )) && ok "Ports necessaires a Wazuh libres (443, 1514, 1515, 9200, 55000)"
fi

# 7. Heritage du TP3
if command -v suricata >/dev/null 2>&1; then
  ok "Suricata installe (TP3)"
else
  bad "Suricata absent" "Refais la mise en place du TP3 : sudo bash $TP3_DIR/install-ids.sh"
fi

rules="$TPHOME/tp3-ids/local.rules"
if [[ -s "$rules" ]]; then
  n=$(grep -cE 'sid:[[:space:]]*1[0-9]{6,}' "$rules")
  if (( n >= 1 )); then
    ok "Tes regles du TP3 : $rules ($n regles)"
  else
    bad "Aucune regle personnelle dans $rules" "Le TP4 reutilise les regles que tu as ecrites au TP3."
  fi
else
  bad "Regles du TP3 introuvables ($rules)" "Recupere ton fichier local.rules du TP3 et place-le dans $TPHOME/tp3-ids/"
fi

if [[ -f "$TP3_DIR/declencher-trafic.sh" ]]; then
  ok "Script de trafic du TP3 present"
else
  bad "Script de trafic du TP3 absent ($TP3_DIR/declencher-trafic.sh)" "Fais un git pull dans le depot de la classe (uimm-src-3)."
fi

if systemctl cat web-interne.service >/dev/null 2>&1; then
  ok "Portail web du TP3 present (web-interne.service)"
else
  bad "Portail web du TP3 absent (web-interne.service)" "Relance la mise en place du TP3 : sudo bash $TP3_DIR/install-ids.sh"
fi

if command -v jq >/dev/null 2>&1; then
  ok "jq installe"
else
  bad "jq absent" "sudo apt install -y jq"
fi

# 8. Pare-feu (information)
if ufw status 2>/dev/null | grep -q 'Status: active'; then
  info "UFW est actif (TP1)" "Il faudra ouvrir le port 443 pour acceder a la console (Partie 1)."
fi

echo "-------------------------------------------------"
if (( ko == 0 )); then
  printf "%sTa VM est prete : passe a l'installation (Partie 1).%s\n" "$GREEN$BOLD" "$NC"
else
  printf "%s%d point(s) a corriger. Corrige-les puis relance ce script.%s\n" "$BOLD" "$ko" "$NC"
fi
