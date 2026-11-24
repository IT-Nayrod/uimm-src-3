#!/usr/bin/env bash
#
# verif-tp4.sh
# Verifie le travail du TP4 (SIEM Wazuh) et affiche un score.
# A lancer en root :
#   sudo bash verif-tp4.sh            -> liste des points valides ou non
#   sudo bash verif-tp4.sh --details  -> explique precisement ce qui manque
#
set -uo pipefail

if [[ $EUID -ne 0 ]]; then
  echo "Lance ce script en root : sudo bash verif-tp4.sh" >&2
  exit 1
fi

DETAILS=0
[[ "${1:-}" == "--details" || "${1:-}" == "-v" ]] && DETAILS=1

GREEN=$'\e[32m'; RED=$'\e[31m'; BOLD=$'\e[1m'; NC=$'\e[0m'
score=0; total=0

TPUSER="${SUDO_USER:-root}"
TPHOME="$(getent passwd "$TPUSER" | cut -d: -f6)"
[[ -z "$TPHOME" ]] && TPHOME=/root

OSSEC_CONF=/var/ossec/etc/ossec.conf
ALERTS_DIR=/var/ossec/logs/alerts
AR_LOG=/var/ossec/logs/active-responses.log
ATTACKER="185.220.101.47"

if ! command -v jq >/dev/null 2>&1; then
  echo "jq est necessaire : sudo apt install -y jq" >&2
  exit 1
fi

if [[ ! -d /var/ossec ]]; then
  echo "Wazuh n'est pas installe sur cette machine (/var/ossec absent). Commence par la Partie 1." >&2
  exit 1
fi

# --- Resume des alertes : fichier du jour et archives des 7 derniers jours ---
DIGEST="$(mktemp)"
trap 'rm -f "$DIGEST"' EXIT
{
  cat "$ALERTS_DIR/alerts.json" 2>/dev/null
  find "$ALERTS_DIR" -name 'ossec-alerts-*.json.gz' -mtime -7 -print0 2>/dev/null | xargs -0 -r zcat 2>/dev/null
} | jq -R -c 'fromjson? | {id: (.rule.id // ""), lvl: (.rule.level // 0), groups: (.rule.groups // []), srcip: (.data.srcip // ""), path: (.syscheck.path // "")}' \
  > "$DIGEST" 2>/dev/null

# Nombre d'alertes correspondant a un filtre jq
count_alerts() { jq -c "select($1)" "$DIGEST" 2>/dev/null | grep -c .; }
has_alert()    { (( $(count_alerts "$1") > 0 )); }

# --- Affichage -----------------------------------------------------------------
DETAIL_MSG=""
check() {
  local label="$1"; shift
  total=$((total + 1))
  DETAIL_MSG=""
  if "$@"; then
    printf "%s[ OK  ]%s %s\n" "$GREEN" "$NC" "$label"
    score=$((score + 1))
  else
    printf "%s[ECHEC]%s %s\n" "$RED" "$NC" "$label"
    if (( DETAILS )) && [[ -n "$DETAIL_MSG" ]]; then
      printf "        -> %s\n" "$DETAIL_MSG"
    fi
  fi
}

# --- Controles -----------------------------------------------------------------

c_services() {
  local s down=()
  for s in wazuh-manager wazuh-indexer wazuh-dashboard; do
    systemctl is-active --quiet "$s" 2>/dev/null || down+=("$s")
  done
  if (( ${#down[@]} > 0 )); then
    DETAIL_MSG="Service(s) inactif(s) : ${down[*]}. Demarre-les (sudo systemctl start ...) et lis sudo journalctl -u <service> en cas d'echec."
    return 1
  fi
}

c_suricata_source() {
  if awk '/<!--/{c=1} c&&/-->/{c=0; next} c{next}
          /<localfile>/{b=""} {b=b $0}
          /<\/localfile>/{ if (b ~ /\/var\/log\/suricata\/eve\.json/ && b ~ /<log_format>[[:space:]]*json[[:space:]]*</) f=1 }
          END{exit !f}' "$OSSEC_CONF" 2>/dev/null; then
    return 0
  fi
  DETAIL_MSG="Aucun bloc <localfile> ne lit /var/log/suricata/eve.json au format json dans $OSSEC_CONF (Partie 2)."
  return 1
}

c_bruteforce() {
  has_alert "(.groups | any(. == \"authentication_failures\")) and .lvl >= 10 and .srcip == \"$ATTACKER\"" && return 0
  DETAIL_MSG="Aucune alerte de force brute SSH enregistree. Le serveur Wazuh doit tourner pendant tout le rejeu de l'incident (Partie 4)."
  return 1
}

c_correlation() {
  has_alert '.id == "40112"' && return 0
  DETAIL_MSG="L'alerte native qui correle des echecs d'authentification suivis d'un succes n'est jamais apparue. Rejoue l'incident avec le serveur actif du debut a la fin."
  return 1
}

c_suricata_alerts() {
  has_alert '.id == "86601"' && return 0
  DETAIL_MSG="Aucune alerte Suricata dans le SIEM. Verifie le bloc <localfile> de eve.json, que ta sonde tourne sur lo avec tes regles (pgrep -af suricata), puis rejoue l'incident."
  return 1
}

c_fim_known() {
  has_alert '(.id == "554" or .id == "550") and (.path | test("^/etc/cron\\.d/svc-update|^/usr/local/bin/\\.sync"))' && return 0
  DETAIL_MSG="Le FIM n'a vu ni la tache planifiee ni le script de l'attaquant. Configure la surveillance en temps reel (Partie 3), attends le message 'scan ended', puis rejoue l'incident."
  return 1
}

HIDDEN_DETECTED=0
c_fim_hidden() {
  if has_alert '(.id == "554" or .id == "550") and (.path | test("^/etc/systemd/system/.*sync-update"))'; then
    HIDDEN_DETECTED=1
    return 0
  fi
  DETAIL_MSG="La persistance non annoncee n'a pas ete vue par le FIM. Trouve-la (Partie 4), etends ta surveillance en temps reel a son emplacement (Partie 5), puis rejoue l'incident (Partie 7)."
  return 1
}

c_custom_rules() {
  local n
  n=$(jq -r 'select(((.id | tonumber?) // 0) >= 100000) | .id' "$DIGEST" 2>/dev/null | sort -u | grep -c .)
  (( n >= 3 )) && return 0
  DETAIL_MSG="$n regle(s) personnelle(s) declenchee(s) sur 3 attendues (ID >= 100000). Teste-les avec wazuh-logtest, verifie la syntaxe (wazuh-analysisd -t), redemarre le serveur puis rejoue l'incident."
  return 1
}

c_active_response() {
  has_alert '.id == "651" or .id == "601"' && return 0
  if [[ -f "$AR_LOG" ]] && grep 'firewall-drop' "$AR_LOG" 2>/dev/null | grep -q "${ATTACKER//./\\.}"; then
    return 0
  fi
  DETAIL_MSG="Aucun blocage automatique enregistre. Configure un bloc <active-response> (Partie 6), redemarre le serveur puis rejoue l'incident."
  return 1
}

c_sca() {
  has_alert '.id == "19010"' && return 0
  DETAIL_MSG="Aucun controle de conformite n'est passe d'echec a reussite. Corrige des controles en echec puis redemarre le serveur pour relancer l'evaluation (Partie 8)."
  return 1
}

c_uid0() {
  local extra
  extra=$(awk -F: '($3 == 0 && $1 != "root") {print $1}' /etc/passwd | paste -sd ' ' -)
  [[ -z "$extra" ]] && return 0
  DETAIL_MSG="Compte(s) a UID 0 en plus de root : ${extra}. Rappel du TP2 : userdel refuse de supprimer un compte qui partage l'UID de root."
  return 1
}

c_cron_script() {
  local left=()
  [[ -e /etc/cron.d/svc-update ]] && left+=("/etc/cron.d/svc-update")
  [[ -e /usr/local/bin/.sync ]] && left+=("/usr/local/bin/.sync")
  (( ${#left[@]} == 0 )) && return 0
  DETAIL_MSG="Encore present : ${left[*]} (Partie 8)."
  return 1
}

c_hidden_gone() {
  local left=() f
  for f in /etc/systemd/system/sync-update.timer /etc/systemd/system/sync-update.service \
           /etc/systemd/system/timers.target.wants/sync-update.timer; do
    [[ -e "$f" || -L "$f" ]] && left+=("$f")
  done
  systemctl is-active --quiet sync-update.timer 2>/dev/null && left+=("sync-update.timer (actif)")
  (( ${#left[@]} == 0 )) && return 0
  if (( HIDDEN_DETECTED )); then
    DETAIL_MSG="Encore present : ${left[*]}. Desactive-la avant de supprimer ses fichiers (Partie 8)."
  else
    DETAIL_MSG="Une persistance de l'attaquant est encore active sur le systeme. Trouve-la d'abord (Partie 4)."
  fi
  return 1
}

RAPPORT=""
for f in "$TPHOME/tp4-siem/rapport-siem.md" "./rapport-siem.md"; do
  [[ -s "$f" ]] && { RAPPORT="$f"; break; }
done

c_report_attack() {
  if [[ -z "$RAPPORT" ]]; then
    DETAIL_MSG="Rapport introuvable : $TPHOME/tp4-siem/rapport-siem.md (Partie 9)."
    return 1
  fi
  local n
  n=$(grep -oE 'T[0-9]{4}(\.[0-9]{3})?' "$RAPPORT" | sort -u | grep -c .)
  (( n >= 3 )) && return 0
  DETAIL_MSG="Le rapport cite $n technique(s) ATT&CK distincte(s) (format TXXXX), il en faut au moins 3."
  return 1
}

c_report_content() {
  [[ -z "$RAPPORT" ]] && { DETAIL_MSG="Rapport introuvable (Partie 9)."; return 1; }
  local miss=()
  grep -qiE 'systemd|timer|minuteur' "$RAPPORT" || miss+=("la persistance non annoncee")
  grep -qiE '40112|corr[^ ]*lation' "$RAPPORT" || miss+=("l'alerte de correlation native")
  (( ${#miss[@]} == 0 )) && return 0
  DETAIL_MSG="Le rapport n'explique pas encore : ${miss[*]}."
  return 1
}

# --- Execution -----------------------------------------------------------------

echo "${BOLD}=== Verification du TP4 : SIEM Wazuh ===${NC}"
check "Les trois briques du SIEM sont actives"                    c_services
check "La source Suricata est raccordee au SIEM"                  c_suricata_source
check "La force brute SSH a ete detectee"                         c_bruteforce
check "La correlation native (echecs puis succes) s'est declenchee" c_correlation
check "Les alertes de ta sonde Suricata remontent dans le SIEM"   c_suricata_alerts
check "Le FIM temps reel a vu les persistances connues"           c_fim_known
check "La persistance non annoncee a ete detectee par le FIM"     c_fim_hidden
check "Au moins 3 de tes regles se sont declenchees"              c_custom_rules
check "La riposte automatique a bloque l'attaquant"               c_active_response
check "La conformite du serveur a progresse (SCA)"                c_sca
check "Plus aucun compte a UID 0 hormis root"                     c_uid0
check "Tache planifiee et script cache supprimes"                 c_cron_script
check "Persistance non annoncee eradiquee"                        c_hidden_gone
check "Rapport redige avec au moins 3 techniques ATT&CK"          c_report_attack
check "Rapport : persistance cachee et correlation expliquees"    c_report_content

echo "-------------------------------------------------"
if (( score == total )); then
  printf "%sScore : %s/%s. SIEM operationnel, incident traite de bout en bout, bravo.%s\n" "$GREEN$BOLD" "$score" "$total" "$NC"
else
  printf "%sScore : %s/%s. Corrige les lignes [ECHEC] puis relance.%s\n" "$BOLD" "$score" "$total" "$NC"
  (( DETAILS )) || echo "Relance avec --details pour savoir precisement ce qui manque."
fi
