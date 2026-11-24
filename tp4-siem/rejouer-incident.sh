#!/usr/bin/env bash
#
# rejouer-incident.sh
# Rejoue l'incident Solmetal sur la VM de TP pour que le SIEM le detecte :
# activite cote hote (journal systeme + modifications reelles) et activite reseau.
#
# A executer UNIQUEMENT sur la VM de TP, jetable et isolee.
# Usage : sudo bash rejouer-incident.sh [--sans-reseau]
#
set -uo pipefail

if [[ $EUID -ne 0 ]]; then
  echo "Lance ce script en root : sudo bash rejouer-incident.sh" >&2
  exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TRAFIC="$SCRIPT_DIR/../tp3-supervision/declencher-trafic.sh"
ATTACKER="185.220.101.47"
VICTIM="stagiaire"
RUN_ID="$(date +%s)"
SANS_RESEAU=0
[[ "${1:-}" == "--sans-reseau" ]] && SANS_RESEAU=1

# --- Preconditions -----------------------------------------------------------

if ! systemctl is-active --quiet wazuh-manager; then
  echo "ERREUR : le serveur Wazuh (wazuh-manager) n'est pas actif." >&2
  echo "         Demarre-le : sudo systemctl start wazuh-manager" >&2
  exit 1
fi

if (( SANS_RESEAU == 0 )); then
  if ! pgrep -af suricata | grep -q -- '-i lo'; then
    echo "ERREUR : ta sonde Suricata n'ecoute pas l'interface lo." >&2
    echo "         Lance-la comme indique dans le sujet (Partie 2), puis relance ce script." >&2
    exit 1
  fi
  if [[ ! -f "$TRAFIC" ]]; then
    echo "ERREUR : script de trafic du TP3 introuvable : $TRAFIC" >&2
    echo "         Fais un git pull dans le depot de la classe (uimm-src-3)." >&2
    exit 1
  fi
  systemctl start web-interne.service >/dev/null 2>&1 || true
fi

# --- Outils ------------------------------------------------------------------

log_sshd() { logger -p auth.info -t sshd --id="$1" -- "$2"; }
rand_port() { echo $((RANDOM % 60000 + 1024)); }
rand_pid()  { echo $((RANDOM % 9000 + 1000)); }

debut="$(date +%H:%M:%S)"
echo "==> Debut de l'incident : $debut"

# --- Phase 1 : intrusion sur l'hote -----------------------------------------

echo "  - activite suspecte sur le service SSH"
users=(root admin oracle test postgres ubuntu deploy)
for _ in $(seq 1 30); do
  u="${users[$((RANDOM % ${#users[@]}))]}"
  log_sshd "$(rand_pid)" "Failed password for invalid user $u from $ATTACKER port $(rand_port) ssh2"
  sleep 0.1
done
sleep 2

pid="$(rand_pid)"
vuid="$(id -u "$VICTIM" 2>/dev/null || echo 1001)"
log_sshd "$pid" "Accepted password for $VICTIM from $ATTACKER port $(rand_port) ssh2"
logger -p authpriv.info -t sshd --id="$pid" -- "pam_unix(sshd:session): session opened for user $VICTIM(uid=$vuid) by (uid=0)"
sleep 2

echo "  - activite de l'utilisateur connecte"
logger -p authpriv.notice -t sudo -- "  $VICTIM : TTY=pts/1 ; PWD=/home/$VICTIM ; USER=root ; COMMAND=/usr/bin/cat /etc/shadow"
sleep 2

echo "  - modifications du systeme"
# Compte a privileges : on le recree a chaque passage pour que sa creation soit journalisee
if grep -q '^svc-update:' /etc/passwd; then
  sed -i '/^svc-update:/d' /etc/passwd /etc/shadow
fi
useradd -o -u 0 -g 0 -M -d /home/svc-update -s /bin/bash svc-update
echo 'svc-update:Backdoor2024!' | chpasswd

# Script de balise (inoffensif : ecrit une ligne dans /tmp)
cat > /usr/local/bin/.sync <<EOF
#!/bin/bash
# build $RUN_ID
echo "beacon \$(date)" >> /tmp/.beacon
EOF
chmod 755 /usr/local/bin/.sync

# Tache planifiee
cat > /etc/cron.d/svc-update <<EOF
# maintenance $RUN_ID
*/10 * * * * root /usr/local/bin/.sync >/dev/null 2>&1
EOF
chmod 644 /etc/cron.d/svc-update

# Unite systemd
cat > /etc/systemd/system/sync-update.service <<EOF
# rev $RUN_ID
[Unit]
Description=System sync update

[Service]
Type=oneshot
ExecStart=/usr/local/bin/.sync
EOF
cat > /etc/systemd/system/sync-update.timer <<EOF
# rev $RUN_ID
[Unit]
Description=System sync update timer

[Timer]
OnBootSec=2min
OnUnitActiveSec=5min

[Install]
WantedBy=timers.target
EOF
systemctl daemon-reload
systemctl enable sync-update.timer >/dev/null 2>&1
systemctl restart sync-update.timer >/dev/null 2>&1

# --- Phase 2 : activite reseau ------------------------------------------------

if (( SANS_RESEAU == 0 )); then
  echo "  - activite reseau (environ 1 minute)"
  bash "$TRAFIC" >/dev/null 2>&1
else
  echo "  - activite reseau ignoree (--sans-reseau)"
fi

fin="$(date +%H:%M:%S)"
echo "==> Incident rejoue entre $debut et $fin."
echo "    A toi d'enqueter dans le SIEM. N'eradique rien avant la Partie 8 du sujet."
