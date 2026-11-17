#!/bin/sh
# Régénère la règle Suricata 1000048 (scanners Modat) depuis la liste publiée.
# Ne modifie la règle que si la liste a changé ; garde l'ancienne en cas d'erreur.
# OPNsense : /conf/modat-rule-update.sh, copié vers /usr/local/bin par le hook 98-soar-ban,
# cron /etc/cron.d/modat-rule-update : 30 4 * * 1 root /usr/local/bin/modat-rule-update.sh
LOG=/var/log/modat-rule-update.log
URL=https://scanner.modat.io/ipv4.txt
RULES=/conf/custom.rules
TMP=/tmp/modat-maj.$$
log() { echo "$(date '+%Y-%m-%d %H:%M:%S') $*" >> "$LOG"; logger -t modat-rule "$*"; }
fin() { rm -f "$TMP".*; exit "$1"; }

fetch -qo "$TMP.txt" "$URL" || { log "ERREUR : téléchargement impossible, règle inchangée"; fin 1; }
tr -d '\r' < "$TMP.txt" | grep -v '^[[:space:]]*$' > "$TMP.list"
N=$(wc -l < "$TMP.list" | tr -d ' ')
BAD=$(grep -cvE '^[0-9]{1,3}(\.[0-9]{1,3}){3}/[0-9]{1,2}$' "$TMP.list")
if [ "$N" -lt 10 ] || [ "$BAD" -ne 0 ]; then
  log "ERREUR : liste suspecte ($N lignes, $BAD invalides), règle inchangée"; fin 1
fi

L=$(paste -sd, "$TMP.list")
R="drop ip [$L] any -> \$HOME_NET any (msg:\"CUSTOM DROP - Modat scanner (liste scanner.modat.io/ipv4.txt)\"; classtype:attempted-recon; priority:1; sid:1000048; rev:1;)"

if grep -qxF "$R" "$RULES"; then log "OK : liste inchangée ($N plages)"; fin 0; fi

echo "$R" > "$TMP.rules"
if ! suricata -T -c /usr/local/etc/suricata/suricata.yaml -S "$TMP.rules" > "$TMP.test" 2>&1; then
  log "ERREUR : nouvelle règle refusée par suricata -T, règle inchangée"; fin 1
fi

cp "$RULES" "$RULES.prec"
grep -v 'sid:1000048;' "$RULES.prec" > "$RULES"
echo "$R" >> "$RULES"
/usr/local/bin/custom-rules-fix.sh
log "MAJ : règle 1000048 régénérée ($N plages), version précédente dans $RULES.prec"
fin 0
