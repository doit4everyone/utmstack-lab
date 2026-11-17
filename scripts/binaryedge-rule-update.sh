#!/bin/sh
# Régénère les règles Suricata 1000060 à 1000079 (sondes BinaryEdge) depuis l'API publique.
# La liste (environ 3 800 adresses /32) est découpée en lots de 300 adresses, une règle par lot.
# Ne modifie les règles que si la liste a changé ; garde les anciennes en cas d'erreur.
# Option -n : génère et teste les règles sans les installer.
# OPNsense : /conf/binaryedge-rule-update.sh, copié vers /usr/local/bin par le hook 98-soar-ban,
# cron /etc/cron.d/binaryedge-rule-update : 40 4 * * 1 root /usr/local/bin/binaryedge-rule-update.sh
LOG=/var/log/binaryedge-rule-update.log
URL=https://api.binaryedge.io/v1/minions
RULES=/conf/custom.rules
TAG="CUSTOM DROP - BinaryEdge scanner"
SID0=1000060
LOT=300
MAXLOTS=20
TMP=/tmp/binaryedge-maj.$$
SEC=0; [ "$1" = "-n" ] && SEC=1
log() { echo "$(date '+%Y-%m-%d %H:%M:%S') $*" >> "$LOG"; logger -t binaryedge-rule "$*"; [ $SEC -eq 1 ] && echo "$*"; }
fin() { rm -f "$TMP".*; exit "$1"; }

fetch -qo "$TMP.json" "$URL" || { log "ERREUR : téléchargement impossible, règles inchangées"; fin 1; }
grep -oE '"[0-9]{1,3}(\.[0-9]{1,3}){3}"' "$TMP.json" | tr -d '"' | sort -t. -k1,1n -k2,2n -k3,3n -k4,4n -u > "$TMP.ips"
N=$(wc -l < "$TMP.ips" | tr -d ' ')
if [ "$N" -lt 100 ]; then log "ERREUR : liste suspecte ($N adresses), règles inchangées"; fin 1; fi
NL=$(( (N + LOT - 1) / LOT ))
if [ "$NL" -gt "$MAXLOTS" ]; then log "ERREUR : $N adresses, $NL lots au-delà de la plage de SID réservée, règles inchangées"; fin 1; fi

split -l "$LOT" "$TMP.ips" "$TMP.lot."
k=0
for f in "$TMP".lot.*; do
  L=$(paste -sd, "$f")
  echo "drop ip [$L] any -> \$HOME_NET any (msg:\"$TAG (api.binaryedge.io/v1/minions, lot $((k + 1))/$NL)\"; classtype:attempted-recon; priority:1; sid:$((SID0 + k)); rev:1;)" >> "$TMP.rules"
  k=$((k + 1))
done

grep -F "$TAG" "$RULES" > "$TMP.actuel"
if [ $SEC -eq 0 ] && cmp -s "$TMP.rules" "$TMP.actuel"; then log "OK : liste inchangée ($N adresses)"; fin 0; fi

if ! suricata -T -c /usr/local/etc/suricata/suricata.yaml -S "$TMP.rules" > "$TMP.test" 2>&1; then
  log "ERREUR : nouvelles règles refusées par suricata -T, règles inchangées"; tail -5 "$TMP.test" >> "$LOG"; fin 1
fi
if [ $SEC -eq 1 ]; then log "TEST : $N adresses, $NL règles acceptées par suricata -T, rien installé"; fin 0; fi

cp "$RULES" "$RULES.prec"
grep -vF "$TAG" "$RULES.prec" > "$RULES"
cat "$TMP.rules" >> "$RULES"
/usr/local/bin/custom-rules-fix.sh
log "MAJ : $N adresses, $NL règles (sid $SID0 à $((SID0 + NL - 1))), version précédente dans $RULES.prec"
fin 0
