#!/bin/sh
LOG="/var/log/soar_ban.log"
IP=$1
COUNTRY=$2
ASN=$3
EVENT_TIMESTAMP=$4
ORIGIN=$5
LAT=$6
LON=$7
ALERT_ID=$8

echo "$(date) START: IP=$IP COUNTRY=$COUNTRY ASN=$ASN TS=$EVENT_TIMESTAMP ORIGIN=$ORIGIN LAT=$LAT LON=$LON" >> "$LOG"

[ -z "$COUNTRY" ] || [ "$COUNTRY" = "null" ] && COUNTRY="Unknown"
[ -z "$ASN" ] || [ "$ASN" = "null" ] && ASN="AS0"
# Coordonnées UTMStack de l'adresse (carte CrowdSec) : vides si absentes ou non numériques
echo "$LAT" | grep -Eq '^-?[0-9]+([.][0-9]+)?$' || LAT=""
echo "$LON" | grep -Eq '^-?[0-9]+([.][0-9]+)?$' || LON=""

# -------------------------------------------------------
# 0. Protection des adresses internes
# -------------------------------------------------------
# Toutes les plages privées (RFC 1918), le local et le lien local.
# Couvre aussi le VPN IKEv2 (10.2.8.0/24).
case "$IP" in
    10.*|127.*|169.254.*|192.168.*|172.1[6-9].*|172.2[0-9].*|172.3[01].*)
        echo "$(date) SKIP: $IP is internal, not banning" >> "$LOG"
        echo "OK: $IP (internal)"
        exit 0
        ;;
esac

# -------------------------------------------------------
# 0b. Connexion sortante : un poste interne vers une IP signalée
# -------------------------------------------------------
# Pas de ban automatique (risque de faux positif des listes de
# réputation sur un grand fournisseur, par exemple Microsoft).
# Message syslog SOAR_OUTBOUND, repris par une règle UTMStack
# dont l'alerte reste ouverte pour investigation du poste.
if [ -n "$ORIGIN" ] && [ "$ORIGIN" != "null" ] && [ "$ORIGIN" != "$IP" ]; then
    case "$ORIGIN" in
        10.*|192.168.*|172.1[6-9].*|172.2[0-9].*|172.3[01].*)
            echo "$(date) OUTBOUND: $ORIGIN -> $IP, not banned" >> "$LOG"
            logger -p local5.alert -t crowdsec \
              "SOAR_OUTBOUND {\"origin\":\"$ORIGIN\",\"ip\":\"$IP\",\"country\":\"$COUNTRY\",\"as\":\"$ASN\"}"
            echo "OK: $IP (outbound from $ORIGIN, not banned)"
            exit 0
            ;;
    esac
fi

# -------------------------------------------------------
# 1. Détection de rejeu par l'horodatage de l'événement
# -------------------------------------------------------
# Les horodatages SOAR sont en UTC (suffixe Z) : TZ=UTC obligatoire
if [ -n "$EVENT_TIMESTAMP" ] && [ "$EVENT_TIMESTAMP" != "null" ] && [ "$EVENT_TIMESTAMP" != '$(timestamp)' ]; then
    TS_CLEAN=$(echo "$EVENT_TIMESTAMP" | sed 's/\.[0-9]*//' | sed 's/+[0-9:]*//' | sed 's/Z$//' | tr 'T' ' ')
    EVENT_UNIX=$(TZ=UTC date -j -f "%Y-%m-%d %H:%M:%S" "$TS_CLEAN" "+%s" 2>/dev/null)
    NOW_UNIX=$(date +%s)
    if [ -n "$EVENT_UNIX" ] && [ "$EVENT_UNIX" -gt 0 ]; then
        AGE=$((NOW_UNIX - EVENT_UNIX))
        echo "$(date) TIMESTAMP: age=${AGE}s" >> "$LOG"
        if [ "$AGE" -gt 7200 ]; then
            echo "$(date) REPLAY: event is ${AGE}s old, skipping ban for $IP" >> "$LOG"
            echo "OK: $IP (replay)"
            exit 0
        fi
    else
        echo "$(date) TIMESTAMP: parse failed for '$EVENT_TIMESTAMP', skipping replay check" >> "$LOG"
    fi
fi

# -------------------------------------------------------
# 2. Déduplication par IP sur 7 jours (filet de sécurité)
# -------------------------------------------------------
RECENT_BANS="/conf/soar_recent_bans.txt"

if [ -f "$RECENT_BANS" ]; then
    CUTOFF=$(date -v-168H +%s 2>/dev/null)
    if [ -z "$CUTOFF" ]; then
        CUTOFF=$(date -d '168 hours ago' +%s 2>/dev/null)
    fi
    if [ -n "$CUTOFF" ]; then
        awk -v cutoff="$CUTOFF" '$1 > cutoff' "$RECENT_BANS" > /tmp/bans_clean.txt
        mv /tmp/bans_clean.txt "$RECENT_BANS"
    fi
fi

if grep -q " $IP$" "$RECENT_BANS" 2>/dev/null; then
    echo "$(date) DEDUPE 7j: $IP already processed, skipping" >> "$LOG"
    if [ -n "$ALERT_ID" ] && [ "$ALERT_ID" != "null" ]; then
        TOKEN=$(cat /conf/utmstack_token.txt 2>/dev/null)
        if [ -n "$TOKEN" ]; then
            curl -sk -X POST "https://10.100.1.150/api/utm-alerts/status" \
              -H "Authorization: Bearer $TOKEN" \
              -H "Content-Type: application/json" \
              -d "{\"alertIds\":[\"$ALERT_ID\"],\"status\":5,\"statusObservation\":\"Auto-closed by SOAR: IP already in dedup 7j\"}" \
              >> "$LOG" 2>&1
        fi
    fi
    echo "OK: $IP (dedup)"
    exit 0
fi

# -------------------------------------------------------
# 3. Bannissement CrowdSec
# -------------------------------------------------------
if ! /usr/local/bin/cscli decisions list --ip "$IP" 2>/dev/null | grep -q "ban"; then
    /usr/local/bin/cscli decisions add --ip "$IP" --duration 24h --reason utmstack
    echo "$(date +%s) $IP" >> "$RECENT_BANS"
    logger -p local5.alert -t crowdsec \
      "CROWDSEC_BAN {\"event_type\":\"ban\",\"ip\":\"$IP\",\"reason\":\"utmstack\",\"country\":\"$COUNTRY\",\"as\":\"$ASN\",\"lat\":\"$LAT\",\"lon\":\"$LON\",\"type\":\"ban\"}"
    echo "$(date) BAN: $IP ($COUNTRY / $ASN)" >> "$LOG"
    echo "OK: BAN $IP ($COUNTRY / $ASN)"
else
    echo "$(date) SKIP: $IP already in CrowdSec" >> "$LOG"
    echo "OK: $IP (exists)"
fi

# -------------------------------------------------------
# 4. Fermeture de l'alerte par l'API UTMStack
# (ALERT_ID non exposé par le SOAR : section prête pour une version future)
# -------------------------------------------------------
if [ -n "$ALERT_ID" ] && [ "$ALERT_ID" != "null" ]; then
    TOKEN=$(cat /conf/utmstack_token.txt 2>/dev/null)
    if [ -n "$TOKEN" ]; then
        curl -sk -X POST "https://10.100.1.150/api/utm-alerts/status" \
          -H "Authorization: Bearer $TOKEN" \
          -H "Content-Type: application/json" \
          -d "{\"alertIds\":[\"$ALERT_ID\"],\"status\":5,\"statusObservation\":\"Auto-closed by SOAR after CrowdSec ban\"}" \
          >> "$LOG" 2>&1
        echo "$(date) ALERT CLOSED: $ALERT_ID" >> "$LOG"
    fi
fi

echo "$(date) END: completed for $IP" >> "$LOG"
