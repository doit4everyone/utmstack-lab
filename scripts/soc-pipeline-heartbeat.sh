#!/bin/bash
#
# soc-pipeline-heartbeat.sh
# ------------------------------------------------------------------
# Surveille que le pipeline LLM (n8n) a bien produit un rapport SOC
# dans les dernieres 26h. Si ce n'est pas le cas, emet un syslog vers
# l'agent UTMStack pour transformer la panne du pipeline en alerte SIEM.
#
# IMPORTANT : ce script tourne sur la VM UTMStack, PAS dans n8n.
# Un heartbeat qui tourne dans le systeme qu'il surveille ne detecte
# pas la panne de ce systeme.
#
# Deploiement : voir install-heartbeat.sh (service + timer systemd)
# ------------------------------------------------------------------

# --- Parametres a adapter ---
SEUIL_HEURES=26                        # 26h = tolerance de 2h apres le run de 6h
UPTIME_MIN_HEURES=2                    # pas d'alerte si la VM vient de demarrer
AGENT_SYSLOG_IP="<UTMSTACK_AGENT_IP>"  # agent Windows UTMStack (ex. 10.100.1.16)
AGENT_SYSLOG_PORT=7014                 # port syslog de l'agent Windows
DB_NAME="utmstack"
DB_USER="postgres"
LOG="/var/log/soc-pipeline-heartbeat.log"

# --- Age du dernier rapport ---
CONTAINER=$(docker ps -q -f name=utmstack_postgres)

if [ -z "$CONTAINER" ]; then
  AGE=9999
  DETAIL="conteneur postgres introuvable"
else
  AGE=$(docker exec "$CONTAINER" psql -U "$DB_USER" -d "$DB_NAME" -t -A -c \
    "SELECT COALESCE(ROUND(EXTRACT(EPOCH FROM (NOW() - MAX(date_generation)))/3600), 9999) FROM resumes_soc;" \
    2>/dev/null | tr -d '[:space:]')
  DETAIL="requete postgres"
fi

# Normalisation : tout ce qui n'est pas un entier = panne (fail-safe, jamais fail-silent)
if [ -z "$AGE" ] || ! [[ "$AGE" =~ ^[0-9]+$ ]]; then
  AGE=9999
  DETAIL="$DETAIL - reponse invalide ou vide"
fi

# --- Uptime de la VM, en heures ---
UPTIME_H=$(awk '{print int($1/3600)}' /proc/uptime)

# --- Decision ---
if [ "$AGE" -ge "$SEUIL_HEURES" ]; then

  # Garde-fou : lab rallume apres un arret prolonge, le pipeline
  # n'a pas encore eu l'occasion de tourner. La verification suivante
  # (uptime > 2h) rattrapera une vraie panne.
  if [ "$UPTIME_H" -lt "$UPTIME_MIN_HEURES" ]; then
    echo "$(date -Is) REPORTE - age=${AGE}h mais uptime=${UPTIME_H}h (demarrage recent)" >> "$LOG"
    exit 0
  fi

  if [ "$AGE" -eq 9999 ]; then
    MSG="SOC-PIPELINE-HEARTBEAT FAILURE - impossible de determiner la date du dernier rapport SOC ($DETAIL) - pipeline LLM potentiellement hors service"
  else
    MSG="SOC-PIPELINE-HEARTBEAT FAILURE - aucun rapport SOC genere depuis ${AGE}h (seuil ${SEUIL_HEURES}h) - pipeline LLM potentiellement hors service"
  fi

  # local0.crit -> severite syslog 2 (Critical), mappee en High cote UTMStack
  logger -n "$AGENT_SYSLOG_IP" -P "$AGENT_SYSLOG_PORT" -T \
         -p local0.crit -t soc-pipeline "$MSG"

  echo "$(date -Is) ALERTE EMISE - age=${AGE}h uptime=${UPTIME_H}h - $DETAIL" >> "$LOG"
  exit 1

else
  echo "$(date -Is) OK - dernier rapport il y a ${AGE}h" >> "$LOG"
  exit 0
fi
