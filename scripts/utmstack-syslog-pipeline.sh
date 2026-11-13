#!/bin/sh
# Applique l'ingest pipeline crowdsec-country à l'index syslog du jour.
# En v11.3.0, le template OpenSearch d'UTMStack (utmstack_indexes) est prioritaire :
# un template dédié ne s'applique plus. Cron : */5 * * * *
# Identifiants OpenSearch : /root/.os.curl (chmod 600), une ligne user = "admin:<mot de passe>"
CID=$(docker ps -qf name=utmstack_node1 | head -1)
[ -z "$CID" ] && exit 0
for D in $(date -u +%Y-%m-%d) $(date +%Y-%m-%d); do
  docker exec -i "$CID" curl -sk -K - -H 'Content-Type: application/json' -X PUT \
    "https://localhost:9200/v11-log-syslog-$D/_settings" \
    -d '{"index.default_pipeline":"crowdsec-country"}' < /root/.os.curl > /dev/null 2>&1
done
