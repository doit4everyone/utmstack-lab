#!/bin/sh
# Correctifs OpenSearch appliqués toutes les 5 minutes (cron : */5 * * * *).
# 1. Ingest pipeline crowdsec-country sur l'index syslog du jour. En v11.3.0, le template
#    OpenSearch d'UTMStack (utmstack_indexes) est prioritaire : un template dédié ne s'applique plus.
# 2. Aucune réplique sur les index v11-* : sur un nœud unique, une réplique ne peut jamais être
#    allouée, mais elle compte dans la limite de 1000 shards (cluster.max_shards_per_node).
#    Limite atteinte le 20 novembre 2026 : plus aucun index du jour créé, Suricata perdu 2 jours.
#    Même traitement pour les index internes d'OpenSearch créés chaque jour (un appel par famille :
#    une famille refusée ne bloque pas les autres). Les journaux security-auditlog-* sont gérés par
#    la politique ISM security-auditlog-30j (configs/opensearch/ism-security-auditlog-30j.json).
# Identifiants OpenSearch : /root/.os.curl (chmod 600), une ligne user = "admin:<mot de passe>"
CID=$(docker ps -qf name=utmstack_node1 | head -1)
[ -z "$CID" ] && exit 0
os() { docker exec -i "$CID" curl -sk -K - -H 'Content-Type: application/json' -X PUT "https://localhost:9200/$1" -d "$2" < /root/.os.curl > /dev/null 2>&1; }
for D in $(date -u +%Y-%m-%d) $(date +%Y-%m-%d); do
  os "v11-log-syslog-$D/_settings" '{"index.default_pipeline":"crowdsec-country"}'
done
for P in 'v11-*' 'top_queries-*' '.opendistro-ism-managed-index-history-*'; do
  os "$P/_settings?expand_wildcards=all" '{"index.number_of_replicas":0}'
done
