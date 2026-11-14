#!/usr/bin/env python3
# Statistiques Suricata pour les tableaux de bord UTMStack (cron horaire, VM UTMStack, root).
# UTMStack v11.3.0 ne propose pas de métrique « valeurs distinctes » (MetricAggregationEnum :
# COUNT, AVERAGE, MAX, MIN, MEDIAN, SUM). Ce script calcule le nombre d'adresses distinctes
# (agrégation cardinality d'OpenSearch) et l'écrit dans un document de l'index syslog du jour,
# avec des champs numériques que les visualisations lisent par MAX.
import json, subprocess, datetime, sys

CRED = "/root/.os.curl"
TZ = "Europe/Zurich"
cid = subprocess.check_output(["docker", "ps", "-qf", "name=utmstack_node1"]).decode().split()[0]

def os_req(method, path, body):
    with open(CRED, "rb") as f:
        out = subprocess.run(["docker", "exec", "-i", cid, "curl", "-sk", "-K", "-", "-X", method,
                              "-H", "Content-Type: application/json", "-d", json.dumps(body),
                              "https://localhost:9200" + path],
                             stdin=f, capture_output=True, check=True).stdout
    return json.loads(out)

def compter(depuis, filtres, jusqua="now"):
    q = {"size": 0, "track_total_hits": True,
         "query": {"bool": {"filter": filtres + [
             {"range": {"@timestamp": {"gte": depuis, "lt": jusqua, "time_zone": TZ}}}]}},
         "aggs": {"ip": {"cardinality": {"field": "origin.ip.keyword", "precision_threshold": 40000}}}}
    r = os_req("POST", "/v11-log-suricata-*/_search", q)
    return r["aggregations"]["ip"]["value"], r["hits"]["total"]["value"]

BLOQUE = [{"term": {"event.eventType": "alert"}}, {"term": {"event.alert.action": "blocked"}}]

# Reconstitution de l'historique : utmstack-soc-stats.py --backfill 30
# Un document par jour passé (journée complète, heure suisse), horodaté à 12:00 UTC
# pour tomber dans le bon jour de la courbe. Les jours sans alerte sont ignorés.
if len(sys.argv) == 3 and sys.argv[1] == "--backfill":
    for n in range(int(sys.argv[2]), 0, -1):
        ip, alertes = compter("now-%dd/d" % n, BLOQUE, "now-%dd/d" % (n - 1))
        if alertes == 0:
            continue
        jour = (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=n)).replace(
            hour=12, minute=0, second=0, microsecond=0)
        stats = {"blocked_ips_day": ip, "blocked_alerts_day": alertes}
        doc = {"@timestamp": jour.isoformat().replace("+00:00", "Z"), "dataType": "syslog",
               "dataSource": "utmstack-soc-stats", "raw": "SOC_STATS " + json.dumps(stats), "soc_stats": stats}
        os_req("POST", "/v11-log-syslog-%s/_doc" % jour.strftime("%Y-%m-%d"), doc)
        print(jour.strftime("%Y-%m-%d"), doc["raw"])
    sys.exit(0)

ip_jour, alertes_jour = compter("now/d", BLOQUE)
ip_24h, alertes_24h = compter("now-24h", BLOQUE)

now = datetime.datetime.now(datetime.timezone.utc)
stats = {"blocked_ips_day": ip_jour, "blocked_alerts_day": alertes_jour,
         "blocked_ips_24h": ip_24h, "blocked_alerts_24h": alertes_24h}
doc = {"@timestamp": now.isoformat().replace("+00:00", "Z"),
       "dataType": "syslog", "dataSource": "utmstack-soc-stats",
       "raw": "SOC_STATS " + json.dumps(stats), "soc_stats": stats}
os_req("POST", "/v11-log-syslog-%s/_doc" % now.strftime("%Y-%m-%d"), doc)
print(doc["raw"])
