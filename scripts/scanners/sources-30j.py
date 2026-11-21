#!/usr/bin/env python3
"""Exporte les adresses sources publiques vues par Suricata sur 30 jours (VM UTMStack, en root).

Sortie : une ligne par adresse, « ip événements événements_bloqués », triée par volume.
Usage : python3 sources-30j.py > /root/sources-30j.txt
Identifiants OpenSearch : /root/.os.curl (chmod 600), une ligne user = "admin:<mot de passe>".
"""
import json
import subprocess

cid = subprocess.check_output(["docker", "ps", "-qf", "name=utmstack_node1"]).decode().split()[0]
prives = ["192.168.0.0/16", "10.0.0.0/8", "172.16.0.0/12", "127.0.0.0/8"]
q = {
    "size": 0,
    "query": {"bool": {
        "filter": [{"range": {"@timestamp": {"gte": "now-30d"}}}],
        "must_not": [{"term": {"origin.ip": p}} for p in prives],
    }},
    "aggs": {"ip": {
        "terms": {"field": "origin.ip.keyword", "size": 20000},
        "aggs": {"bloque": {"filter": {"bool": {"filter": [
            {"term": {"event.eventType": "alert"}},
            {"term": {"event.alert.action": "blocked"}},
        ]}}}},
    }},
}
with open("/root/.os.curl", "rb") as f:
    out = subprocess.run(
        ["docker", "exec", "-i", cid, "curl", "-sk", "-K", "-", "-X", "POST",
         "-H", "Content-Type: application/json", "-d", json.dumps(q),
         "https://localhost:9200/v11-log-suricata-*/_search"],
        stdin=f, capture_output=True, check=True).stdout
for b in json.loads(out)["aggregations"]["ip"]["buckets"]:
    print(b["key"], b["doc_count"], b["bloque"]["doc_count"])
