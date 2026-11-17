-- Tableau de bord « Scanners Internet » : 9 visualisations copiées de visualisations existantes (chapitre 12).
-- Usage : docker exec -i $(docker ps -qf name=postgres | head -1) psql -U postgres -d utmstack < scanners-dashboard.sql
-- Sources à adapter : 1000018 (compteur NF), 1000020 (tableau d'adresses), cartes et barres par nom.
BEGIN;
CREATE TABLE IF NOT EXISTS utm_visualization_bak_20261117 AS SELECT * FROM utm_visualization;
CREATE TEMP TABLE f AS SELECT
 '{"operator":"IS_BETWEEN","field":"@timestamp","value":["now-24h","now"]}'::jsonb AS h24,
 '{"operator":"IS_BETWEEN","field":"@timestamp","value":["now-7d","now"]}'::jsonb  AS d7,
 '[{"operator":"IS","field":"event.eventType","value":"alert"},{"operator":"IS","field":"event.alert.action","value":"blocked"}]'::jsonb AS blk,
 '[{"operator":"CONTAIN","field":"raw","value":"CUSTOM"},{"operator":"CONTAIN","field":"raw","value":"scanner"}]'::jsonb AS loc;

CREATE TEMP TABLE n (nom text, descr text, src text, filtres jsonb);
INSERT INTO n SELECT * FROM (VALUES
 ('Scanners - Modat bloqué (24 h)', 'Alertes bloquées par la règle 1000048 (liste scanner.modat.io)', 'id:1000018',
   (SELECT jsonb_build_array(h24) || blk || '[{"operator":"IS","field":"event.alert.signature_id","value":"1000048"}]' FROM f)),
 ('Scanners - BinaryEdge bloqué (24 h)', 'Alertes bloquées par les règles 1000060 et suivantes (API minions BinaryEdge)', 'id:1000018',
   (SELECT jsonb_build_array(h24) || blk || '[{"operator":"CONTAIN","field":"raw","value":"CUSTOM"},{"operator":"CONTAIN","field":"raw","value":"BinaryEdge"}]' FROM f)),
 ('Scanners - Group-IB bloqué (24 h)', 'Alertes bloquées par la règle 1000049', 'id:1000018',
   (SELECT jsonb_build_array(h24) || blk || '[{"operator":"IS","field":"event.alert.signature_id","value":"1000049"}]' FROM f)),
 ('Scanners - Censys hors NF bloqué (24 h)', 'Alertes bloquées par la règle 1000050 (plages officielles absentes de NF)', 'id:1000018',
   (SELECT jsonb_build_array(h24) || blk || '[{"operator":"IS","field":"event.alert.signature_id","value":"1000050"}]' FROM f)),
 ('Scanners - Règles locales bloquées (24 h)', 'Toutes les règles CUSTOM DROP de scanners (Modat, BinaryEdge, Group-IB, Censys)', 'id:1000018',
   (SELECT jsonb_build_array(h24) || blk || loc FROM f)),
 ('Scanners - Carte règles locales (24 h)', 'Adresses bloquées par les règles locales de scanners', 'name:Suricata - NF Scanners Map',
   (SELECT jsonb_build_array(h24) || blk || loc FROM f)),
 ('Scanners - Fournisseurs, règles locales (7 j)', 'Fournisseurs (ASO) des adresses bloquées par les règles locales de scanners', 'name:Top 10 blocked Suricata',
   (SELECT jsonb_build_array(d7) || blk || loc FROM f)),
 ('Scanners - Adresses bloquées, règles locales (7 j)', 'Adresses bloquées par les règles locales de scanners', 'id:1000020',
   (SELECT jsonb_build_array(d7) || blk || loc FROM f)),
 ('Scanners - Règles locales par heure (24 h)', 'Chronologie des alertes bloquées par les règles locales de scanners', 'name:Suricata - Timeline Alertes',
   (SELECT jsonb_build_array(h24) || blk || loc FROM f))
) t;

INSERT INTO utm_visualization
  (id, name, description, created_date, user_created, chart_config, chart_type,
   filters, id_pattern, aggregation, event_type, chart_action, system_owner)
SELECT (SELECT MAX(id) FROM utm_visualization WHERE id >= 1000000) + ROW_NUMBER() OVER (ORDER BY n.nom),
  n.nom, n.descr, NOW(), 'admin', v.chart_config, v.chart_type, n.filtres::text,
  v.id_pattern, v.aggregation, NULL, v.chart_action, false
FROM n JOIN utm_visualization v
  ON v.id   = (CASE WHEN n.src LIKE 'id:%'   THEN substr(n.src,4)::bigint END)
  OR v.name = (CASE WHEN n.src LIKE 'name:%' THEN substr(n.src,6) END)
WHERE NOT EXISTS (SELECT 1 FROM utm_visualization x WHERE x.name = n.nom);

SELECT id, name, chart_type, id_pattern FROM utm_visualization WHERE name LIKE 'Scanners - %' ORDER BY id;
-- Libellés hérités des visualisations copiées
UPDATE utm_visualization
SET aggregation  = replace(replace(aggregation,  'Top IP scanners NF bloquées', 'Adresses bloquées'), 'NF Scanners Blocked', 'Alertes bloquées'),
    chart_config = replace(replace(chart_config, 'Top IP scanners NF bloquées', 'Adresses bloquées'), 'NF Scanners Blocked', 'Alertes bloquées'),
    modified_date = NOW()
WHERE name LIKE 'Scanners - %' AND (aggregation LIKE '%NF%' OR chart_config LIKE '%NF%');
COMMIT;
