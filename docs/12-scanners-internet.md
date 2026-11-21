---
title: "Chapitre 12 : Scanners Internet, mesurer et combler les trous des règles NF | DoIt4Everyone"
description: "Mesure de la couverture des règles NF face aux scanners Internet connus (liste OpenFilters et trafic réel sur 30 jours), règles Suricata locales régénérées depuis les listes officielles (Modat, BinaryEdge, Censys, Group-IB) et tableau de bord UTMStack « Scanners Internet »."
lang: fr
---
<style>
  header, footer { display: none !important; }
  .wrapper {
    max-width: 900px !important;
    margin: 0 auto !important;
    float: none !important;
    position: relative !important;
    padding: 40px 20px !important;
    font-family: "Helvetica Neue", Helvetica, Arial, sans-serif !important;
    font-size: 1.1em !important;
  }
  section {
    width: 100% !important;
    float: none !important;
    margin: 0 !important;
  }
  h1, h2 { text-align: center; }
  table { width: 100%; display: table; margin: 20px 0; }
</style>

# Chapitre 12 : Scanners Internet

> [← Retour à l'index](../)

## Sommaire

- [Point de départ : une adresse sur trois laissée passer](#point-de-départ--une-adresse-sur-trois-laissée-passer)
- [Mesurer la couverture théorique](#mesurer-la-couverture-théorique)
- [Mesurer ce qui frappe réellement](#mesurer-ce-qui-frappe-réellement)
- [Règles locales : principes communs](#règles-locales--principes-communs)
- [Modat (sid 1000048)](#modat-sid-1000048)
- [BinaryEdge (sid 1000060 à 1000079)](#binaryedge-sid-1000060-à-1000079)
- [Group-IB (sid 1000049) et Censys (sid 1000050)](#group-ib-sid-1000049-et-censys-sid-1000050)
- [Ce que le lab ne bloque pas, et pourquoi](#ce-que-le-lab-ne-bloque-pas-et-pourquoi)
- [Vérifier l'absence de double comptage](#vérifier-labsence-de-double-comptage)
- [Tableau de bord « Scanners Internet »](#tableau-de-bord--scanners-internet-)
- [Limites](#limites)

---

Les règles NF de networkforensic.dk (chapitre 07) bloquent en `drop` les scanners Internet connus : Shodan, Censys, Shadowserver, Onyphe et des dizaines d'autres. Ce chapitre répond à une question simple : **que laissent-elles passer ?** Il décrit la méthode de mesure, les règles locales ajoutées pour combler les trous qui comptent vraiment, et le tableau de bord qui permet de suivre le résultat.

Toutes les mesures ont été faites dans le lab entre le 17 et le 21 novembre 2026, sur UTMStack v11.3 CE et OPNsense 26.1 (Suricata 8).

---

## Point de départ : une adresse sur trois laissée passer

Le 17 novembre 2026, une vérification sur la plateforme Magnify de Modat (un moteur de recherche d'équipements exposés, du même type que Shodan) montre que l'adresse publique du lab y est référencée. Les règles NF couvrent pourtant Modat. La comparaison avec la liste officielle des sondes Modat, publiée sur `https://scanner.modat.io/ipv4.txt`, donne l'explication :

| Liste officielle Modat | Valeur |
|---|---|
| Plages publiées | 37 |
| Adresses | 195 |
| Adresses absentes des règles NF | **64**, soit une sur trois |

Les règles NF reposent sur des listes maintenues à la main, qui prennent du retard quand un scanner ajoute des sondes. Si Modat passe à travers, d'autres scanners passent aussi. Il fallait le mesurer pour tous, pas seulement pour celui qu'on avait remarqué.

---

## Mesurer la couverture théorique

### La liste de référence

Le dépôt GitHub [OpenFilters/internet-scanners](https://github.com/OpenFilters/internet-scanners) rassemble les plages d'adresses des scanners Internet connus, une organisation par fichier (`cidr/<organisation>_v4.txt`). Au moment de la mesure (mise à jour du 15 novembre 2026), il couvre **75 organisations et 77 975 adresses IPv4**, sous licence Unlicense.

> ⚠️ C'est une liste **communautaire**. Pour Modat, elle contient des plages /24 plus larges que la liste officielle. Elle sert ici d'outil de mesure, pas de liste de blocage : chaque règle locale décrite plus bas repose sur une liste officielle ou sur une vérification indépendante.

### Extraire les adresses des règles NF

Sur OPNsense, toutes les adresses et plages présentes dans les règles NF actives :

```sh
grep -hE '^(drop|alert)' /usr/local/etc/suricata/opnsense.rules/NF-*.rules \
  | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}(/[0-9]{1,2})?' | sort -u > /tmp/nf-all.txt
wc -l /tmp/nf-all.txt
```

Dans le lab, la liste contient 1 219 entrées. Le filtre `^(drop|alert)` écarte les règles désactivées (lignes commençant par `#alert`), qui ne protègent plus rien, ainsi que les commentaires, où figurent des numéros de version qui ressemblent à des adresses (`2.9.16.1`, `2.8.18.0`). La liste inclut en revanche des adresses qui ne sont pas des scanners (serveurs DNS publics, adresses de destination de certaines règles), ce qui ne fausse pas la mesure : seules les adresses présentes dans les listes de scanners sont comptées.

### Calculer la couverture par organisation

Le script [`scripts/scanners/scanners-couverture.py`](https://github.com/doit4everyone/utmstack-lab/blob/main/scripts/scanners/scanners-couverture.py) (Python 3, sans dépendance) fusionne les plages et calcule, pour chaque organisation, combien de ses adresses sont couvertes par les règles :

```bash
git clone https://github.com/OpenFilters/internet-scanners.git
python3 scanners-couverture.py couverture nf-all.txt internet-scanners/cidr modat-officiel.txt
```

Le dernier argument, facultatif, ajoute des listes déjà couvertes par des règles locales (ici la liste officielle Modat, couverte par la règle 1000048).

**Résultat : les règles NF couvrent 30 % des adresses connues** (23 661 sur 77 975). Les plus gros trous :

| Organisation | Adresses | Couvertes | Manquantes |
|---|---|---|---|
| Tenable ASM | 6 339 | 0 % | 6 339 |
| Strechoid | 7 474 | 24 % | 5 653 |
| Intruder | 5 448 | 0 % | 5 448 |
| BitSight | 5 376 | 0 % | 5 376 |
| Hunter (Qianxin) | 3 617 | 0 % | 3 617 |
| BinaryEdge | 3 805 | 7 % | 3 520 |
| IPinfo | 2 702 | 1 % | 2 669 |
| Alpha Strike Labs | 2 560 | 0 % | 2 560 |
| Palo Alto Networks (Xpanse) | 5 632 | 59 % | 2 304 |
| Censys | 5 120 | 70 % | 1 536 |
| Mandiant ASM | 1 268 | 0 % | 1 268 |

À l'inverse, Shadowserver, Rapid7, Onyphe, Netscout et Recyber sont couverts à plus de 98 %.

**Ce chiffre de 30 % ne suffit pas pour décider.** Une partie de ces organisations ne scanne pas tout Internet : Tenable, Intruder et Mandiant font de la gestion de surface d'attaque pour leurs clients et ne testent en principe que les cibles déclarées. Il faut donc croiser avec le trafic réellement reçu.

---

## Mesurer ce qui frappe réellement

### Exporter les adresses sources sur 30 jours

Sur la VM UTMStack, le script [`scripts/scanners/sources-30j.py`](https://github.com/doit4everyone/utmstack-lab/blob/main/scripts/scanners/sources-30j.py) interroge OpenSearch et produit une ligne par adresse source vue par Suricata : adresse, nombre d'événements, nombre d'événements bloqués.

```bash
python3 sources-30j.py > /root/sources-30j.txt
```

Il agrège sur `origin.ip.keyword`, un champ typé et agrégeable en v11.3 (les champs `event.*`, eux, ne le sont pas : voir le chapitre 04). Le comptage des blocages filtre sur `event.eventType` = `alert` et `event.alert.action` = `blocked`, pour ne pas compter deux fois le même paquet (l'événement `drop` porte aussi le bloc `alert`).

### Croiser avec les listes de scanners

```bash
python3 scanners-couverture.py croise nf-all.txt internet-scanners/cidr sources-30j.txt modat-officiel.txt
```

Le script écarte les adresses privées, puis indique pour chaque organisation les adresses vues, les événements, les blocages, et la part qui n'est couverte par aucune règle.

**Résultat sur 30 jours** (export du 17 novembre 2026) : 3 472 adresses publiques, 74 195 événements, dont 15 892 bloqués.

| Origine du trafic | Adresses | Événements | Part du trafic total |
|---|---|---|---|
| Scanners connus (présents dans la liste OpenFilters) | 1 582 | 23 302 | 31 % |
| dont couverts par les règles | 1 031 | 18 912 | 25 % |
| dont **non couverts** par les règles | **551** | **4 390** | **6 %** |
| Adresses hors de toute liste de scanners | 1 890 | 50 893 | 69 % |

Sur les 4 390 événements de scanners non couverts, 900 ont quand même été bloqués par d'autres règles.

L'écart entre la théorie et la pratique est net. **Sur le papier, les règles couvrent 30 % des adresses de scanners connues. Dans les faits, elles couvrent 81 % du trafic que ces scanners envoient réellement** (18 912 événements sur 23 302). Les scanners qui ne sont pas couverts sont, pour la plupart, ceux qui ne viennent jamais : Tenable, Intruder et Mandiant, les plus gros absents sur le papier, n'ont envoyé aucun paquet en 30 jours.

Les scanners qui passent réellement, par volume :

| Organisation | Adresses non couvertes | Événements | Bloqués quand même |
|---|---|---|---|
| BinaryEdge | 36 | 1 630 | 298 |
| Group-IB | 2 | 565 | 177 |
| Censys | 50 | 266 | 52 |
| BitSight | 68 | 264 | 60 |
| securityresearch.net | 1 | 229 | 0 |
| VirusTotal | 49 | 223 | 61 |
| FOFA | 4 | 174 | 2 |
| Infrawatch | 69 | 162 | 49 |
| Strechoid | 54 | 127 | 34 |

> ℹ️ Une même adresse peut figurer dans deux listes (Intruder utilise par exemple des sondes Tenable) : les totaux sont des ordres de grandeur.

Les 1 890 adresses hors de toute liste se répartissent en deux groupes. D'un côté, des hébergeurs (Linode, DigitalOcean) déjà en partie bloqués par d'autres règles : des scanners non déclarés ou des attaquants, qu'aucune liste ne couvrira. De l'autre, des adresses jamais bloquées dans des plages Microsoft, Fastly ou GitHub : le plus souvent du trafic légitime du lab, pas du scan.

---

## Règles locales : principes communs

Les trous qui comptent sont comblés par des règles locales dans `custom.rules` (chapitre 07, partie 6), avec les mêmes principes pour toutes :

1. **Une source officielle quand elle existe**, régénérée automatiquement chaque semaine, plutôt qu'une liste figée qui vieillira comme les règles NF.
2. **Une plage de SID réservée et vérifiée libre avant usage** : 1000048 à 1000050 pour les règles fixes, 1000060 à 1000079 pour les lots BinaryEdge.
3. **Un libellé commun**, `CUSTOM DROP - <organisation> scanner`, qui permet de les filtrer ensemble dans UTMStack sans confondre avec les autres règles locales.
4. **Pas de recouvrement inutile avec NF** pour les règles fixes : seules les adresses absentes des règles NF y figurent.
5. **Test avant installation** avec `suricata -T -S <fichier>`, puis installation par `custom-rules-fix.sh`, qui copie `/conf/custom.rules` vers le fichier actif et recharge Suricata.

Avant de réserver une plage :

```sh
grep -cE 'sid:10000[67][0-9];' /conf/custom.rules
```

Le résultat doit être `0`.

---

## Modat (sid 1000048)

Modat est un service néerlandais (Modat B.V.) de cartographie des équipements exposés sur Internet, avec sa plateforme de recherche Magnify. Son comportement dans le lab est particulier : sur 14 jours, **1 599 événements sur seulement 3 ports, depuis 11 adresses**. À titre de comparaison, Akamai a produit 3 720 événements répartis sur 1 765 ports. Modat est donc insistant plutôt que large : il revient très souvent sur les mêmes services.

### La règle

Une seule règle couvre les 37 plages officielles :

```
drop ip [23.111.14.183/32,23.111.14.184/29,...,212.73.148.52/32] any -> $HOME_NET any (msg:"CUSTOM DROP - Modat scanner (liste scanner.modat.io/ipv4.txt)"; classtype:attempted-recon; priority:1; sid:1000048; rev:1;)
```

Elle n'est pas écrite à la main : le script de régénération la produit depuis la liste publiée.

### Régénération hebdomadaire

Le script [`scripts/modat-rule-update.sh`](https://github.com/doit4everyone/utmstack-lab/blob/main/scripts/modat-rule-update.sh), placé dans `/conf/modat-rule-update.sh` sur OPNsense :

1. télécharge la liste officielle ;
2. la valide : au moins 10 lignes, chaque ligne est un CIDR valide ;
3. génère la règle et la teste avec `suricata -T -S` ;
4. ne remplace la ligne 1000048 dans `/conf/custom.rules` que si la liste a changé, puis lance `custom-rules-fix.sh` ;
5. en cas d'erreur, garde l'ancienne règle et l'écrit dans `/var/log/modat-rule-update.log` et dans syslog (`modat-rule`).

Cron : `/conf/modat-rule-update`, copié dans `/etc/cron.d/` par le hook `98-soar-ban` :

```
30 4 * * 1 root /usr/local/bin/modat-rule-update.sh
```

Installation, dans `sh` sur OPNsense :

```sh
fetch -o /conf/modat-rule-update.sh https://raw.githubusercontent.com/doit4everyone/utmstack-lab/main/scripts/modat-rule-update.sh
chmod 755 /conf/modat-rule-update.sh
echo '30 4 * * 1 root /usr/local/bin/modat-rule-update.sh' > /conf/modat-rule-update
cp /conf/modat-rule-update.sh /usr/local/bin/ && cp /conf/modat-rule-update /etc/cron.d/
/usr/local/bin/modat-rule-update.sh; tail -2 /var/log/modat-rule-update.log
```

Lignes à ajouter dans le hook `/usr/local/etc/rc.syshook.d/start/98-soar-ban`, avant `exit 0` :

```sh
cp /conf/modat-rule-update.sh /usr/local/bin/modat-rule-update.sh && chmod +x /usr/local/bin/modat-rule-update.sh
cp /conf/modat-rule-update /etc/cron.d/modat-rule-update
```

Premiers blocages observés le jour même de l'installation, depuis 85.217.140.10 et 85.217.140.15.

---

## BinaryEdge (sid 1000060 à 1000079)

BinaryEdge (propriété de l'assureur cyber Coalition) est **le principal trou réel** : 36 adresses non couvertes, 1 630 événements en 30 jours, dont une seule adresse (45.79.40.209) à l'origine de 390 événements sans aucun blocage.

### Source officielle

BinaryEdge publie la liste de ses sondes sur `https://api.binaryedge.io/v1/minions`, en JSON et sans clé d'API :

```sh
fetch -qo - https://api.binaryedge.io/v1/minions | head -c 200
```

Le 17 novembre 2026, elle contenait **3 805 adresses /32**, hébergées chez AWS, Linode ou DigitalOcean. Ces sondes changent souvent : la régénération hebdomadaire est indispensable.

### Une règle par lot de 300 adresses

Le script découpe la liste en **lots de 300 adresses, une règle par lot**, plutôt que de mettre 3 805 adresses dans une seule règle. Une ligne fait ainsi environ 4,6 Ko, et on évite de dépendre d'une limite de longueur de règle propre à la version de Suricata. Avec 3 805 adresses, on obtient 13 règles (sid 1000060 à 1000072). La plage réservée va jusqu'à 1000079, soit 6 000 adresses au maximum. Au-delà, le script refuse la mise à jour et le signale.

```
drop ip [3.64.29.106,3.64.190.196,...] any -> $HOME_NET any (msg:"CUSTOM DROP - BinaryEdge scanner (api.binaryedge.io/v1/minions, lot 1/13)"; classtype:attempted-recon; priority:1; sid:1000060; rev:1;)
```

### Le script

[`scripts/binaryedge-rule-update.sh`](https://github.com/doit4everyone/utmstack-lab/blob/main/scripts/binaryedge-rule-update.sh) suit la même logique que celui de Modat. Il extrait les adresses du JSON, vérifie qu'il y en a au moins 100, génère et teste les règles, et ne touche à `custom.rules` que si quelque chose a changé. Il ne retire que les lignes portant son propre libellé, les autres règles locales restent intactes. Il garde la version précédente dans `/conf/custom.rules.prec`.

Il accepte une option `-n` qui génère et teste les règles **sans rien installer**, à lancer avant la première installation :

```sh
fetch -o /conf/binaryedge-rule-update.sh https://raw.githubusercontent.com/doit4everyone/utmstack-lab/main/scripts/binaryedge-rule-update.sh
chmod 755 /conf/binaryedge-rule-update.sh
/conf/binaryedge-rule-update.sh -n
# TEST : 3805 adresses, 13 règles acceptées par suricata -T, rien installé
```

Installation, dans `sh` sur OPNsense :

```sh
cp /usr/local/etc/rc.syshook.d/start/98-soar-ban /root/98-soar-ban.bak
sed -i '' -e '/modat-rule-update/{p;s/modat/binaryedge/g;}' /usr/local/etc/rc.syshook.d/start/98-soar-ban
echo '40 4 * * 1 root /usr/local/bin/binaryedge-rule-update.sh' > /conf/binaryedge-rule-update
cp /conf/binaryedge-rule-update.sh /usr/local/bin/ && cp /conf/binaryedge-rule-update /etc/cron.d/
/usr/local/bin/binaryedge-rule-update.sh; tail -2 /var/log/binaryedge-rule-update.log
grep -c 'CUSTOM DROP - BinaryEdge' /conf/custom.rules
```

La commande `sed` duplique dans le hook chaque ligne Modat en version BinaryEdge. Le cron passe le lundi à 4 h 40, dix minutes après Modat.

---

## Group-IB (sid 1000049) et Censys (sid 1000050)

Ces deux scanners produisent moins de trafic non couvert, et une règle fixe suffit.

**Group-IB** ne publie pas de liste officielle connue. La règle reprend ses **16 adresses fixes** de la liste communautaire, sans les 3 déjà présentes dans les règles NF. L'attribution est vérifiée par le DNS inverse avant installation :

```sh
drill -x 89.248.172.11 | grep PTR
# 11.172.248.89.in-addr.arpa. 3600 IN PTR asm.group-ib.com.
```

**Censys** publie ses plages sur sa page d'exclusion de la collecte (`docs.censys.com/docs/opt-out-of-data-collection`, 16 plages /24 lors de la mise à jour du 28 octobre 2026). Les règles NF en couvrent 12. La règle 1000050 ajoute les 4 manquantes : `66.132.148.0/24`, `66.132.186.0/24`, `66.132.195.0/24` et `66.132.224.0/24`.

```
drop ip [80.82.65.153,80.82.70.118,80.82.70.133,80.82.70.228,80.82.70.40,89.248.171.23,89.248.171.24,89.248.172.9,89.248.172.10,89.248.172.11,89.248.172.12,89.248.172.14,89.248.172.33,94.102.49.128,94.102.49.210,94.102.63.23] any -> $HOME_NET any (msg:"CUSTOM DROP - Group-IB scanner (adresses fixes hors NF)"; classtype:attempted-recon; priority:1; sid:1000049; rev:1;)
drop ip [66.132.148.0/24,66.132.186.0/24,66.132.195.0/24,66.132.224.0/24] any -> $HOME_NET any (msg:"CUSTOM DROP - Censys scanner (plages officielles hors NF)"; classtype:attempted-recon; priority:1; sid:1000050; rev:1;)
```

Après avoir écrit ces deux lignes complètes dans `/tmp/new.rules`, test puis installation :

```sh
suricata -T -c /usr/local/etc/suricata/suricata.yaml -S /tmp/new.rules > /dev/null 2>&1 && echo TEST_OK
cp /conf/custom.rules /conf/custom.rules.prec && cat /tmp/new.rules >> /conf/custom.rules && /usr/local/bin/custom-rules-fix.sh
```

Ces deux règles sont fixes : la page Censys est à revérifier de temps en temps, à la main.

---

## Ce que le lab ne bloque pas, et pourquoi

| Organisation | Décision | Raison |
|---|---|---|
| Tenable, Intruder, Mandiant | rien | jamais vus en 30 jours ; ils ne scannent en principe que les cibles de leurs clients |
| VirusTotal, Strechoid | rien | adresses Google Cloud (VirusTotal) et Azure (Strechoid) partagées et réattribuées, très peu d'événements par adresse : le risque de bloquer un jour un service légitime dépasse le gain |
| Infrawatch | rien pour l'instant | plages dédiées, mais 162 événements répartis sur 69 adresses en 30 jours : gain trop faible |
| BitSight, FOFA | rien pour l'instant | intérêt modéré, à reconsidérer si leur volume augmente |
| securityresearch.net | rien | une seule adresse, à surveiller |

---

## Vérifier l'absence de double comptage

Une adresse peut être couverte à la fois par une règle NF et par une règle locale : c'est le cas de 131 des 195 adresses Modat et d'environ 285 adresses BinaryEdge. Si Suricata produisait deux alertes pour le même paquet, les compteurs d'événements bloqués compteraient double.

Vérification sur 24 heures pour 85.217.140.10, couverte par NF et par la 1000048 :

```bash
CID=$(docker ps -qf name=utmstack_node1)
for F in '{"term":{"event.alert.signature_id":"1000048"}}' '{"prefix":{"event.alert.signature":"NF - "}}' '{"match_all":{}}'; do
  docker exec -i $CID curl -sk -K - -H 'Content-Type: application/json' "https://localhost:9200/v11-log-suricata-*/_count" \
    -d "{\"query\":{\"bool\":{\"filter\":[{\"term\":{\"origin.ip\":\"85.217.140.10\"}},{\"term\":{\"event.eventType\":\"alert\"}},{\"range\":{\"@timestamp\":{\"gte\":\"now-24h\"}}},$F]}}}" < /root/.os.curl; echo
done
```

Résultat : 3 alertes 1000048, 20 alertes NF, 23 alertes au total. **Chaque alerte porte une seule signature**, les deux règles n'ont pas répondu au même paquet. Les compteurs restent justes.

---

## Tableau de bord « Scanners Internet »

Le tableau de bord rassemble les règles NF et les règles locales. Les 9 visualisations « Scanners - » sont créées en SQL par copie de visualisations existantes, selon la méthode du chapitre 04. Le script complet est dans le dépôt : [`configs/utmstack/scanners-dashboard.sql`](https://github.com/doit4everyone/utmstack-lab/blob/main/configs/utmstack/scanners-dashboard.sql).

```bash
docker exec -i $(docker ps -qf name=postgres | head -1) psql -U postgres -d utmstack < scanners-dashboard.sql
```

Il sauvegarde d'abord la table `utm_visualization`, ne recrée pas une visualisation qui existe déjà, et liste ce qu'il a créé.

| Visualisation | Type | Période | Filtre propre |
|---|---|---|---|
| Suricata - Count NF Blocked | compteur | 24 h | `raw` contient `NF` (chapitre 04) |
| Suricata - Scanners NF distincts (24 h) | compteur | dernière heure | statistiques SOC_STATS (chapitre 04) |
| Scanners - Règles locales bloquées (24 h) | compteur | 24 h | `raw` contient `CUSTOM` et `scanner` |
| Scanners - Modat bloqué (24 h) | compteur | 24 h | `event.alert.signature_id` = 1000048 |
| Scanners - BinaryEdge bloqué (24 h) | compteur | 24 h | `raw` contient `CUSTOM` et `BinaryEdge` |
| Scanners - Group-IB bloqué (24 h) | compteur | 24 h | `event.alert.signature_id` = 1000049 |
| Scanners - Censys hors NF bloqué (24 h) | compteur | 24 h | `event.alert.signature_id` = 1000050 |
| Suricata - NF Scanners Map | carte | 24 h | `raw` contient `NF` |
| Scanners - Carte règles locales (24 h) | carte | 24 h | `raw` contient `CUSTOM` et `scanner` |
| Scanners - Règles locales par heure (24 h) | courbe | 24 h | idem |
| Suricata - Scanners NF distincts par jour | courbe | 30 jours | statistiques SOC_STATS |
| Scanners - Fournisseurs, règles locales (7 j) | barres | 7 jours | idem, regroupé par `origin.geolocation.aso.keyword` |
| Scanners - Adresses bloquées, règles locales (7 j) | table | 7 jours | idem, regroupé par `origin.ip.keyword` |

Toutes les visualisations « Scanners - » filtrent aussi sur `event.eventType` = `alert` et `event.alert.action` = `blocked`. Le couple `CUSTOM` et `scanner` exclut la règle locale r00ts3c du chapitre 07, qui porte aussi le préfixe `CUSTOM DROP`.

**Contrôle de cohérence :** le compteur « Règles locales bloquées » doit être égal à la somme des quatre compteurs Modat, BinaryEdge, Group-IB et Censys. Au premier affichage : 4 = 4 + 0 + 0 + 0. Les compteurs à 0 pendant quelques jours n'indiquent pas un filtre cassé : ces scanners ne passent pas tous les jours.

### Deux pièges rencontrés

**L'ordre d'évaluation d'un `OR` en PostgreSQL n'est pas garanti.** La première version du script désignait la visualisation source soit par son ID (`id:1000018`), soit par son nom (`name:...`), avec une jointure du type `(src LIKE 'id:%' AND v.id = substr(src,4)::bigint) OR (...)`. PostgreSQL a évalué la conversion en `bigint` sur une ligne « name: », et la transaction entière a été annulée (`invalid input syntax for type bigint`). Sur une base de test, l'ordre avait été favorable par hasard. La version publiée utilise des `CASE`, dont l'ordre d'évaluation est garanti.

**Les libellés internes sont copiés avec la visualisation.** Les compteurs créés par copie affichaient « NF Scanners Blocked » et le tableau « Top IP scanners NF bloquées », libellés stockés dans `aggregation` ou `chart_config`. Le script les remplace par « Alertes bloquées » et « Adresses bloquées ». Après une copie, il faut toujours vérifier ces libellés, sinon le tableau de bord induit en erreur.

> ⚠️ **Données manquantes les 20 et 21 novembre 2026.** Pendant ces deux jours, OpenSearch a refusé de créer les index du jour (limite de 1000 shards atteinte) : les courbes du tableau de bord présentent un trou à ces dates. Cause et correction : [chapitre 01, limite de shards](01-installation.html#11-limite-de-1000-shards-sur-un-nœud-unique).

---

## Limites

- **Bloquer les scanners connus ne protège pas un service exposé.** Cela retire l'adresse du lab des catalogues publics (Shodan, Censys, Modat) et réduit le bruit, mais les attaquants scannent depuis leurs propres adresses, absentes de toute liste. La seule vraie protection d'un service sensible reste de ne pas l'exposer.
- **Les listes changent.** Les règles régénérées (Modat, BinaryEdge) suivent les listes officielles ; les règles fixes (Group-IB, Censys) et les règles NF vieillissent. La mesure de ce chapitre est à refaire périodiquement, par exemple chaque trimestre, avec les mêmes scripts.
- **La liste OpenFilters est communautaire.** Elle sert à mesurer, pas à bloquer.
- **Les adresses cloud sont réattribuées.** Une sonde BinaryEdge hébergée chez AWS peut appartenir à quelqu'un d'autre la semaine suivante. Le risque est limité par la régénération hebdomadaire et par le fait que la règle ne vise que le trafic entrant vers `$HOME_NET`.

---

> ℹ️ *Testé sur UTMStack v11.3 CE, OPNsense 26.1, Suricata 8, novembre 2026.*

---

[← Règles de corrélation YAML](11-correlations-yaml.md) | [Retour à l'index →](../)
