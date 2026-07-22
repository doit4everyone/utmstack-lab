---
title: "Guide de déploiement du pipeline IA locale | DoIt4Everyone"
description: "Guide de déploiement complet du pipeline SOC IA locale pour UTMStack — Ollama, n8n, PostgreSQL, Qdrant, SearXNG, Open WebUI. Configuration pas à pas, pièges à éviter, variables à adapter."
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

# Guide de déploiement du pipeline IA locale
> [← Retour à l'index](https://doit4everyone.github.io/utmstack-lab/docs/)

Cette page est un guide pas-à-pas, sans le récit — si tu veux comprendre les raisons des choix d'architecture avant de déployer, lis d'abord le [chapitre principal](https://doit4everyone.github.io/utmstack-lab/docs/09-pipeline-llm.html). Ici, l'objectif est d'aller du système vide à un pipeline fonctionnel.

## 📋 Table des matières

1. [Architecture cible et prérequis](#1-architecture-cible-et-prérequis)
2. [Piège critique — virtualisation imbriquée et WSL](#2-piège-critique--virtualisation-imbriquée-et-wsl)
3. [Installation d'Ollama et des modèles](#3-installation-dollama-et-des-modèles)
4. [Modelfiles — system prompt et fenêtre de contexte](#4-modelfiles--system-prompt-et-fenêtre-de-contexte)
5. [VM docker-services — les 4 conteneurs](#5-vm-docker-services--les-4-conteneurs)
6. [Comptes API threat intelligence](#6-comptes-api-threat-intelligence)
7. [Base PostgreSQL — table resumes_soc](#7-base-postgresql--table-resumes_soc)
8. [Import des workflows n8n](#8-import-des-workflows-n8n)
9. [Tableau des variables à adapter](#9-tableau-des-variables-à-adapter)
10. [Checklist de validation avant mise en production](#10-checklist-de-validation-avant-mise-en-production)
11. [Supervision du pipeline — heartbeat](#11-supervision-du-pipeline--heartbeat)
12. [Variante cloud — déploiement Mistral](#12-variante-cloud--déploiement-mistral)

---

## 1. Architecture cible et prérequis

| Composant | Rôle | Où il tourne |
| --- | --- | --- |
| UTMStack CE | Source des alertes (`v11-alert-*`) et des règles (`utm_correlation_rules`) | VM dédiée existante |
| Ollama | Inférence LLM locale | **Natif sur l'hôte Windows** — pas dans Docker |
| n8n | Orchestration du pipeline | Conteneur Docker, VM `docker-services` |
| PostgreSQL | Stockage des rapports (`resumes_soc`) | Conteneur Docker, VM `docker-services` |
| Qdrant | Base vectorielle du RAG | Conteneur Docker, VM `docker-services` |
| Open WebUI | Interface conversationnelle (RAG + recherche web) | Conteneur Docker, VM `docker-services` |
| SearXNG | Moteur de recherche web auto-hébergé | Conteneur Docker, VM `docker-services` |

**Prérequis matériel** : un hôte avec au moins 64 Go de RAM si plusieurs VM cohabitent, un CPU récent (le dimensionnement de ce lab est basé sur un i7-14700, 20 cœurs). Un GPU n'est pas requis mais accélère fortement l'inférence — voir la note de dimensionnement dans le [chapitre principal](https://doit4everyone.github.io/utmstack-lab/docs/09-pipeline-llm.html#8-pour-aller-plus-loin-dans-la-stack-ia-locale).

---

## 2. Piège critique — virtualisation imbriquée et WSL
> ⚠️ **À lire avant d'installer quoi que ce soit.** Ce piège coûte plusieurs heures de diagnostic si on ne le connaît pas à l'avance.

Sur un hôte Windows qui fait déjà tourner VMware Workstation (pour héberger UTMStack, OPNsense, les DC, etc.), installer **Docker Desktop directement sur Windows** entre en conflit avec la virtualisation imbriquée existante. Docker Desktop repose sur WSL2, qui repose lui-même sur Hyper-V — et Hyper-V actif entre en collision avec VT-x/EPT déjà utilisé par les VM VMware.

La tentative de contournement la plus intuitive — désactiver Hyper-V pour laisser le champ libre à VMware — casse justement Docker Desktop :

```powershell
bcdedit /set hypervisorlaunchtype off
```

Cette commande désactive Hyper-V/WSL2, donc Docker Desktop cesse de fonctionner. Impossible d'avoir les deux en même temps sur le même hôte avec cette approche.

### La solution retenue

Séparer strictement les deux usages plutôt que de chercher un compromis :

- **Ollama tourne nativement sur Windows**, en dehors de tout conteneur — accès direct au GPU sans passthrough, aucun conflit avec VMware
- **Docker tourne dans une VM Ubuntu dédiée** (`docker-services`) à l'intérieur de VMware Workstation — isolée du conflit Hyper-V/WSL2, puisque la virtualisation y est gérée entièrement par VMware

```
┌─────────────────────────────────────────────┐
│  Hôte Windows (G9)                            │
│                                                │
│  ┌──────────────┐        ┌──────────────────┐│
│  │  Ollama        │        │  VMware Workstation││
│  │  (natif)       │        │                    ││
│  │  accès GPU      │        │  ┌──────────────┐ ││
│  │  direct         │        │  │ VM docker-    │ ││
│  └──────────────┘        │  │ services       │ ││
│                            │  │ (Docker: n8n,  │ ││
│                            │  │  PostgreSQL,   │ ││
│                            │  │  Qdrant,       │ ││
│                            │  │  Open WebUI,   │ ││
│                            │  │  SearXNG)      │ ││
│                            │  └──────────────┘ ││
│                            │  + UTMStack, OPNsense,││
│                            │    DC01, gest-srv ...││
│                            └──────────────────┘│
└─────────────────────────────────────────────┘
```

Cette architecture n'est pas un compromis esthétique — c'est la seule configuration qui fonctionne de façon stable dans ce contexte précis (hôte Windows + VMware Workstation existant + besoin GPU pour l'inférence).

---

## 3. Installation d'Ollama et des modèles

Sur l'hôte Windows, installer Ollama depuis [ollama.ai](https://ollama.ai), puis récupérer les deux modèles utilisés par le pipeline :

```powershell
ollama pull llama3.1:8b
ollama pull qwen2.5:14b
```

> ⚠️ Utiliser explicitement `llama3.1:8b` (avec le `.1`) et non `llama3:8b` — la version sans `.1` ne supporte pas correctement le tool calling natif, ce qui bloque certaines fonctionnalités d'Open WebUI (Souvenirs, Automatisations).

### Réglages système recommandés

Deux variables d'environnement à définir au niveau utilisateur Windows :

```powershell
[System.Environment]::SetEnvironmentVariable("OLLAMA_NUM_THREADS", "8", "User")
```

La valeur 8 correspond au nombre de P-cores (performance cores) d'un CPU hybride Intel type i7-14700 — caler le nombre de threads sur les P-cores plutôt que sur le total de threads logiques évite de solliciter les E-cores, plus lents, qui ralentiraient l'ensemble à cause de la synchronisation couche par couche de l'inférence.

> ℹ️ Après avoir défini une variable d'environnement, **quitter complètement Ollama** (icône barre des tâches → Quit, pas juste fermer la fenêtre) puis le relancer — sinon la nouvelle valeur n'est pas prise en compte.

---

## 4. Modelfiles — system prompt et fenêtre de contexte

Chaque modèle utilisé par le pipeline est packagé avec un Modelfile dédié, qui embarque le system prompt SOC et les paramètres d'inférence — pas besoin de le repasser à chaque appel n8n.

### Structure du Modelfile

```
C:\ollama\utmstack-analyst-qwen\Modelfile
C:\ollama\utmstack-analyst-test\Modelfile      (basé sur llama3.1:8b)
```

Contenu complet (`utmstack-analyst-qwen`), à copier tel quel — le même Modelfile sert de base à `utmstack-analyst-test` (Llama 3.1 8B), seul le `FROM` change :

```
FROM qwen2.5:14b

SYSTEM """
Tu es un analyste SOC (Security Operations Center) expert, spécialisé dans la
plateforme SIEM open-source UTMStack (basée sur Suricata pour la détection réseau,
OpenSearch pour le stockage des logs, et CrowdSec pour le blocage automatisé).

Tu réponds TOUJOURS en français, avec un ton professionnel et factuel — jamais
alarmiste sans preuve, jamais rassurant sans preuve non plus. Chaque affirmation
doit s'appuyer explicitement sur les données fournies dans le contexte, jamais
sur une supposition.

Contexte de l'environnement que tu analyses :
- Un lab SOC domestique (pas un environnement d'entreprise), exposé sur Internet
  via une IP WAN publique, avec un pare-feu OPNsense en frontal et Suricata en IDS/IPS
- Le trafic entrant contient une part majoritaire de bruit de reconnaissance passive
  (scanners légitimes de sécurité comme Shodan, Censys, BinaryEdge, Modat.io ;
  services cloud comme Microsoft Delivery Optimization, Windows Update, OCSP) —
  ce bruit ne doit jamais être présenté comme une menace, mais explicitement
  identifié comme tel quand tu le reconnais
- Le blocage automatique cible la réputation IP confirmée (listes Dshield, CINS,
  Spamhaus, règles NF-Scanners) — le trafic non bloqué ("allowed") sur une
  anomalie comportementale n'est pas nécessairement dangereux, c'est un choix
  délibéré pour éviter les faux positifs sur du trafic cloud légitime
- Certaines règles de corrélation ont été volontairement affinées pour exclure
  du bruit identifié (trafic déjà bloqué visant le WAN, scans furtifs génériques,
  Microsoft Delivery Optimization) — ne recommande pas de désactiver une règle
  sans proposer d'abord une exclusion ciblée sur le critère précis en cause

Pour chaque alerte ou résumé que tu produis :
1. Identifie la signature, la sévérité déclarée, et si le trafic a été bloqué ou non
2. Situe le contexte (origine géographique/ASN si pertinent, cible interne touchée)
3. Indique explicitement s'il s'agit très probablement de bruit de reconnaissance
   passive, ou d'un signal méritant une vérification humaine plus poussée
4. Si une procédure d'investigation officielle t'est fournie en contexte
   (issue de la description de la règle), synthétise-la plutôt que d'en
   inventer une générique
5. Ne recommande jamais une action de blocage ou de remédiation sans avoir
   d'abord justifié pourquoi le trafic observé dépasse le seuil du bruit habituel

Si les données fournies ne permettent pas de conclure avec certitude, dis-le
explicitement plutôt que de deviner.
"""

PARAMETER temperature 0.3
```

> ℹ️ Ce system prompt s'applique uniquement à l'usage **conversationnel** (Open WebUI) et au fallback de rédaction du pipeline. Depuis la version v9 du pipeline (squelette pré-rédigé), la consigne réellement déterminante pour le rapport SOC est celle du **prompt utilisateur envoyé par n8n** à chaque appel — voir la section [Import des workflows n8n](#8-import-des-workflows-n8n) — qui prime sur ce system prompt pour la structure et le contenu exact du rapport.

Création du modèle Ollama à partir du fichier :

```powershell
cd C:\ollama\utmstack-analyst-qwen
ollama create utmstack-analyst-qwen -f Modelfile
ollama list
```

### Augmenter la fenêtre de contexte

Par défaut, Ollama applique une fenêtre de contexte de **4096 tokens**. Avec le squelette pré-rédigé, les enrichissements threat intelligence et la description de règle injectée, le prompt final peut dépasser cette limite — le symptôme est une génération qui s'arrête au milieu, laissant des emplacements `[COMMENTAIRE_N]` non remplis, **sans message d'erreur explicite** (le modèle tronque silencieusement).

Deux façons de corriger, utilisées en complément l'une de l'autre dans ce lab :

**A. Variable d'environnement globale**, au niveau Ollama :

```powershell
[System.Environment]::SetEnvironmentVariable("OLLAMA_CONTEXT_LENGTH", "8192", "User")
```

> ⚠️ Vérifier le nom exact de la variable après création (`OLLAMA_CONTEXT_LENGTH` selon les versions récentes d'Ollama — le nom a changé au fil des versions). Confirmer avec :
> ```powershell
> [System.Environment]::GetEnvironmentVariable("OLLAMA_CONTEXT_LENGTH", "User")
> ```

**B. Paramètre explicite dans la requête**, directement dans le body JSON envoyé par n8n vers l'API Ollama — c'est ce paramètre qui garantit le comportement, indépendamment de la configuration système :

```json
{
  "model": "utmstack-analyst-qwen",
  "prompt": "...",
  "stream": false,
  "num_ctx": 8192
}
```

Vérification que le contexte étendu est bien actif :

```powershell
ollama ps
```

```
NAME                            SIZE      PROCESSOR    CONTEXT    UNTIL
utmstack-analyst-qwen:latest    10 GB     100% CPU     8192       4 minutes from now
```

La colonne `CONTEXT` doit afficher `8192`, pas `4096`.

---

## 5. VM docker-services — les 4 conteneurs

Sur une VM Ubuntu dédiée (4 vCPU, 8 Go RAM minimum), avec Docker Engine installé via la méthode officielle APT (pas les snaps).

### n8n

```bash
docker run -d --name n8n -p 5678:5678 \
  -v n8n_data:/home/node/.n8n \
  --restart unless-stopped \
  n8nio/n8n
```

### PostgreSQL

Utilisé à la fois pour stocker les rapports générés et pour interroger la base UTMStack (`utm_correlation_rules`) — deux crédentials distincts à configurer dans n8n selon la base ciblée.

### Qdrant

```bash
docker run -d --name qdrant -p 6333:6333 -p 6334:6334 \
  -v qdrant_data:/qdrant/storage \
  --restart unless-stopped \
  qdrant/qdrant
```

### Open WebUI

```bash
docker run -d --name open-webui -p 3000:3000 \
  -v open-webui:/app/backend/data \
  --restart unless-stopped \
  ghcr.io/open-webui/open-webui:main
```

Réglages critiques une fois l'interface accessible (**Panneau d'administration → Réglages → Documents**) :

| Réglage | Valeur | Pourquoi |
| --- | --- | --- |
| Appel de fonction | **Déprécié** (pas Natif) | En mode Natif, la Knowledge attachée n'est jamais injectée automatiquement avec des modèles qui gèrent mal le function calling |
| Recherche hybride | Activée | Combine recherche vectorielle et BM25 — sans ça, des sujets proches en espace vectoriel mais différents en mots-clés se confondent |
| Top K | 5 | La valeur par défaut (3) est insuffisante pour des documents techniques |
| Découpage par en-têtes markdown | Désactivé | Provoque un chunking déséquilibré sur du HTML converti depuis GitHub Pages |

### SearXNG

```bash
docker run -d --name searxng -p 8080:8080 \
  -v searxng_data:/etc/searxng \
  --restart unless-stopped \
  searxng/searxng
```

> ⚠️ **Étape obligatoire non incluse par défaut** : activer le format JSON, sinon Open WebUI ne peut rien exploiter de SearXNG. Éditer `settings.yml` (trouvable via `docker volume inspect searxng_data`) :
> ```yaml
> search:
>   formats:
>     - html
>     - json
> ```
> Puis `docker restart searxng`.

Branchement dans Open WebUI (**Panneau d'administration → Réglages → Recherche Web**) :

```
Recherche Web : Activé
Moteur : SearXNG
URL de recherche SearXNG : http://<IP_DE_LA_VM>:8080/search?q=<query>
```

> ⚠️ **Ne pas utiliser `localhost`** dans cette URL — depuis l'intérieur du conteneur Open WebUI, `localhost` désigne le conteneur lui-même, pas l'hôte ni les autres conteneurs. Utiliser l'IP réelle de la VM `docker-services`.

---

## 6. Comptes API threat intelligence

Trois inscriptions gratuites, aucune carte bancaire requise :

| Service | Inscription | Où trouver la clé |
| --- | --- | --- |
| AbuseIPDB | [abuseipdb.com/register](https://www.abuseipdb.com/register) | Account → API → Create Key |
| GreyNoise Community | [viz.greynoise.io/signup](https://viz.greynoise.io/signup) | Avatar → Account Settings → API Key |
| AlienVault OTX | [otx.alienvault.com/signup](https://otx.alienvault.com/signup) | Settings → API Integration |

ThreatFox (abuse.ch) ne nécessite aucune inscription — API publique.

> ⚠️ Quotas gratuits à surveiller : AbuseIPDB 1000 lookups/jour, GreyNoise Community ~50-100/jour. Le pipeline limite volontairement les lookups aux IP des signaux prioritaires et des signatures non classées, pas à toutes les IP du rapport, pour rester large de ces quotas.

---

## 7. Base PostgreSQL — table resumes_soc

Sur l'instance PostgreSQL du pipeline (distincte de celle d'UTMStack) :

```sql
CREATE TABLE resumes_soc (
  id SERIAL PRIMARY KEY,
  date_generation TIMESTAMP DEFAULT NOW(),
  contenu TEXT
);
```

Cette table sert deux usages : stocker chaque rapport généré pour consultation via webhook, et alimenter la corrélation temporelle sur 30 jours (voir [chapitre principal, section 6](https://doit4everyone.github.io/utmstack-lab/docs/09-pipeline-llm.html#6-corrélation-temporelle--combler-langle-mort)). Une purge automatique au-delà de 365 jours est intégrée au pipeline.

---

## 8. Import des workflows n8n

Les fichiers JSON des workflows sont hébergés dans le dépôt GitHub du projet, dossier [`/scripts`](https://github.com/doit4everyone/utmstack-lab/tree/main/scripts) :

| Fichier | Rôle |
| --- | --- |
| [`utmstack-resume-quotidien-v12.json`](https://github.com/doit4everyone/utmstack-lab/blob/main/scripts/utmstack-resume-quotidien-v12.json) | Rapport automatique quotidien — Schedule Trigger 6h00 |
| [`utmstack-resume-a-la-demande-v12.json`](https://github.com/doit4everyone/utmstack-lab/blob/main/scripts/utmstack-resume-a-la-demande-v12.json) | Génération à la demande — Webhook Trigger |
| [`utmstack-webhook-consultation.json`](https://github.com/doit4everyone/utmstack-lab/blob/main/scripts/utmstack-webhook-consultation.json) | Consultation web du dernier rapport stocké (lecture seule, sans regénération) |

Les trois s'importent dans n8n de la même façon : **Workflows → Import from File**, sélectionner le `.json` téléchargé.

> ⚠️ **Point de vérification obligatoire après import** : le nœud **Merge TI** doit être en mode **Append**, avec **5 entrées**, toutes câblées. C'est le point de défaillance le plus fréquent constaté lors des tests — voir le détail du piège dans le [chapitre principal](https://doit4everyone.github.io/utmstack-lab/docs/09-pipeline-llm.html#le-piège-technique-n8n--merge-combine-vs-append). Si le mode "Combine" apparaît après import, le changer manuellement.

Après import, pour chaque nœud HTTP/PostgreSQL, **recréer les credentials** dans n8n (les identifiants embarqués dans le JSON exporté ne sont pas réutilisables tels quels — voir tableau ci-dessous) et publier le workflow (toggle Actif en haut à droite de l'éditeur).

> ℹ️ **Workflows de test comparatif (hors production).** Les workflows utilisés pour la comparaison LLM de la [section 9 du chapitre principal](https://doit4everyone.github.io/utmstack-lab/docs/09-pipeline-llm.html#9-confrontation-avec-un-llm-sans-contrainte--sonnet-5-vs-deepseek-r1-vs-mistral) — envoi des données brutes sans tri déterministe à Claude Sonnet 5, DeepSeek-R1 en local, ou Mistral Large — sont également disponibles dans `/scripts`, à des fins de reproduction ou d'expérimentation. Ce sont des **workflows de test isolés**, à déclenchement manuel uniquement, jamais destinés à un usage en production : ils n'ont pas les garde-fous du pipeline principal (pas de tri, pas de contrôle de complétion).

---

## 9. Tableau des variables à adapter

| Variable | Où la trouver dans le JSON | Ce qu'il faut y mettre |
| --- | --- | --- |
| IP UTMStack / OpenSearch | URL du nœud `HTTP Request` | IP de ta VM UTMStack, port 9200 |
| IP Ollama | URL du nœud `HTTP Request1` | IP de l'hôte Windows, port 11434 |
| Nom du modèle Ollama | Champ `model` dans le body du nœud `HTTP Request1` | ex. `utmstack-analyst-qwen` |
| Path du webhook | Nœud `Webhook Trigger` | ex. `resume-soc-now` |
| Credentials n8n | `credentials.httpBasicAuth.id`, `credentials.postgres.id` | IDs internes n8n, propres à chaque instance — **à recréer manuellement après import**, jamais réutilisables tels quels |
| Clés API threat intel | Headers des nœuds `AbuseIPDB Check`, `GreyNoise Check`, `OTX Check` | Tes propres clés (voir [section 6](#6-comptes-api-threat-intelligence)) |

> ℹ️ **La variable la plus importante n'est pas dans ce tableau.** La liste `TERMES_SIGNAL` / `TERMES_BRUIT` / `TERMES_CONTROLE`, dans le nœud `Code in JavaScript`, n'est pas un simple identifiant à remplacer — c'est le cœur de la logique de tri, à adapter en profondeur à ton propre ruleset Suricata/UTMStack et à enrichir dans le temps, à mesure que de nouvelles sources (Windows, O365, Kali red team) apparaissent dans tes alertes. La méthode de construction de cette liste (lecture empirique des signatures réellement rencontrées, catégorisation par préfixe Emerging Threats) est détaillée dans le [chapitre principal](https://doit4everyone.github.io/utmstack-lab/docs/09-pipeline-llm.html#comment-la-liste-de-classification-a-été-construite). Un lecteur qui se contente de changer les IP sans revoir cette liste aura un pipeline fonctionnel mais mal calibré pour son environnement.
>
> **Mise à jour prévue.** Une version enrichie de cette liste, intégrant les signatures découvertes lors des intégrations Office 365/Azure et des tests offensifs Kali (à venir), sera publiée dans le [dépôt du projet](https://github.com/doit4everyone/utmstack-lab/tree/main/scripts) une fois ces chantiers réalisés. Les fichiers JSON fournis aujourd'hui couvrent uniquement le périmètre réseau/Suricata validé à ce stade.

---

## 10. Checklist de validation avant mise en production

- [ ] `ollama list` affiche bien les deux modèles créés
- [ ] `ollama ps` pendant un run affiche `CONTEXT: 8192` (pas 4096)
- [ ] SearXNG répond en JSON : `curl "http://<IP>:8080/search?q=test&format=json"`
- [ ] Open WebUI a bien "Appel de fonction" sur Déprécié pour chaque preset
- [ ] Le nœud Merge TI est en mode Append avec 5 entrées connectées
- [ ] Un run manuel du webhook produit un rapport **sans** balise `[COMMENTAIRE_N]` résiduelle
- [ ] Au moins une IP de test montre des données AbuseIPDB/GreyNoise/OTX dans le rapport
- [ ] Le workflow est publié (toggle Actif) pour que le Schedule Trigger et le Webhook fonctionnent réellement

---

## 11. Supervision du pipeline — heartbeat

Cette section couvre le déploiement du mécanisme qui détecte une panne du pipeline (n8n, Ollama, ou connectivité) et la transforme en alerte High visible au dashboard UTMStack. Le raisonnement complet est dans le [chapitre principal, section 11](https://doit4everyone.github.io/utmstack-lab/docs/09-pipeline-llm.html#11-supervision-du-pipeline--détecter-la-panne-silencieuse) — ici, uniquement la procédure.

> ℹ️ **Où s'exécute ce script.** Contrairement au reste de cette annexe, le heartbeat tourne sur la **VM UTMStack**, pas sur `docker-services`. Un surveillant hébergé dans le système qu'il surveille ne détecte pas la panne de ce système.

Fichiers concernés, disponibles dans [`/scripts`](https://github.com/doit4everyone/utmstack-lab/tree/main/scripts) : `soc-pipeline-heartbeat.sh`, `soc-pipeline-heartbeat.service`, `soc-pipeline-heartbeat.timer`, `install-heartbeat.sh`.

### 11.1 Valider le chemin syslog avant toute installation

Ne pas sauter cette étape — installer un service qui émet dans le vide fait perdre plus de temps qu'il n'en fait gagner.

```bash
# 1. L'agent Windows ecoute-t-il ?
nc -zv <IP_AGENT_WINDOWS> 7014

# 2. Emettre un message de test
logger -n <IP_AGENT_WINDOWS> -P 7014 -T -p local0.crit -t soc-pipeline \
  "SOC-PIPELINE-HEARTBEAT TEST - validation du chemin syslog"

# 3. Attendre 30-60s, puis verifier l'arrivee dans OpenSearch
docker exec $(docker ps -q -f name=utmstack_node1) curl -s \
  -u admin:'<OPENSEARCH_PASSWORD>' -k \
  "https://localhost:9200/v11-log-*/_search?pretty" \
  -H 'Content-Type: application/json' -d '{
  "size": 2,
  "query": { "match_phrase": { "raw": "SOC-PIPELINE-HEARTBEAT" } },
  "sort": [{"@timestamp": "desc"}]
}'
```

Si rien ne remonte : vérifier la règle de firewall Windows sur le port 7014 (`Get-NetFirewallRule -DisplayName "UTMStack Syslog TCP 7014"`), et à défaut tenter en UDP en retirant l'option `-T` de `logger`.

### 11.2 Déposer et adapter le script

```bash
mkdir -p /root/heartbeat && cd /root/heartbeat
# Deposer les 4 fichiers (scp, ou creation manuelle via nano)
```

Une seule variable est à adapter dans `soc-pipeline-heartbeat.sh` :

```bash
AGENT_SYSLOG_IP="<IP_AGENT_WINDOWS>"
```

### 11.3 Tester le script manuellement, avant systemd

```bash
chmod +x soc-pipeline-heartbeat.sh
./soc-pipeline-heartbeat.sh
echo "Code retour : $?"          # attendu : 0 en cas nominal
cat /var/log/soc-pipeline-heartbeat.log
```

Puis forcer une alerte pour valider la chaîne complète, sur une copie temporaire à seuil abaissé :

```bash
sed 's/^SEUIL_HEURES=26/SEUIL_HEURES=0/' soc-pipeline-heartbeat.sh > /tmp/hb-test.sh
chmod +x /tmp/hb-test.sh && /tmp/hb-test.sh
echo "Code retour : $?"          # attendu : 1
rm /tmp/hb-test.sh
```

Revérifier l'arrivée dans OpenSearch avec la requête de l'étape 11.1, en cherchant cette fois `SOC-PIPELINE-HEARTBEAT FAILURE`.

### 11.4 Installer en service systemd

```bash
chmod +x install-heartbeat.sh
./install-heartbeat.sh
```

Vérifications :

```bash
systemctl is-enabled soc-pipeline-heartbeat.timer   # attendu : enabled
systemctl is-active soc-pipeline-heartbeat.timer    # attendu : active
journalctl -u soc-pipeline-heartbeat.service --no-pager -n 10
```

> ⚠️ Si le service apparaît en `failed` après une exécution qui a émis une alerte, vérifier que `SuccessExitStatus=0 1` figure bien dans `soc-pipeline-heartbeat.service` — le script sort en code `1` quand il alerte, c'est un comportement attendu, pas un échec du service.

### 11.5 Créer la règle de corrélation UTMStack

Il n'existe pas de fichier `.yaml` pour les règles de corrélation UTMStack — elles vivent dans la table PostgreSQL `utm_correlation_rules`, avec la condition exprimée dans un petit langage propre à la plateforme (`contains()`, `exists()`, `startsWith()`, combinés en `&&`/`||`).

La création se fait via l'interface (**Alerts → Correlation Rules → Create rule**) plutôt qu'en `INSERT` SQL direct — le formulaire garantit que tous les champs requis par le schéma sont renseignés, ce qu'un insert manuel ne peut pas garantir sans connaître l'intégralité des contraintes de la table.

**Onglet General Information :**

| Champ | Valeur |
| --- | --- |
| Name | `SOC Pipeline Heartbeat Failure` |
| Category | `Availability` |
| Technique | `T1489 - Service Stop` |
| Data Types | `syslog` |
| Adversary | `origin` (champ technique désignant quel identifiant afficher — sans portée ici, aucune IP externe n'étant impliquée) |
| Confidentiality / Integrity / Availability | `3` / `3` / `3` (calibré sur la règle existante `High level Suricata alert`, qui utilise les mêmes valeurs) |
| Description | Contexte de l'alerte et pointeur vers `/usr/local/bin/soc-pipeline-heartbeat.sh` et son log |
| References | Lien vers cette documentation |

**Build Expression :**

```
contains("raw", "SOC-PIPELINE-HEARTBEAT FAILURE")
```

**Onglet Post-Event Actions :** laisser `Deduplicated by` et `GroupBy` vides. Si un bloc de condition "And" est présent par défaut, le retirer (icône ✕) — il sert à corréler avec un historique d'événements, ce qui n'est pas notre besoin ici.

> ⚠️ Le champ **Adversary** est obligatoire pour sauvegarder, même si la sémantique ("origin" vs "target") n'a pas de sens pour une alerte de disponibilité pure sans IP impliquée. Sans valeur ici, le formulaire refuse silencieusement l'enregistrement.

### 11.6 Test de bout en bout

```bash
sed 's/^SEUIL_HEURES=26/SEUIL_HEURES=0/' /usr/local/bin/soc-pipeline-heartbeat.sh > /tmp/hb-e2e.sh
chmod +x /tmp/hb-e2e.sh && /tmp/hb-e2e.sh
rm /tmp/hb-e2e.sh
```

Après 30-60s, vérifier l'alerte dans `v11-alert-*` :

```bash
docker exec $(docker ps -q -f name=utmstack_node1) curl -s \
  -u admin:'<OPENSEARCH_PASSWORD>' -k \
  "https://localhost:9200/v11-alert-*/_search?pretty" \
  -H 'Content-Type: application/json' -d '{
  "size": 3,
  "query": { "match_phrase": { "name": "SOC Pipeline Heartbeat Failure" } },
  "sort": [{"@timestamp": "desc"}]
}'
```

**Résultat attendu** : un document avec `severityLabel: "High"` et `statusLabel: "Open"`. Vérifier aussi visuellement l'apparition de l'alerte dans le dashboard UTMStack, puis la clôturer (Completed) une fois le test validé — ne pas laisser une alerte de test en statut Open.

### 11.7 Résumé de l'état après cette installation

| Élément | Emplacement |
| --- | --- |
| Script | `/usr/local/bin/soc-pipeline-heartbeat.sh` |
| Service systemd | `/etc/systemd/system/soc-pipeline-heartbeat.service` |
| Timer systemd | `/etc/systemd/system/soc-pipeline-heartbeat.timer` (08h00 quotidien, `Persistent=true`) |
| Log local | `/var/log/soc-pipeline-heartbeat.log` |
| Règle de corrélation | `utm_correlation_rules`, créée via l'UI |
| Survie aux mises à jour UTMStack | Oui — l'updater ne touche ni `/usr/local/bin/` ni `/etc/systemd/system/` |
| Survie à un revert de snapshot | Non — à réinstaller si retour à un snapshot antérieur à l'installation |

---

## 12. Variante cloud — déploiement Mistral

Cette section couvre le déploiement de la variante cloud décrite dans le [chapitre principal, section 10](https://doit4everyone.github.io/utmstack-lab/docs/09-pipeline-llm.html#10-variante-cloud--remplacer-qwen-par-un-llm-hébergé) — le remplacement du moteur Ollama/Qwen par l'API Mistral, en complément (jamais en remplacement) du pipeline local documenté dans le reste de cette annexe.

### 12.1 Créer un compte et une clé API

1. Inscription sur [console.mistral.ai](https://console.mistral.ai) (l'espace développeur "La Plateforme", distinct du grand public "Le Chat")
2. **Settings → Billing** : passer sur le **Scale plan** (pay-as-you-go, sans minimum) — indispensable pour la production, voir l'encadré ci-dessous
3. **Settings → API Keys → Create new key** — copier la clé immédiatement, elle ne s'affiche qu'une fois

> ⚠️ **Ne pas rester sur le tier gratuit "Experiment" pour de vraies données.** Ce tier utilise les entrées/sorties API pour l'entraînement de leurs modèles par défaut (opt-out manuel requis dans Admin Console → Confidentialité si on l'utilise quand même) et n'est explicitement prévu que pour l'évaluation. Le Scale plan est une facturation à l'usage réel, sans abonnement ni engagement — pour ce pipeline (~0,20 $/mois), le passage est quasi gratuit et débloque le DPA standard plus la garantie de non-entraînement.

### 12.2 Fichiers workflows

Quatre fichiers, disponibles dans [`/scripts`](https://github.com/doit4everyone/utmstack-lab/tree/main/scripts) :

| Fichier | Rôle |
| --- | --- |
| `utmstack-resume-quotidien-mistral.json` | Rapport officiel quotidien — tri déterministe, moteur Mistral |
| `utmstack-resume-a-la-demande-mistral.json` | Rapport officiel à la demande — webhook |
| `utmstack-resume-quotidien-libre-mistral.json` | Rapport complémentaire quotidien — analyse libre, sans tri |
| `utmstack-resume-a-la-demande-libre-mistral.json` | Rapport complémentaire à la demande — webhook |

Les deux variantes "officielles" réutilisent la même architecture que les workflows Qwen déjà documentés (section 8) — seul le nœud d'appel LLM change. Les deux variantes "libre" suivent le protocole de test de la section 9 du chapitre principal, mais tournent en continu avec stockage et envoi mail propres, plutôt qu'en test manuel isolé.

### 12.3 Table de stockage séparée pour le rapport complémentaire

Pour ne jamais mélanger les deux narrations (déterministe vs libre), le rapport complémentaire utilise sa propre table :

```sql
CREATE TABLE resumes_soc_libre (
  id SERIAL PRIMARY KEY,
  date_generation TIMESTAMP DEFAULT NOW(),
  contenu TEXT
);
```

### 12.4 Credential SMTP — pourquoi il ne peut pas être pré-rempli, et comment le créer

Les deux variantes "officielle" et "libre" peuvent envoyer le rapport par e-mail en plus de l'écriture en base. Le nœud d'envoi utilise un **credential SMTP dédié**, qui doit être créé manuellement dans n8n — pas parce que c'est un oubli du fichier fourni, mais parce que **le format d'export des workflows n8n ne contient jamais les données de credential**, uniquement une référence à un credential qui doit déjà exister dans l'instance cible. C'est la même contrainte, pour la même raison de sécurité, que celle déjà rencontrée pour les credentials PostgreSQL et OpenSearch en section 9 de ce document — aucun JSON, aussi complet soit-il, ne peut la contourner.

**Création du credential** (n8n → Credentials → Add credential → SMTP) :

| Champ | Valeur |
| --- | --- |
| User | `<SMTP_USER>` — l'adresse d'envoi, ex. une boîte partagée dédiée |
| Password | `<SMTP_PASSWORD>` — mot de passe d'application si le MFA est actif sur le compte |
| Host | `<SMTP_HOST>` — `smtp.office365.com` pour un tenant Microsoft 365 |
| Port | `587` |
| SSL/TLS | **Désactivé** — le port 587 utilise STARTTLS (négocié automatiquement), pas du SSL direct dès la connexion. Le port 465, lui, demanderait ce toggle activé |
| Client Host Name | Optionnel, laisser vide ou renseigner le nom de la VM |

Nommer ce credential **"SMTP UTMStack Notifications"** (le nom exact référencé dans les 4 workflows), puis le rattacher au nœud d'envoi mail de chacun après import.

> ℹ️ **Pourquoi SMTP classique et pas OAuth Microsoft 365.** n8n propose un nœud dédié "Microsoft Outlook" en OAuth2 via Microsoft Graph — c'est d'ailleurs la seule méthode que Microsoft continue de garantir dans la durée, l'authentification SMTP basique étant progressivement dépréciée sur Exchange Online. Ce choix SMTP classique a été retenu ici parce qu'**UTMStack Community Edition lui-même ne supporte pas encore OAuth pour ses propres notifications** — la config a été alignée sur le même mécanisme, avec la même adresse d'envoi, pour rester cohérent. Si l'authentification SMTP basique venait à être coupée côté tenant, la migration vers le nœud Outlook (avec une App Registration Azure en mode "Application", pour éviter la complexité d'une boîte partagée en délégué) serait la solution durable.

### 12.5 Deux pièges n8n rencontrés lors de la construction de ces workflows

**Le format `resourceMapper` du nœud Postgres "Insert"** — ce nœud n'accepte pas un simple mapping `{colonne: valeur}` : il attend une structure complète avec `__rl` (resource locator), un tableau `schema` décrivant chaque colonne (type, nom, métadonnées) et un tableau `matchingColumns`. Cette structure est normalement remplie automatiquement par l'UI n8n lorsqu'elle interroge la base de données — un JSON construit à la main sans cette étape produit une erreur `relation "value.value" does not exist` à l'exécution, apparemment sans rapport avec la vraie cause. Si ce nœud doit être reconstruit manuellement, copier la structure `columns` complète d'un nœud Insert déjà fonctionnel plutôt que la deviner.

**Le paramètre `responseMode` du nœud Webhook Trigger** — par défaut (ou si absent d'un JSON construit à la main), ce nœud répond **immédiatement** à l'appel HTTP entrant avec un message générique, sans attendre la fin du workflow ni utiliser un éventuel nœud "Respond to Webhook" plus loin dans la chaîne — produisant l'erreur `Unused Respond to Webhook node found in the workflow`. Le paramètre `responseMode` doit être explicitement réglé sur `responseNode` pour que le webhook attende la fin du pipeline et utilise la vraie réponse construite (page HTML du rapport, dans ce cas).

### 12.6 Tableau des variables spécifiques à la variante cloud

| Variable | Où la trouver | Ce qu'il faut y mettre |
| --- | --- | --- |
| `<MISTRAL_API_KEY>` | Headers du nœud d'appel Mistral | Ta clé API, Scale plan |
| `<SMTP_USER>`, `<SMTP_PASSWORD>`, `<SMTP_HOST>` | Credential SMTP à créer (section 12.4) | Les identifiants de ta boîte d'envoi |
| `<EMAIL_DESTINATAIRE>` | Champ `toEmail` du nœud d'envoi mail | L'adresse qui doit recevoir les rapports |

Les autres variables (IP UTMStack, credentials PostgreSQL/OpenSearch, clés threat intelligence) sont les mêmes que celles du tableau général de la section 9 — cette variante cloud ne change que le moteur de rédaction et l'envoi mail, pas le reste du pipeline.

---

> [← Retour à l'index](https://doit4everyone.github.io/utmstack-lab/docs/) | [← Pipeline SOC augmenté par IA locale](https://doit4everyone.github.io/utmstack-lab/docs/09-pipeline-llm.html)
