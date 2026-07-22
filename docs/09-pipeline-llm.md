---
title: "Pipeline SOC augmenté par IA locale | DoIt4Everyone"
description: "Pipeline SOC augmenté par IA locale (Ollama, n8n) pour UTMStack. Retour d'expérience complet sur 12 versions, tri déterministe, enrichissement threat intelligence, et pourquoi un LLM local seul ne suffit pas."
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

# Pipeline SOC augmenté par IA locale
> [← Retour à l'index](../)

Ce chapitre documente le projet qui a occupé la majeure partie de deux sessions de travail : brancher un LLM local (Ollama) sur les alertes UTMStack pour produire un résumé quotidien exploitable, sans dépendance cloud. Le résultat final fonctionne bien — mais le chemin pour y arriver est le vrai contenu de cette page. Douze versions de pipeline, plusieurs échecs de classification révélateurs, et une leçon d'architecture qui dépasse largement ce lab.

> ℹ️ **À qui s'adresse ce chapitre.** Si tu cherches juste à déployer le pipeline chez toi, va directement à l'[annexe technique de déploiement](https://doit4everyone.github.io/utmstack-lab/docs/09-pipeline-llm-deploiement.html). Cette page-ci raconte *pourquoi* le pipeline est construit comme il l'est — utile si tu veux comprendre les pièges avant de les reproduire, ou si tu veux adapter l'approche à ton propre contexte.

## 📋 Table des matières

1. [Pourquoi ce projet](#1-pourquoi-ce-projet)
2. [Architecture générale](#2-architecture-générale)
3. [L'arc narratif — 12 versions, ce qu'on a appris à chaque échec](#3-larc-narratif--12-versions-ce-quon-a-appris-à-chaque-échec)
4. [Pourquoi un LLM local ne peut pas (encore) remplacer le jugement humain](#4-pourquoi-un-llm-local-ne-peut-pas-encore-remplacer-le-jugement-humain)
5. [Enrichissement threat intelligence](#5-enrichissement-threat-intelligence)
6. [Corrélation temporelle — combler l'angle mort](#6-corrélation-temporelle--combler-langle-mort)
7. [Positionnement économique — combien coûte l'alternative](#7-positionnement-économique--combien-coûte-lalternative)
8. [Pour aller plus loin dans la stack IA locale](#8-pour-aller-plus-loin-dans-la-stack-ia-locale)
9. [Confrontation avec un LLM sans contrainte — Sonnet 5 vs DeepSeek-R1 vs Mistral](#9-confrontation-avec-un-llm-sans-contrainte--sonnet-5-vs-deepseek-r1-vs-mistral)
10. [Variante cloud — remplacer Qwen par un LLM hébergé](#10-variante-cloud--remplacer-qwen-par-un-llm-hébergé)
11. [Supervision du pipeline — détecter la panne silencieuse](#11-supervision-du-pipeline--détecter-la-panne-silencieuse)
12. [Limitations connues, assumées honnêtement](#12-limitations-connues-assumées-honnêtement)

---

## 1. Pourquoi ce projet

Le SOC AI natif d'UTMStack Community Edition produit un résumé pauvre et générique — un texte du type *"AI GENERATED ANALYSIS: Multiple related alerts were detected..."*, quel que soit le modèle branché derrière. La cause a été confirmée par reverse engineering du backend (`SocAIService.analyzeAlert()`, extraction du `.war`) : un vrai appel API externe existe bien, mais le prompt système est **codé en dur côté UTMStack, invisible et non modifiable** depuis l'extérieur.

En creusant dans le schéma PostgreSQL, une colonne est apparue sans être exploitée nulle part : `rule_description` dans `utm_correlation_rules`. Pour chaque règle de corrélation, elle contient une description complète avec une section *Next Steps* détaillée (10+ étapes d'investigation) et des références MITRE ATT&CK — jamais affichée dans l'UI, jamais utilisée par le SOC AI natif.

Ce champ inexploité est devenu le point de départ du projet : construire un pipeline externe (n8n) qui interroge les vraies données d'alertes UTMStack, exploite `rule_description`, et produit un résumé réellement contextualisé — avec un objectif de départ non négociable : **tout doit rester local**, aucune donnée ne sort du lab.

Ce chapitre documente d'abord cette architecture 100% locale (sections 2 à 9), qui reste la référence et le pipeline de production principal. Les tests comparatifs menés en section 9 ont cependant fait émerger un résultat qu'il aurait été malhonnête de passer sous silence : un fournisseur cloud basé en UE peut égaler, voire dépasser, la qualité d'analyse du meilleur modèle local testé, pour un coût mensuel dérisoire. La section 10 documente cette **variante cloud optionnelle** — jamais comme un remplacement du pipeline local, mais comme un second choix légitime, avec ses propres compromis explicites.

---

## 2. Architecture générale

Le pipeline existe en deux variantes, qui partagent la même logique :

| Variante | Déclenchement | Modèle | Usage |
| --- | --- | --- | --- |
| Rapport quotidien | Schedule Trigger, 6h00 (Europe/Zurich) | Qwen 2.5 14B | Consultation du matin, pas de contrainte de temps |
| À la demande | Webhook n8n | Qwen 2.5 14B | Vérification ponctuelle, ~5-9 minutes de génération |

**Stack technique complète** : Ollama natif sur l'hôte Windows (accès direct au CPU/futur GPU sans passthrough), n8n pour l'orchestration, PostgreSQL pour le stockage des rapports et la lecture des `rule_description`, OpenSearch (`v11-alert-*`) comme source de données, plus SearXNG et Open WebUI pour l'usage conversationnel complémentaire (voir [section 8](#8-pour-aller-plus-loin-dans-la-stack-ia-locale)).

### Schéma d'architecture (version finale)

```
┌──────────────────┐
│  Schedule (6h)     │
│  ou Webhook         │
└─────────┬──────────┘
          │
          ▼
┌─────────────────────────────┐
│  OpenSearch v11-alert-*      │   agrégations 24h : sévérité,
│  (HTTP Request)              │   catégorie MITRE, signatures,
└─────────┬─────────────────────   IP source/cible + géoloc
          │
          ▼
┌─────────────────────────────┐
│  PostgreSQL                  │   utm_correlation_rules
│  rule_description             │   (procédures officielles,
└─────────┬─────────────────────   Next Steps, MITRE)
          │
          ▼
┌───────────────────────────────────────────┐
│  TRI DÉTERMINISTE (JavaScript)              │
│  ─────────────────────────────              │
│  • Classement SIGNAL / CONTRÔLE /           │
│    BRUIT / INDÉTERMINÉ (mots-clés)          │
│  • Déduplication par signature              │
│  • Flag "rareté suspecte" (≤2 occurrences)  │
│  • Construction du SQUELETTE pré-rédigé     │
│    avec emplacements [COMMENTAIRE_N]        │
└─────────┬────────────────────────────────────
          │
          ▼
┌─────────────────────────────┐
│  IPs Signaux (split)          │   une IP → un item
└─────────┬─────────────────────
          │
    ┌─────┼─────┬─────┬───────────────┐
    ▼     ▼     ▼     ▼               ▼
 ┌─────┐┌─────┐┌─────┐┌──────┐  ┌───────────────┐
 │Abuse││Grey ││ OTX ││Threat│  │ Historique     │
 │IPDB ││Noise││     ││ Fox  │  │ SOC (30j)      │
 └──┬──┘└──┬──┘└──┬──┘└──┬───┘  └──────┬────────┘
    │      │      │      │             │
    └──────┴──────┴──────┴─────────────┘
                   │
                   ▼
       ┌─────────────────────────┐
       │  Merge TI (Append,        │  ⚠️ le mode "Combine"
       │  5 entrées)                │     ne gère que 2 entrées !
       └────────────┬──────────────┘
                    │
                    ▼
       ┌─────────────────────────┐
       │  Aggregation TI            │  regroupe par IP :
       │  (JavaScript)               │  score, classification,
       └────────────┬────────────────  pulses, récurrence
                    │
                    ▼
       ┌─────────────────────────┐
       │  Fusion dans le            │  injection des données
       │  squelette (JS)            │  TI sous chaque IP
       └────────────┬──────────────┘
                    │
                    ▼
       ┌─────────────────────────┐
       │  Ollama — Qwen 14B         │  COMPLÉTION PURE :
       │  (HTTP Request)             │  remplit [COMMENTAIRE_N],
       └────────────┬────────────────  ne reclasse rien,
                    │                  n'invente aucun nom
                    ▼
       ┌─────────────────────────┐
       │  Contrôle de complétion    │  balise restante ?
       │  (JavaScript)               │  → ⚠️ avertissement visible
       └────────────┬──────────────┘     (jamais de nettoyage
                    │                     silencieux)
                    ▼
       ┌─────────────────────────┐
       │  PostgreSQL resumes_soc    │  stockage + purge >365j
       └────────────┬──────────────┘
                    │
                    ▼
       ┌─────────────────────────┐
       │  Webhook / Dashboard        │  consultation web
       └─────────────────────────┘
```

Le principe qui traverse tout le schéma : **tout ce qui est encadré en amont d'Ollama est déterministe et auditable** — du code, pas du LLM. Le modèle n'intervient qu'à un seul endroit précis, pour une seule tâche précise (compléter un texte déjà structuré), jamais pour classer ni pour décider. Ce principe n'est pas arrivé du premier coup — la section suivante raconte comment on y est arrivé.

---

## 3. L'arc narratif — 12 versions, ce qu'on a appris à chaque échec

### v1-v3 — La fausse bonne piste

Les premières versions du pipeline interrogeaient l'index `v11-log-*` — les logs Suricata bruts. Erreur de conception discrète mais lourde de conséquences : ce n'est pas l'index que consulte le dashboard UTMStack. Le bon index pour les alertes de corrélation est **`v11-alert-*`**, avec des champs bien spécifiques (`name.keyword`, `severityLabel.keyword`, `category.keyword`, `technique.keyword`, `adversary.ip.keyword`, `target.ip.keyword`).

Cette correction a immédiatement révélé un problème de fond resté invisible jusque-là : la règle **`High level Suricata alert`** générait à elle seule 300 à 1000+ alertes par jour, classées "High", catégorie "Initial Access" — et il s'est avéré que ~95% de ce volume était en réalité du trafic *ET INFO Windows Update P2P Activity* et *GNU/Linux APT User-Agent Outbound*. Un faux positif massif, invisible tant que le pipeline travaillait sur le mauvais index.

> ⚠️ **Piège à retenir.** `adversary.ip` et `target.ip` suivent la **direction du flux réseau**, pas le rôle attaquant/victime. Sur certaines signatures (notamment celles détectant une réponse sortante), l'IP interne apparaît comme `adversary` et l'IP externe comme `target` — l'inverse de l'intuition. À vérifier au cas par cas plutôt que de supposer.

### v4 — Le prompt durci, et pourquoi ça ne suffit pas

Face à un premier test où Mistral NeMo 12B classait un webshell actif (`ET WEB_SERVER WebShell Generic - wget http - POST`) en "bruit de reconnaissance passive", la réponse naturelle a été de durcir le prompt : liste explicite de termes obligatoirement prioritaires, interdictions formelles, règle de non-contradiction.

Résultat du test suivant : le modèle a bien identifié la signature `ET COMPROMISED` en section signal — puis a écrit dans la même réponse *"il n'y a pas de signal nécessitant une vérification humaine prioritaire"*, se contredisant dans son propre texte. Le prompt engineering seul avait amélioré le comportement sans le corriger : le modèle appliquait la contrainte localement, mais l'oubliait trois phrases plus tard.

### v5-v8 — Le tri déterministe

Le changement de philosophie qui a débloqué le projet : **sortir la classification du LLM et la coder en JavaScript.**

```javascript
const TERMES_SIGNAL = [
  "WebShell", "EXPLOIT", "COMPROMISED", "MALWARE", "TROJAN",
  "ATTACK_RESPONSE", "CNC", "Cobalt Strike", "Empire",
  "Remote Command Execution", "Suspicious String", "sinkhole",
  "Backdoor", "Ransomware", "Shellcode", "Phishing", "Exfiltration",
  "Lateral Movement", "Mimikatz", "PsExec", "Reverse Shell"
];
```

Une simple correspondance de mots-clés, testée unitairement sur les signatures réelles du lab avant d'être appliquée, classe chaque signature en SIGNAL / CONTRÔLE / BRUIT / INDÉTERMINÉ. Le LLM reçoit alors des données **déjà triées** et se contente de rédiger — plus de décision de classification à sa charge.

Testé sur trois modèles (Llama 3.1 8B, Mistral NeMo 12B, Qwen 2.5 14B), le résultat a validé l'approche : les trois produisaient des rapports cohérents une fois la classification retirée de leur responsabilité. Un bug de déduplication est apparu au passage — la même signature citée par deux règles de corrélation différentes se retrouvait comptée (et affichée) deux fois — corrigé en fusionnant par nom de signature avec somme des occurrences.

> ℹ️ **Le principe qui en ressort.** *Détection déterministe, narration probabiliste.* C'est le même partage des rôles qu'un SIEM industriel : les règles de corrélation détectent, le LLM (quand il y en a un) rédige. Confondre les deux mène à des rapports qui se contredisent.

### v9-v11 — Le squelette pré-rédigé

Le tri déterministe seul ne suffisait pas encore. Sur un run réel, un modèle a produit une signature qui n'existait dans aucune donnée source :

```
CUSTOM DROP - r00ts3c COMPROMISED DVR attempt
```

Ce nom n'apparaît nulle part dans les logs. Le modèle avait **fusionné deux noms réels distincts** — `CUSTOM DROP - r00ts3c ViewLog.asp DVR exploit attempt` et `ET COMPROMISED Known Compromised or Hostile Host Traffic group 19` — en un troisième nom halluciné, plausible en apparence, inventé en réalité.

La correction a poussé le principe du tri déterministe à son terme logique : le code JavaScript ne se contente plus de classer, il **rédige le squelette complet du rapport**, avec les noms de signatures, les chiffres, les règles parentes déjà écrits en dur. Le LLM ne reçoit plus que des emplacements `[COMMENTAIRE_N]` à remplir :

```
**CUSTOM DROP - r00ts3c ViewLog.asp DVR exploit attempt** — 1 occurrence(s)
- Règle(s) : Exploit Attempt Detection | sévérité High | T1210
- IP sources principales : 115.84.178.56 [Vietnam] (1)
- Cibles internes : 192.168.1.203 (1)
- Procédure officielle (extrait) : [...]
[COMMENTAIRE_4]
```

Sa tâche devient de la pure complétion — reproduire le texte à l'identique, remplacer chaque balise par 2-3 phrases d'analyse. Plus aucune possibilité structurelle d'inventer un nom.

### Comparatif des modèles testés

| Modèle | Comportement observé sur la tâche de complétion |
| --- | --- |
| Llama 3.1 8B | Le plus fiable sur la fidélité des noms (aucune altération observée), mais laisse parfois la balise `[COMMENTAIRE_N]` visible à côté de son propre commentaire au lieu de la supprimer |
| Mistral NeMo 12B | Correct une fois le tri déterministe en place, mais tendance à minimiser les signaux confirmés dans les versions antérieures au tri |
| Qwen 2.5 14B | Le plus riche en contexte et le mieux rédigé, mais le plus "créatif" — a inventé une section entière ("NEXT STEPS") en pompant le contexte PostgreSQL brut fourni en trop grande quantité |

Un enseignement contre-intuitif s'est dégagé de ce comparatif : **sur une tâche de pure complétion, le modèle le plus docile bat parfois le plus capable.** Qwen, plus intelligent, prenait des initiatives non désirées ; Llama, plus simple, exécutait la consigne à la lettre. La correction a fini par retirer la source de la dérive plutôt que de changer de modèle : le contexte PostgreSQL brut (15 `rule_description` en vrac) a été remplacé par l'injection d'**une seule description ciblée**, celle de la règle concernée, directement dans le squelette au bon endroit. Une fois cette source de confusion supprimée, les deux modèles se sont stabilisés.

### Comment la liste de classification a été construite

`TERMES_SIGNAL`, `TERMES_CONTROLE` et `TERMES_BRUIT` ne sont pas une liste théorique — ils viennent d'une lecture empirique des signatures Suricata réellement rencontrées dans ce lab, catégorisées à la main par familiarité avec la nomenclature du ruleset Emerging Threats (ET) :

| Préfixe / mot-clé Suricata | Ce qu'il signale en général | Catégorie retenue |
| --- | --- | --- |
| `ET WEB_SERVER`, `ET EXPLOIT`, `ET COMPROMISED`, `ET ATTACK_RESPONSE` | Exploitation active, hôte compromis confirmé | SIGNAL |
| `ET DROP`, `ET CINS`, `Dshield`, `Spamhaus` | Blocage sur réputation IP déjà neutralisé | CONTROLE |
| `ET INFO`, `SURICATA STREAM/HTTP/TCPv4` | Bruit de décodage protocolaire ou trafic informatif | BRUIT |
| Tout le reste (ex : `SCAN Slow port scan detected`) | Ambigu par nature | INDÉTERMINÉ (laissé au jugement du LLM, avec flag de rareté si peu fréquent) |

La méthode pour l'étendre à un autre lab est la même : **observer les signatures qui remontent réellement**, pas deviner à l'avance. Deux sources concrètes pour trouver la signification d'une signature inconnue :

1. **La documentation Emerging Threats / Proofpoint** — les règles `ET *` suivent une nomenclature stable par catégorie (`ET WEB_SERVER`, `ET POLICY`, `ET SCAN`, `ET MALWARE`...), consultable sur [rules.emergingthreats.net](https://rules.emergingthreats.net/)
2. **Le champ `msg` de la règle Suricata elle-même** — visible directement dans OpenSearch (`lastEvent.log.alert.signature`), généralement assez explicite pour classer sans ambiguïté

> ⚠️ **Cette liste vit, elle n'est jamais figée.** Chaque nouvelle source de données (agent Windows plus riche, intégration O365, tests offensifs Kali) fait apparaître des signatures que la liste actuelle ne couvre pas — elles tombent alors par défaut en INDÉTERMINÉ, visibles mais non priorisées automatiquement. C'est un filet de sécurité, pas un défaut : mieux vaut une signature ignorée du tri mais visible, qu'une signature mal classée silencieusement. La liste doit être revue à chaque élargissement significatif du périmètre de collecte.
>
> Ce lab prévoit justement plusieurs élargissements à court terme — intégrations Office 365/Azure (voir [chapitre Intégrations](https://doit4everyone.github.io/utmstack-lab/docs/10-integrations.html)) et tests offensifs avec Kali Linux. **Une version mise à jour de `TERMES_SIGNAL`/`BRUIT`/`CONTROLE`, enrichie avec les signatures découvertes lors de ces deux chantiers, sera publiée dans le dépôt une fois ces tests réalisés.** En attendant, la liste fournie ici reste la version validée sur le périmètre réseau/Suricata uniquement.

### Exemple vécu — une nouvelle source de bruit, en conditions réelles

La maintenance de cette liste n'est pas théorique. Le jour même de la rédaction de ce chapitre, l'activation du SMTP sur UTMStack (pour l'envoi de ses propres notifications par e-mail) a produit **489 alertes en une heure**, toutes sur la même signature : `NF - Outbound mail setup command EHLO`. La cause, une fois investiguée : UTMStack envoyait une notification par e-mail à chaque déclenchement de règle — y compris pour la règle de heartbeat décrite en section 10 — et chaque notification déclenchait à son tour cette signature Suricata, dans une boucle auto-entretenue sans risque réel mais bruyante.

Ce cas illustre concrètement le principe : la signature ne figurait dans aucune des trois listes (ni SIGNAL, ni BRUIT, ni CONTRÔLE), elle est tombée en INDÉTERMINÉ, **visible** dans les rapports plutôt que silencieusement ignorée — ce qui a permis de la repérer et de comprendre la boucle le jour même. La correction n'a pas eu lieu dans `TERMES_SIGNAL` mais en amont, directement dans Suricata (`threshold.config`, directive `suppress` ciblée sur l'IP source plutôt que sur l'IP de destination — les relais Microsoft 365 tournant sur plusieurs plages IP, une exclusion par destination unique aurait été contournée dès le lendemain par un relais différent).

---

## 4. Pourquoi un LLM local ne peut pas (encore) remplacer le jugement humain

Aucun LLM, local ou non, n'a de mécanisme intrinsèque pour dire *"je ne sais pas"* — un modèle génératif complète du texte selon des probabilités, il ne vérifie pas des faits. La différence entre un LLM local 8-14B et un modèle massif n'est pas qu'un local "n'y arrive pas du tout" — c'est que le seuil auquel il tient une contrainte logique sur toute une génération est beaucoup plus bas, et que le coût pour repousser ce seuil (modèle 70B+, fine-tuning sur corpus propre, GPU professionnel à 15-30k CHF, mois de travail) est hors de portée d'un lab domestique.

**C'est cette limite précise, observée concrètement, qui a motivé le passage au tri déterministe.** Avant que le tri JavaScript n'existe (versions v1 à v4, section 3), Llama 3.1 8B, Mistral NeMo 12B et Qwen 2.5 14B — livrés à eux-mêmes sur les mêmes données brutes qu'aujourd'hui — ont chacun échoué différemment sur la même tâche de classification : un webshell confirmé classé en bruit de reconnaissance passive, une conclusion qui se contredit dans la même réponse, un nom de signature entièrement halluciné par fusion de deux signatures réelles. Le tri déterministe n'a pas été introduit par principe abstrait — il a été introduit parce que trois modèles locaux différents ont chacun raté cette même tâche, de trois façons différentes.

La confirmation est venue bien plus tard, une fois le pipeline stabilisé : les tests de la [section 9](#9-confrontation-avec-un-llm-sans-contrainte--sonnet-5-vs-deepseek-r1-vs-mistral), menés sur la même tâche non déterministe, ont montré que même un modèle local nettement plus récent et plus gros — DeepSeek-R1-Distill-32B, sorti après cette génération de modèles et spécifiquement entraîné au raisonnement — échoue encore sur le point précis qui compte le plus : relier deux faits dispersés dans le texte pour construire une corrélation. Le problème n'était donc pas propre à Llama, Mistral ou Qwen 2.5 — c'est une limite qui persiste à travers plusieurs générations de modèles locaux de cette taille, tant que le calcul reste accessible sur du matériel domestique.

### Les 4 piliers d'un pipeline IA qui reste fiable

1. **Jamais de décision critique confiée au LLM** — le classement signal/bruit reste du code, pas de la génération
2. **LLM cantonné à la reformulation** — rédiger un commentaire, jamais juger
3. **Échec rendu visible** — si le modèle ne termine pas sa tâche, le rapport l'affiche explicitement (`⚠️ GÉNÉRATION INCOMPLÈTE`) plutôt que d'être nettoyé silencieusement
4. **Un humain décide toujours** de l'action finale — le pipeline informe, il n'agit jamais seul

> ℹ️ **Le message central de ce chapitre.** L'IA générative dans un SOC n'est pas ce qui détecte. Ce qui détecte, c'est le detection engineering (règles) et parfois le machine learning statistique classique (baseline comportementale). L'IA générative sert à rendre lisible et actionnable ce que la détection a déjà trouvé. Confondre les deux mène soit à des attentes déçues, soit à des investissements mal ciblés.

---

## 5. Enrichissement threat intelligence

Une fois le tri et la rédaction stabilisés, la limite suivante est apparue : le rapport nommait une menace sans jamais dire si l'IP source avait une réputation connue. Quatre feeds gratuits ont été intégrés — **AbuseIPDB**, **GreyNoise Community**, **AlienVault OTX**, et **ThreatFox** (abuse.ch, sans clé requise) — appliqués uniquement aux IP des signaux prioritaires et des signatures non classées, pour préserver les quotas gratuits (1000 lookups/jour AbuseIPDB, ~50-100/jour GreyNoise).

Feeds volontairement écartés : Shodan/Censys (redondant avec la géolocalisation déjà native dans UTMStack), VirusTotal (quota trop restrictif pour un usage batch), MISP (pertinent mais trop lourd à déployer et alimenter pour ce lab).

> ⚠️ **Pourquoi pas dans le RAG.** Les feeds threat intelligence sont des listes d'IoC (IP, hash, domaines) — structurées, volatiles, sans aucune sémantique vectorielle. Les injecter dans une base vectorielle comme Qdrant gaspille du calcul d'embedding et noie le RAG de bruit au moment d'une vraie recherche sémantique. La bonne approche est un lookup structuré au moment de la génération du rapport, pas une indexation.

### Le piège technique n8n — Merge "Combine" vs "Append"

La partie la plus instructive de ce chantier n'était pas les feeds eux-mêmes, mais un piège d'architecture n8n qui a produit un comportement erratique difficile à diagnostiquer : sur certains runs, seuls 1 ou 2 feeds sur 4 apparaissaient dans le rapport final ; sur d'autres, les 3-4 étaient présents. Le premier réflexe a été de suspecter une condition de course (timing variable des appels API).

La vraie cause : le nœud **Merge** de n8n, en mode **"Combine"**, ne gère que **2 entrées fixes** — quel que soit le nombre de branches câblées visuellement dessus. Câbler 4 ou 5 flux parallèles sur un Merge en mode Combine ne produit pas une erreur claire ; ça produit un comportement silencieusement incomplet.

La correction : passer le nœud Merge en mode **"Append"**, avec le nombre d'entrées explicitement défini (5, dans ce cas — 4 feeds + la corrélation temporelle décrite en [section 6](#6-corrélation-temporelle--combler-langle-mort)). En mode Append, chaque branche connectée à sa propre entrée est simplement concaténée à la sortie, sans tentative de "combinaison" par paire.

```
Mode : Append
Number of Inputs : 5
```

Résultat une fois corrigé : comportement stable et reproductible d'un run à l'autre, avec les 3-4 feeds systématiquement présents.

### Résultat concret

Pour une IP source détectée dans un signal, le rapport affiche désormais :

```
**CUSTOM DROP - r00ts3c ViewLog.asp DVR exploit attempt** — 1 occurrence(s)
- IP sources principales : 115.84.178.56 [Vietnam] (1)
  * AbuseIPDB : score 87/100, 342 signalement(s)
  * GreyNoise : malicious — exploiter
  * OTX : 3 pulse(s) — DVR Botnet Wave 2026-Q2, SEA IoT Compromises
```

Une IP asiatique tentant un exploit DVR contre le WAN devient immédiatement lisible et vérifiable — pas juste "IP malveillante" affirmé sans preuve.

---

## 6. Corrélation temporelle — combler l'angle mort

Le pipeline, même dans sa version enrichie, avait un angle mort structurel : chaque rapport est une **photo indépendante des dernières 24h**, sans mémoire des jours précédents. Une chaîne d'exploitation qui se construit lentement — reconnaissance légère un jour, scan plus ciblé quelques jours plus tard, tentative d'exploit ensuite — reste invisible tant que chaque événement pris isolément semble mineur.

C'est exactement ce que fait l'UEBA (User and Entity Behavior Analytics) des SIEM premium — mais il s'agit là de machine learning statistique classique établissant une baseline sur des semaines, pas de LLM génératif. Reproduire l'équivalent ne demande pas d'IA : une requête SQL sur l'historique des rapports déjà stockés suffit à couvrir le cas le plus courant.

```sql
SELECT date_generation, contenu
FROM resumes_soc
WHERE date_generation >= NOW() - INTERVAL '30 days'
ORDER BY date_generation DESC
LIMIT 60;
```

Pour chaque IP d'un signal du jour, le pipeline vérifie si elle apparaît dans les rapports des 30 derniers jours, et injecte le résultat dans le squelette :

```
  * Historique : apparue dans 3 rapport(s) précédent(s) sur 30 jours
    (il y a 1, 5, 12 jour(s)) — pattern potentiellement récurrent à surveiller.
```

Cette branche est câblée en parallèle des quatre feeds threat intelligence, sur le même nœud Merge (5 entrées au lieu de 4).

---

## 7. Positionnement économique — combien coûte l'alternative

Une question revient systématiquement face à ce genre de projet : *pourquoi ne pas utiliser un SIEM commercial ?* La réponse chiffrée est plus instructive que l'intuition.

### Ce que coûterait un SIEM premium pour 50 utilisateurs

Sentinel et Splunk se facturent au **volume de logs ingérés (GB/jour)**, pas au nombre d'utilisateurs — une nuance qui échappe souvent à la première estimation. Pour un environnement 50 users avec un stack correct (M365, EDR, réseau), le volume réaliste se situe autour de 40 GB/jour.

| Solution | Coût annuel réaliste (50 users, ~40 GB/jour) |
| --- | --- |
| UTMStack self-hosted (ce lab) | ~0 CHF de licence (matériel amorti) |
| Microsoft Sentinel, avec licences M365 E5 | ~50 000 à 70 000 USD/an |
| Microsoft Sentinel, sans exemption M365 | ~140 000 USD/an |
| Splunk Cloud + Enterprise Security | ~150 000 à 300 000 USD/an |

À ces montants s'ajoutent, dans tous les cas, un analyste dédié, une formation initiale et un budget d'intégration — portant le total réaliste à **150 000-400 000 CHF/an tout compris** pour une vraie exploitation SIEM premium à cette échelle.

### La confusion marketing Defender / Sentinel

Microsoft Defender for Business (l'EDR endpoint inclus dans M365 Business Premium) fonctionne **de façon totalement autonome**, avec son propre portail (`security.microsoft.com`), sans nécessiter Sentinel. Sentinel est un SIEM qui agrège des sources **au-delà** de l'écosystème Microsoft (firewalls tiers, SaaS non-Microsoft, applications maison) et facture au volume — Microsoft a donc un intérêt commercial direct à entretenir l'impression qu'un Defender "complet" nécessite Sentinel, ce qui est techniquement faux pour la détection endpoint elle-même.

### Ce que font réellement les PME de cette taille

| Segment | Part estimée |
| --- | --- |
| Rien, ou antivirus natif seul | ~40% |
| EDR/XDR seul (Defender for Business, CrowdStrike...) | ~30% |
| EDR + MSSP externalisé (SIEM mutualisé, 3-8k CHF/mois) | ~20% |
| Vrai SOC interne avec SIEM premium dédié | ~5-10% |

Un lab UTMStack + pipeline IA local ne remplace pas un SIEM Enterprise pour une banque régulée. Il remplace en revanche, de façon économiquement et techniquement défendable, ce que fait aujourd'hui la majorité des PME de 50 à 200 utilisateurs : rien, ou un EDR isolé sans corrélation réseau.

---

## 8. Pour aller plus loin dans la stack IA locale

### Dimensionnement GPU

L'inférence sur CPU (i7-14700, 20 cœurs) donne des temps de génération de 2 minutes (Llama 8B) à 5-9 minutes (Qwen 14B) — largement viable pour un batch nocturne, moins confortable pour un usage interactif. Le point technique à connaître avant d'investir dans un GPU : **un modèle qui déborde de la VRAM disponible perd la quasi-totalité du gain attendu**, parce que l'inférence est séquentielle couche par couche et que chaque aller-retour entre GPU et RAM système via le bus PCIe coûte plus cher que le calcul lui-même. Un modèle à 85% en VRAM peut être aussi lent qu'un modèle 100% CPU.

Pour faire tenir Qwen 14B (Q4, ~10 Go) et Llama 8B (Q4, ~6 Go) confortablement en VRAM avec de la marge, **12 Go est le plancher pratique**, 16 Go laisse de la marge pour tester des modèles plus gros (Mistral Small 24B, ~14 Go en Q4) sans dégradation.

### Panorama des modèles de raisonnement ouverts (2026) — tailles, GPU et coût réel

Au-delà de Qwen 14B, le paysage des modèles ouverts spécialisés en raisonnement s'est beaucoup étoffé. Voici où se situe chaque option, avec des chiffres vérifiés plutôt que des ordres de grandeur approximatifs.

**Tenables sur un lab domestique (CPU ou GPU consumer unique) :**

| Modèle | Paramètres | Taille Q4 | GPU minimum | Contexte natif |
|---|---|---|---|---|
| DeepSeek-R1-Distill-Qwen-14B | 14,8B | 9,0 Go | 12 Go (RTX 4070) | 128K |
| Qwen3-14B (mode Thinking togglable) | 14,8B | 9,3 Go | 12 Go | 32K natif / 128K via YaRN |
| QwQ-32B | 32B | ~18-20 Go | RTX 3090/4090 (24 Go) | 32K |
| DeepSeek-R1-Distill-Qwen-32B | 32,8B | ~18-20 Go | RTX 3090/4090 (24 Go) | 128K |
| Llama 3.3 70B (dense, non-reasoning dédié) | 70B | ~40-43 Go | 48 Go (2× RTX 3090, ou Mac 64 Go) | 128K |

> ⚠️ **Testé en conditions réelles sur ce lab** : le R1-Distill-32B a été exécuté en CPU pur sur les 64 Go de RAM système de ce lab, partagés avec plusieurs VM actives. Le calcul théorique laissait ~25 Go de marge — en pratique, le chargement du modèle a occupé jusqu'à 98% de la RAM totale disponible avant même le début du calcul. Le run a fini par aboutir (29 minutes au total), mais sans aucune marge de sécurité réelle. Un seul processus supplémentaire réclamant de la mémoire au mauvais moment aurait pu faire échouer le calcul en cours de route. **La marge théorique de ~25 Go ne s'est pas traduite par une marge pratique confortable.**

**Nécessitant un GPU de classe datacenter (hors de portée d'un lab domestique) :**

| Modèle | Paramètres (actifs/total) | Taille | GPU minimum |
|---|---|---|---|
| Llama 4 Scout | 17B / 109B (MoE) | ~55 Go (INT4) | 1× H100 80 Go |
| Qwen3-30B-A3B (MoE) | 3B actifs / 30B total | ~17-20 Go | RTX 4090 24 Go — seule exception MoE tenable en local |
| Llama 4 Maverick | 17B / 400B (MoE) | ~200 Go (INT4) | 4× H100 |
| DeepSeek-R1 (modèle complet, pas le distillé) | 37B / 671B (MoE) | ~376 Go (Q4) | 8× H100/H200, ou config CPU-only spécialisée (voir plus bas) |
| DeepSeek V3.2 / V4 | 37B / 671B (MoE) | ~370-700 Go | 8× H200 |
| Qwen3-235B-A22B | 22B / 235B (MoE) | ~117-132 Go (INT4) | 4× H100 80 Go minimum |
| GLM-5.2 | 40B / 744B (MoE) | ~240 Go (2-bit) à 454-796 Go (Q4) | Multi-GPU datacenter uniquement |
| Kimi K2.5 | 32B / 1T (MoE) | ~550 Go | Cluster multi-nœuds |

> ⚠️ **Le piège du "actif" vs "total" dans les modèles MoE.** Un modèle Mixture-of-Experts comme Qwen3-235B-A22B n'active que 22 milliards de paramètres par token — mais **la totalité des 235 milliards doit résider en VRAM**, puisqu'on ne sait pas à l'avance quel "expert" sera sollicité. Le nombre de paramètres actifs décrit la vitesse d'inférence, pas le besoin mémoire.

### Coût réel pour tourner un gros modèle — trois voies concrètes

**Voie 1 — Achat de matériel dédié.** Un rig 4× RTX 3090 d'occasion (sans NVLink) pour faire tourner DeepSeek-R1 671B complet en Q4 à ~4 tokens/seconde a été chiffré par la communauté à environ **2000 USD**. Une alternative sans GPU du tout — un serveur bi-EPYC avec 384-512 Go de RAM DDR5 — tourne le même modèle en Q8 à 5-8 tokens/seconde, pour un budget de **2000 à 6000 USD** selon le neuf/occasion.

**Voie 2 — Location cloud à l'heure** (tarifs vérifiés juillet 2026) :

| GPU | VRAM | Prix on-demand | Prix spot/marketplace |
|---|---|---|---|
| RTX 4090 (marketplace) | 24 Go | ~0,34 $/h | dès 0,14 $/h |
| A100 80 Go | 80 Go | 1,99–4,10 $/h | dès 0,60-0,68 $/h |
| H100 80 Go | 80 Go | 2,49–12,29 $/h (5× d'écart selon fournisseur) | dès 1,03-1,49 $/h |
| H200 141 Go | 141 Go | dès 0,50 $/h chez certains fournisseurs | — |

> ℹ️ **Le piège du Pod loué pour un usage ponctuel.** Louer un GPU façon RunPod/Vast.ai implique de déployer un Pod persistant, facturé **tant qu'il tourne** — pas seulement pendant le calcul réel. Pour un test ponctuel, deux alternatives évitent ce piège : le **serverless GPU** (facturation à la seconde de calcul, mise en veille automatique entre appels) ou l'**API hébergée directe** (Together AI, Fireworks AI proposent DeepSeek-R1 déjà déployé, facturé au token). Le calcul d'amortissement le confirme : à un usage de 2h/jour, un GPU 24 Go loué coûte ~18 $/mois — il faudrait des années d'usage quotidien pour justifier l'achat d'une carte dédiée face à la location. **L'achat matériel ne se justifie que pour un usage récurrent et intensif** (un pipeline de production tournant quotidiennement), pas pour explorer ponctuellement un modèle plus gros.

**Voie 3 — API hébergée**, la plus simple : aucun matériel à gérer, facturation au token, quelques centimes par rapport généré. C'est la voie empruntée pour le test Claude Sonnet 5 de la [section suivante](#9-confrontation-avec-un-llm-sans-contrainte--sonnet-5-vs-deepseek-r1-vs-mistral). Le compromis reste la sortie de données hors du lab.

> ℹ️ **Mistral propose un plan gratuit substantiel pour tester.** La "Experiment Plan" de leur API (La Plateforme) donne accès à tous leurs modèles, y compris Mistral Large, avec un plafond généreux de l'ordre d'1 milliard de tokens/mois — largement suffisant pour prototyper ce genre de pipeline sans dépenser un centime, et sans les questions de transfert hors UE qui se posent avec un fournisseur américain ou chinois (voir positionnement nLPD en section 7).

### Où chaque modèle est préférable

- **Pipeline structuré (rapport SOC)** : le modèle le plus fiable sur le respect strict de la structure, quel qu'il soit — dans ce lab, la bascule complète sur Qwen 14B (batch et à la demande) a été retenue après stabilisation du prompt, au prix d'un temps de génération plus long
- **Usage conversationnel (Open WebUI, RAG + recherche web)** : un modèle plus créatif comme Qwen 14B est préférable — la prise d'initiative, défaut sur une tâche de complétion stricte, devient un atout pour synthétiser et croiser des sources

### Limite observée sur RAG + recherche web

Sur une question croisant RAG (documentation du lab) et recherche web (SearXNG), un modèle 8B a produit une citation attribuant à la documentation du lab des informations qu'elle ne contenait pas — une IP jamais mentionnée nulle part dans les pages indexées, présentée comme documentée. La citation formelle (nom du fichier source) ne garantit pas que le contenu attribué soit réellement présent dans la source. À vérifier avant de faire confiance à une citation RAG sur un fait spécifique et récent.

### Chantier futur — RAG auto-alimenté

Aujourd'hui, la base de connaissance Qdrant utilisée par Open WebUI (`UTMStack Lab Docs`) est peuplée **manuellement** : chaque page publiée sur ce site est ajoutée une par une via l'interface (Knowledge → Ajouter une page web). Ça fonctionne pour une dizaine de pages ; ça devient vite pénible sur les ~220 pages prévues à terme pour l'ensemble de cette documentation.

Deux architectures ont été évaluées pour automatiser cette réindexation, sans qu'aucune n'ait encore été implémentée :

- **Via l'API d'ingestion d'Open WebUI**, si elle est exposée de façon stable en dehors de l'interface — la plus simple en théorie, puisqu'Open WebUI gère alors lui-même le chunking et l'embedding ; reste à vérifier concrètement sa disponibilité et sa robustesse
- **En écrivant directement dans Qdrant** via son API REST, en gérant l'embedding séparément (par exemple via un modèle dédié sur Ollama) — plus de travail de mise en place, mais indépendant des changements internes d'Open WebUI

Le déclenchement envisagé serait un nœud n8n en cron (hebdomadaire, par exemple), ou idéalement un webhook déclenché au moment du push sur ce dépôt.

> ⚠️ **Ce qui ne doit pas aller dans le RAG** — enseignement direct de ce projet : les rapports SOC générés quotidiennement (table `resumes_soc`) ne sont volontairement **pas** candidats à l'indexation vectorielle. Une IP ou un nom de signature n'a pas de sémantique exploitable par une recherche par similarité, et des dizaines de rapports quasi identiques jour après jour noieraient le RAG de contenu répétitif. Ce type de donnée reste interrogeable directement en SQL (recherche par motif, par date) — le RAG est réservé à du contenu à vraie valeur sémantique : documentation, procédures, explications.

Ce chantier reste ouvert. Une fois implémenté, cette section sera mise à jour avec la marche à suivre complète.

### Autre chantier hors périmètre de ce chapitre

L'intégration Office 365/Purview comme source d'alertes supplémentaire pour UTMStack est couverte dans le [chapitre Intégrations](https://doit4everyone.github.io/utmstack-lab/docs/10-integrations.html) — une fois ces logs actifs, la liste `TERMES_SIGNAL` de ce pipeline devra être enrichie en conséquence (voir la note à ce sujet plus haut dans cette page).

---

---

## 9. Confrontation avec un LLM sans contrainte — Sonnet 5 vs DeepSeek-R1 vs Mistral

Tout ce chapitre repose sur un principe : sortir la classification du LLM parce qu'aucun modèle local testé ne la tenait de façon fiable. Une question naturelle se pose alors — **un modèle réellement plus grand aurait-il seulement besoin de cette béquille ?** Pour y répondre, le même jeu de données brutes (agrégations OpenSearch + `rule_description`, sans aucun tri déterministe ni squelette) a été soumis à quatre configurations, hors du pipeline de production, dans des workflows n8n isolés dédiés à ce seul test.

### Le protocole

Un prompt unique demandait au modèle de tout faire lui-même : classer les signaux prioritaires, identifier ce qui est neutralisé, repérer le bruit, signaler les règles à fort volume suspectes de faux positif, et conclure sur un nombre précis de signaux réels — exactement la tâche que le tri déterministe du reste du pipeline effectue aujourd'hui en JavaScript.

### Résultats

| Modèle | Temps total | Corrélation croisée source/cible | Cohérence interne | Verdict |
|---|---|---|---|---|
| Claude Sonnet 5 (run 1) | Quelques secondes (API) | ✅ Oui — `192.168.1.203` identifié comme cible ET source, scénario de pivot construit | ✅ Aucune contradiction | Rapport directement actionnable |
| Claude Sonnet 5 (run 2) | Quelques secondes (API) | ✅ Oui — même corrélation retrouvée indépendamment | ✅ Conclusion cohérente avec le corps du texte | Reproductible sur deux runs |
| **Mistral Large (API, société UE)** | **Quelques secondes (API)** | **✅ Oui — même hôte identifié source ET cible, recommandation d'isolement explicite** | **✅ Aucune contradiction, format tableau clair** | **Egale ou dépasse Sonnet sur la lisibilité, coût quasi nul, hébergement UE** |
| DeepSeek-R1-Distill-14B (raisonnement bypassé) | 11 min | ❌ Non — chaque signature traitée isolément | ⚠️ Un même type d'anomalie TCP classé différemment selon l'endroit du texte | Structure correcte, calibration incohérente |
| DeepSeek-R1-Distill-14B (raisonnement forcé) | 15 min 33s | ❌ Non | ❌ Contradiction franche : 211 vs 207 alertes annoncées ; mélange de langue (un mot chinois en plein milieu du texte français) ; "215 signaux prioritaires" annoncés en fin de rapport, noyant les 2 vrais signaux dans un bruit d'alarme massif | Dégradé par rapport au run sans raisonnement forcé |
| DeepSeek-R1-Distill-32B (raisonnement forcé) | 29 min 10s | ❌ Non — les faits sont listés côte à côte sans être reliés | ⚠️ Léger : "5 signaux" annoncés en conclusion, 4 seulement énumérés | Nettement meilleure calibration que le 14B, toujours pas de corrélation multi-signaux |

### Ce qui distingue vraiment Sonnet et Mistral

Sur les deux runs Sonnet et sur les runs Mistral, le modèle a identifié que l'hôte interne `192.168.1.203` était à la fois la **cible** des alertes de scan entrant et la **source** de plusieurs signatures d'exploitation sortantes (Netgear RCE, WebShell) — et en a déduit un scénario cohérent de compromission avec pivot. Aucun des runs R1, ni le 14B ni le 32B, n'a fait ce lien, alors que les faits étaient présents dans les mêmes données brutes. La taille du modèle (14B → 32B) a amélioré la calibration du bruit et réduit les excès d'alarme, mais n'a pas comblé cet écart précis de raisonnement en chaîne — ce qui suggère que l'écart tient autant à l'ampleur de l'entraînement ciblé (RLHF) qu'à la taille brute, et que ce type d'entraînement n'est pas l'apanage exclusif d'un seul fournisseur : Mistral, société française, y arrive tout aussi bien que Sonnet.

> ⚠️ **Particularités techniques rencontrées lors de ces tests, pour qui voudrait les reproduire.** Les modèles R1 ont une tendance documentée par DeepSeek eux-mêmes à *"bypasser"* leur propre mode de raisonnement sur certaines requêtes (aucune balise `<think>` produite), rendant le temps d'exécution imprévisible d'un run à l'autre. Le forcer demande d'appeler l'API Ollama en mode `raw` avec les tokens spéciaux exacts du modèle (`<｜User｜>`, `<｜Assistant｜>` — des barres verticales pleine chasse, pas des barres standards) et de pré-remplir la réponse avec `<think>\n`. Le raisonnement interne produit dans ce mode reste très souvent en anglais, indépendamment de la langue du prompt — sans incidence sur la langue de la réponse finale, qui suit correctement la consigne.

### Le vrai coût de l'écart

Sonnet a répondu en quelques secondes pour quelques centimes via API. Le R1-32B a nécessité 29 minutes en CPU pur, sur une machine dont la RAM a frôlé la saturation (98% dès le chargement, sur 64 Go partagés avec d'autres VM) — sans offrir la qualité de corrélation de Sonnet. Loué sur un GPU 24 Go à l'heure (~0,30 $/h), le même modèle aurait probablement répondu en quelques minutes pour quelques centimes également — mais le fossé de raisonnement avec Sonnet, lui, ne se comble pas en changeant de matériel.

### Erreur visible, erreur silencieuse — la vraie question derrière ce test

Une objection légitime se pose à ce stade : si le but final est un rapport **lu par un analyste humain**, est-ce qu'une éventuelle erreur du LLM ne serait pas simplement repérée à la lecture, rendant le déterminisme superflu ?

La réponse dépend du **type** d'erreur, et c'est la distinction la plus importante de ce chapitre :

- **Les erreurs visibles** se voient à la relecture — un texte tronqué, une contradiction numérique flagrante (211 vs 207), un mélange de langue. Un analyste attentif les repère sans peine, et sur ce point, la supervision humaine est un vrai filet de sécurité qui rend le déterminisme moins critique.
- **Les erreurs silencieuses** ne se voient pas, parce qu'elles **ne ressemblent en rien à une erreur**. Le tout premier échec documenté dans ce chapitre — un modèle classant un webshell confirmé en *"bruit de reconnaissance passive"* — était rédigé avec la même prose fluide et confiante que le reste du rapport. Rien n'attirait l'œil. C'est exactement le mécanisme de la fatigue d'alerte, documenté en cybersécurité depuis des décennies : un analyste qui lit un rapport cohérent et bien écrit tous les matins, pendant des mois, va progressivement baisser sa garde face à un format qui a l'air normal 99% du temps — y compris le jour où il ne l'est pas.

Le déterminisme ne protège donc pas contre "le LLM se trompe" en général — il protège spécifiquement contre le cas où **le LLM se trompe sans que rien ne le signale**. C'est ce risque précis, pas la qualité générale du modèle, qui justifie de garder une classification déterministe en frontal d'un pipeline qui tourne sans supervision immédiate, même si un modèle de la classe de Sonnet serait probablement plus fiable qu'un humain fatigué sur la majorité des cas.

> ℹ️ **Ce que ce test ne prouve pas.** Deux runs Sonnet concordants sont un bon indice de fiabilité, pas une preuve d'infaillibilité — la même prudence méthodologique que celle appliquée tout au long de ce chapitre aux modèles locaux s'applique ici aussi. Pour un usage supervisé où l'analyste relit chaque rapport, un grand LLM sans contrainte déterministe est probablement le meilleur choix. Pour un pipeline entièrement automatisé sans lecture systématique, le déterminisme reste la police d'assurance qu'aucun modèle, aussi capable soit-il, ne remplace encore totalement.

### Un troisième type d'erreur — l'interprétation confiante d'un artefact réel

Les tests initiaux ont révélé deux types d'erreurs : l'invention pure (une CVE non vérifiable, corrigée par une interdiction explicite dans le prompt) et l'incohérence de calibration (un signal minimisé ou un décompte contradictoire). L'usage en production de la variante cloud (section 10) en a révélé un troisième, plus insidieux, sur Mistral pourtant jugé le plus fiable des quatre modèles testés.

Une alerte réelle nommée `Circuit Breaker: Golden Ticket Attack Detection` est apparue dans les données. Son contenu véritable, vérifié directement dans OpenSearch, n'a **rien à voir avec une attaque Kerberos** : c'est UTMStack qui signale que sa propre règle de corrélation "Golden Ticket Attack Detection" a planté et a été désactivée après 5 échecs (`"expression value cannot be nil after placeholder resolution"`) — un message de plomberie interne, pas une détection de sécurité.

Mistral a lu le nom littéralement et construit, avec un aplomb total et sur **deux runs indépendants**, une analyse Kerberos complète et plausible : vérification des tickets de plus de 10h, audit des comptes privilégiés, réinitialisation du compte `krbtgt`. Rien dans le ton n'indiquait une incertitude — la même prose confiante que pour les signaux réellement confirmés.

Ce cas est distinct de l'invention pure : le nom de la règle était authentique, présent dans les vraies données. L'erreur porte sur l'**interprétation du sens**, pas sur l'existence du fait. Une règle anti-invention ("ne cite jamais une référence absente des données") ne suffit pas à s'en prémunir, puisque rien n'a été inventé au sens strict. Le même run a produit une seconde illustration, plus grossière : une mention d'alerte `SOC Pipeline Heartbeat Failure — hors service depuis 26h`, alors que le pipeline venait de fonctionner pour produire ce rapport même — une contradiction logique interne qu'un simple garde-fou de cohérence temporelle pourrait détecter, mais qui n'existe pas dans ce prompt d'analyse libre.

Le point à retenir : même le modèle le plus fiable de la comparaison reste sujet à ce type d'erreur, reproductible sur plusieurs runs. C'est un argument supplémentaire, indépendant de la qualité du modèle, en faveur de la structure abordée en section 10 — garder le pipeline déterministe comme rapport de référence, et traiter toute analyse libre comme un second avis à vérifier, jamais comme une source unique de vérité.

---

## 10. Variante cloud — remplacer Qwen par un LLM hébergé

Les tests de la section précédente ont mis en évidence un résultat qu'il serait malhonnête de taire : Mistral Large, hébergé en UE, égale ou dépasse la qualité d'analyse du meilleur modèle testé, pour un coût mensuel négligeable. Cette section documente comment cette option a été intégrée au pipeline, **en complément du pipeline local existant, jamais à sa place**.

### Le principe — même architecture, moteur interchangeable

L'architecture déterministe décrite dans ce chapitre (tri JS, squelette pré-rédigé, enrichissement threat intelligence, corrélation temporelle) reste strictement identique. Le seul changement : le nœud d'appel LLM, qui pointait vers Ollama/Qwen en local, pointe désormais vers l'API Mistral. Le modèle ne fait toujours que de la **complétion** — remplir des emplacements `[COMMENTAIRE_N]` dans un texte déjà classé et structuré, jamais de classification libre. Toutes les garanties du pipeline déterministe restent intactes ; seule la qualité de rédaction change, à la marge.

### Coût réel mesuré

Pour un rapport complet (prompt d'environ 3000 tokens en entrée, réponse de 1000-1500 tokens), le coût avec Mistral Large (0,50 $ / 1,50 $ par million de tokens) revient à :

```
Un rapport par jour, 30 jours : ≈ 0,11 $/mois
Rapport quotidien + à la demande quotidien : ≈ 0,22 $/mois
```

Négligeable, dans le même ordre de grandeur que Claude Sonnet testé en section 9.

> ⚠️ **Le tier gratuit n'est pas fait pour la production.** Mistral propose un plan "Experiment" gratuit (~1 milliard de tokens/mois), largement suffisant en volume pour ce cas d'usage — mais ce tier **utilise les données envoyées pour l'entraînement de leurs modèles par défaut**, sauf opt-out manuel dans Admin Console → Confidentialité. Pour un usage réel, même de lab, le passage sur le **Scale plan** (pay-as-you-go, sans minimum, sans abonnement) est la seule option sérieuse : il active la garantie de non-entraînement par défaut et donne accès au DPA (Data Processing Addendum) standard, sans négociation commerciale requise. Le surcoût pour y accéder est nul — le Scale plan est une facturation à l'usage, pas un forfait.

### Ce que ce choix règle, et ce qu'il ne règle pas pour la nLPD

Le passage Suisse → UE est reconnu comme offrant un niveau de protection adéquat par la nLPD, sans clause contractuelle type ni garantie supplémentaire — contrairement à un transfert vers les USA ou tout pays sans décision d'adéquation. Combiné au DPA disponible sur le Scale plan et à la garantie de non-entraînement, ce choix règle la question du **mécanisme de transfert**.

Il ne règle pas, à lui seul :
- **La nature des données envoyées** — une IP d'attaquant externe n'est généralement pas une donnée personnelle ; un nom d'utilisateur ou un poste nominatif (pertinent si une future intégration O365/Purview enrichit le flux) en serait une, avec un régime plus strict
- **Le registre des activités de traitement**, que la nLPD demande de tenir pour toute activité impliquant un sous-traitant externe
- **L'information des personnes concernées**, si des données nominatives venaient à transiter

Ces points relèvent d'une vérification par un DPO ou un juriste, indépendamment du fournisseur choisi — le choix de Mistral simplifie le terrain, il ne dispense pas de l'analyse.

### Le pattern double-rapport — la vraie réponse pratique au dilemme de la section 9

Plutôt que de choisir entre "garder le déterminisme" et "profiter de la qualité d'analyse libre d'un grand LLM", le pipeline de production fait tourner **les deux, en parallèle, jamais mélangés** :

| | Rapport officiel | Rapport complémentaire |
|---|---|---|
| Architecture | Tri déterministe + squelette + complétion | Données brutes, analyse libre |
| Fiabilité | Garantie par construction | Dépendante de la qualité du modèle, non garantie |
| Stockage | Table `resumes_soc` | Table séparée `resumes_soc_libre` |
| Étiquetage | Aucun avertissement nécessaire | Bandeau explicite "à titre indicatif", objet de mail préfixé, page web sur fond distinct |
| Rôle | Source de vérité, alimente le heartbeat | Second avis, peut repérer ce que `TERMES_SIGNAL` ne couvre pas encore |

Le rapport complémentaire a une vraie valeur ajoutée démontrée : sur un run réel, il a correctement identifié la boucle SMTP EHLO comme faux positif probable, sans qu'on le lui indique — exactement le type de découverte qu'une liste de mots-clés figée ne peut pas anticiper. Mais le cas "Golden Ticket" documenté plus haut montre aussi sa limite : sans supervision, il ne remplace pas le rapport officiel, il l'enrichit.

### Quand choisir quoi

| Besoin | Recommandation |
|---|---|
| Pipeline automatisé, aucune sortie de donnée acceptable | 100% local (Qwen), comme documenté dans tout le reste de ce chapitre |
| Rapport officiel avec une meilleure qualité de rédaction, coût acceptable | Variante cloud (Mistral) en remplacement du moteur, architecture déterministe inchangée |
| Second avis d'analyse plus riche, en complément | Pattern double-rapport, jamais en source unique |
| Contexte réglementaire strict (secteur régulé, contrat client zéro-sortie) | 100% local, indépendamment du coût de la variante cloud |

La configuration de déploiement complète de cette variante (comptes, clés, credential SMTP, fichiers JSON) est détaillée dans l'[annexe technique](https://doit4everyone.github.io/utmstack-lab/docs/09-pipeline-llm-deploiement.html#12-variante-cloud--déploiement-mistral).

---

## 11. Supervision du pipeline — détecter la panne silencieuse

Un pipeline SOC qui échoue en silence est un problème de conception, pas un détail. Si n8n s'arrête, si Ollama plante, ou si le Schedule Trigger reste dépublié après un import — le rapport quotidien ne s'affiche simplement plus. Pour un analyste qui consulte le dashboard, l'absence de rapport ressemble en tout point à *"rien à signaler"*. C'est le pire mode de défaillance possible pour un outil de sécurité : la panne produit exactement le même signal que l'absence d'incident.

### Pourquoi ce n'est pas n8n qui surveille n8n

Le réflexe naturel serait d'ajouter un workflow n8n de plus, qui vérifie que les autres tournent bien. C'est un contresens : **un surveillant qui meurt en même temps que le système surveillé ne détecte rien.** Si n8n est down, un workflow de heartbeat hébergé dans n8n est down aussi.

Le heartbeat doit tourner **en dehors** du système qu'il surveille. Dans ce lab, il tourne directement sur la VM UTMStack — celle qui reste debout même si `docker-services` (n8n, PostgreSQL, Qdrant) est éteinte.

### Architecture retenue

Un script shell interroge en local la table `resumes_soc` :

```sql
SELECT COALESCE(ROUND(EXTRACT(EPOCH FROM (NOW() - MAX(date_generation)))/3600), 9999)
FROM resumes_soc;
```

Si le dernier rapport a plus de 26h (2h de tolérance après le run planifié de 6h00), le script émet un message **syslog** vers l'agent UTMStack — transformant la panne du pipeline en un événement que le SIEM peut lui-même corréler et afficher comme une alerte.

```
┌─────────────────────────┐
│  VM UTMStack               │  tourne indépendamment
│  (timer systemd, 08h00)    │  de docker-services
│                             │
│  soc-pipeline-heartbeat.sh  │
│  → interroge resumes_soc    │
│    en local (docker exec)   │
│  → si > 26h : syslog        │
└─────────────┬───────────────
              │ logger -n <agent> -P 7014
              ▼
┌─────────────────────────┐
│  Agent Windows UTMStack     │
└─────────────┬───────────────
              ▼
┌─────────────────────────┐
│  v11-log-syslog-*           │  message brut visible
└─────────────┬───────────────
              ▼
┌─────────────────────────┐
│  Règle de corrélation       │  contains("raw",
│  UTMStack (créée via UI)    │  "SOC-PIPELINE-HEARTBEAT
│  Confidentiality/Integrity/ │  FAILURE")
│  Availability = 3/3/3       │
└─────────────┬───────────────
              ▼
┌─────────────────────────┐
│  v11-alert-*                 │  alerte High,
│  "SOC Pipeline Heartbeat     │  visible au dashboard
│   Failure"                   │
└─────────────────────────┘
```

**Fail-safe, pas fail-silent** : toute réponse anormale de la requête PostgreSQL (base injoignable, table vide, sortie corrompue) est traitée comme un âge de "9999h" — donc comme une panne à signaler, jamais comme un cas neutre passé sous silence.

**Un garde-fou contre les faux positifs** : la VM UTMStack de ce lab n'étant pas allumée en continu, un simple redémarrage produirait un déclenchement immédiat (le dernier rapport a alors mécaniquement plus de 26h). Le script vérifie l'uptime de la machine et diffère la vérification si elle vient de démarrer depuis moins de 2h — sans jamais annuler une vraie alerte, seulement la reporter à la vérification suivante.

Déploiement en **timer systemd** plutôt qu'en cron classique, pour deux raisons concrètes : `Persistent=true` rattrape l'exécution manquée si la VM était éteinte à l'heure planifiée — indispensable pour un lab qui ne tourne pas 24/7 — et `journalctl -u soc-pipeline-heartbeat` centralise le diagnostic au même endroit que le reste des services systemd déjà en place sur cette VM.

### Validation en conditions réelles

Le mécanisme complet a été testé de bout en bout, alerte forcée à l'appui : script → syslog → agent → OpenSearch → règle de corrélation → alerte visible au dashboard, avec sévérité **High** et statut **Open**. Le script et sa procédure de déploiement complète (y compris la construction de la règle de corrélation via l'interface UTMStack, faute de format `.yaml` sur cette plateforme — la corrélation vit en base PostgreSQL, dans un langage d'expression propre à UTMStack) sont détaillés dans l'[annexe technique](https://doit4everyone.github.io/utmstack-lab/docs/09-pipeline-llm-deploiement.html#11-supervision-du-pipeline--heartbeat).

## 12. Limitations connues, assumées honnêtement

- **Pas de détection de chaîne d'exploitation avant l'ajout de la section 6** — et même avec, la corrélation reste simple (récurrence d'IP sur 30 jours), pas une vraie modélisation comportementale
- **Dépendance forte à `TERMES_SIGNAL`/`BRUIT`/`CONTROLE`** — une liste de mots-clés maintenue à la main, qui doit être enrichie à chaque nouvelle source de données (Kali red team, O365, Azure) sous peine de laisser passer des signatures inconnues en zone grise
- **Les événements Microsoft Defender ne sont pas encore corrélés** — un test EICAR confirme que Defender détecte et que l'agent UTMStack remonte bien l'événement dans les logs bruts (`v11-log-*`, canal `Microsoft-Windows-Windows Defender/Operational`), mais aucune règle de corrélation UTMStack native ne promeut cet événement en alerte (`v11-alert-*`) — un chantier de règle de corrélation dédiée reste à faire
- **ThreatFox reste silencieux sur les cas testés** — probablement normal (base spécialisée malware, toutes les IP n'y figurent pas), non confirmé de façon exhaustive

### Chantiers de durcissement volontairement différés

Une revue d'architecture menée sur ce pipeline a identifié deux améliorations supplémentaires, sciemment reportées plutôt qu'appliquées dans l'immédiat :

- **Promotion automatique d'un INDÉTERMINÉ en SIGNAL sur la base d'un score threat intelligence élevé** (seuil retenu : AbuseIPDB ≥ 75 OU classification GreyNoise "malicious"). Aujourd'hui, une IP avec un score de réputation confirmé mais dont la signature Suricata ne matche aucun mot-clé de `TERMES_SIGNAL` reste visible dans les données du rapport, mais pas mise en avant dans la section prioritaire — l'analyste doit la repérer lui-même. Corriger ça proprement demande de redistribuer la construction du squelette entre deux nœuds du pipeline (aujourd'hui, le squelette est écrit avant que les données threat intelligence soient disponibles) — une opération qui touche deux nœuds actuellement stables. Reportée à une session de durcissement dédiée, après les intégrations d'agents et les tests Kali, pour ne pas fragiliser un pipeline qui vient d'être stabilisé juste avant une phase de tests plus large.
- **Déplacement des clés API threat intelligence vers le credential store n8n**, plutôt que dans les headers des nœuds HTTP. Sur un lab avec des clés gratuites révocables, l'enjeu n'est pas la confidentialité en tant que telle — c'est d'éliminer une classe d'erreur récurrente lors des futures publications sur ce dépôt : un export de workflow oublié sans nettoyage manuel expose les clés en clair. Reportée pour la même raison que le point précédent — regrouper les changements structurels du pipeline en une seule session plutôt que les répartir.

---

> [← Retour à l'index](https://doit4everyone.github.io/utmstack-lab/docs/) | [→ Guide de déploiement du pipeline](https://doit4everyone.github.io/utmstack-lab/docs/09-pipeline-llm-deploiement.html)
