---
title: "SOC AI — Analyse automatique des alertes | DoIt4Everyone"
description: "Configuration SOC AI dans UTMStack v11.2.8 : Mistral AI, Google Gemini, analyse automatique des alertes, création d'incidents. Comparatif providers et recommandations RGPD."
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

# SOC AI — Analyse automatique des alertes

> [← Retour à l'index](../)

---

## Présentation

La fonctionnalité **SOC AI** intègre un modèle de langage directement dans le workflow d'investigation des alertes UTMStack. Elle analyse automatiquement les alertes, les corrèle avec le contexte historique et les feeds de threat intelligence, et génère des recommandations actionnables.

> ⚠️ **Avertissement UTMStack** — *"This evaluation has been made by an Artificial Intelligence beta that is still in training mode. Use this information carefully and at your own risk."* Le SOC AI est en phase bêta — les analyses sont indicatives et doivent être validées par un analyste.

---

## Providers supportés

UTMStack v11.2.8 supporte les providers suivants :

| Provider | Modèle testé | Free tier | Données |
|----------|-------------|-----------|---------|
| **Mistral AI** | mistral-small-latest | ✅ Plan Experiment | 🇪🇺 Europe |
| **Google Gemini** | gemini-2.5-flash | ✅ Limites quotidiennes | 🇺🇸 USA |
| OpenAI | gpt-4o | ❌ Payant | 🇺🇸 USA |
| Anthropic | claude-* | ❌ Payant | 🇺🇸 USA |
| Azure OpenAI | gpt-4 | ❌ Payant | Variable |
| Ollama | local | ✅ Gratuit | 🏠 Local |
| DeepSeek | deepseek-* | ✅ Limité | 🇨🇳 Chine |
| Groq | llama-* | ✅ Limité | 🇺🇸 USA |
| Custom | OpenAI-compatible | Variable | Variable |

---

## Étape 1 — Obtenir une clé API Mistral

### Procédure

1. Allez sur **[console.mistral.ai](https://console.mistral.ai)**
2. Créez un compte ou connectez-vous
3. **Workspace → API Keys → Create new key**
4. Nommez la clé (ex: `utmstack-soar`)
5. Sélectionnez le plan **Experiment** (gratuit)
6. Copiez la clé générée — elle n'est affichée qu'une seule fois

> ⚠️ Ne partagez jamais une clé API en clair dans un chat, email ou dépôt GitHub.

---

## Étape 2 — Configuration dans UTMStack

**UTMStack → Integrations → SOC AI → Mistral AI**

| Champ | Valeur |
|-------|--------|
| API Key | Clé copiée depuis la console Mistral |
| Model | `mistral-small-latest` |
| Auto-analyze alerts | ✅ Activé |
| Auto-create incidents | ✅ Activé |
| Change alert status after analysis | ✅ Activé |

Cliquez **Save configuration**.

---

## Comportement observé

### Analyse d'alerte

Pour chaque alerte déclenchée, le SOC AI génère automatiquement :

**Classification :** `Possible incident` / `False positive` / `Confirmed incident`

**Reasoning** — contexte et corrélation :
- Corrélation avec ThreatWinds threat intelligence
- Historique des alertes similaires (ex: *58 similar alerts for this signature*)
- Identification des outils offensifs (ex: `zgrab`, `zmap`)
- Analyse du comportement réseau

**Next steps** — recommandations actionnables :
- Immediate Isolation and Blocking
- Detailed Forensic Analysis
- Threat Intelligence Correlation
- Review and Tune Detection Rules

### Création automatique d'incidents

Avec **Auto-create incidents** activé, UTMStack groupe automatiquement les alertes corrélées en incidents `INC-YYYYMMDDHHMMSS` :

- Sévérité calculée automatiquement (HIGH / MEDIUM / LOW)
- Description générée par l'IA
- Statut **Open** jusqu'à validation humaine
- Couvre tous les agents connectés

> ℹ️ Les incidents sont visibles dans **Threat Management → Incidents**. Le matin, un analyste dispose d'une vue synthétique des événements de la nuit, déjà triés et priorisés.

---

## Comparatif Mistral vs Gemini 2.5 Flash

Test réalisé sur la même alerte *Known Malicious IP Detected* (`ET SCAN Zmap User-Agent`) :

| Critère | Mistral small | Gemini 2.5 Flash |
|---------|---------------|------------------|
| Classification | Possible incident | Possible incident |
| Contenu de l'analyse | Identique | Identique |
| Vitesse | Rapide | Rapide |
| Free tier | Plan Experiment | Limites quotidiennes |
| Localisation données | 🇪🇺 Europe | 🇺🇸 USA |
| RGPD / nLPD Suisse | ✅ Conforme | ⚠️ À vérifier |

**Observation importante :** UTMStack utilise un **template de prompt fixe** — le contenu de l'analyse est identique quel que soit le modèle. La qualité intrinsèque du modèle n'impacte pas visiblement le rendu dans l'interface v11.2.8.

---

## Recommandation

**Pour un contexte PME suisse ou européen → Mistral AI**

- Données traitées en Europe (conformité RGPD / nLPD)
- Plan Experiment gratuit suffisant pour un lab
- Résultat équivalent à Gemini pour un usage SOC

**Pour un lab sans contrainte de conformité → Gemini 2.5 Flash**

- Free tier généreux
- Modèle plus récent
- Résultat identique dans UTMStack v11.2.8

---

## Limitations connues

- **Langue** : analyses en anglais uniquement — pas de system prompt configurable dans l'interface native UTMStack
- **Template fixe** : la structure de l'analyse est imposée par UTMStack, indépendamment du modèle
- **Bêta** : fonctionnalité en cours de développement — à utiliser en complément d'une analyse humaine
- **Données sensibles** : les données d'alerte sont envoyées au provider IA — choisir un provider conforme aux exigences de l'organisation

---

> ℹ️ *Testé sur UTMStack v11.2.8, Mistral AI plan Experiment, Google Gemini 2.5 Flash free tier*

---

[← Dashboards UTMStack](04-dashboards.md) | [→ SOAR & Automatisation](05-soar.md)
