---
title: "Installation UTMStack v11 sous VMware Workstation | DoIt4Everyone"
description: "Guide complet installation UTMStack v11.2.8 Community Edition sous VMware Workstation. Configuration VM, bug DHCP, RAM minimum réelle pour l'auto-updater, optimisations post-install pour lab PME Suisse."
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

# Installation UTMStack v11.2.8 sous VMware Workstation

> [← Retour à l'index](../)

> ⚠️ **Mise à jour critique (29 juin 2026) :** un incident terrain a révélé que la RAM recommandée à l'étape 6.7 (10 GB) bloque silencieusement le service d'auto-mise à jour d'UTMStack, créant une boucle d'échec invisible pendant des semaines. Voir la nouvelle section [10. RAM minimum réelle](#10-ram-minimum-réelle--la-leçon-du-29-juin-2026) avant d'appliquer l'étape 6.7.

## 📋 Table des matières

1. [Paramètres de la machine virtuelle](#1-paramètres-de-la-machine-virtuelle)
2. [Bug critique — DHCP](#2-bug-critique--le-dhcp-fait-planter-linstallateur)
3. [Procédure d'installation](#3-procédure-dinstallation)
   - [3.1 Boot depuis l'ISO](#31-boot-depuis-liso)
   - [3.2 Configuration réseau](#32-configuration-réseau-dans-linstallateur)
   - [3.3 Reconnexion carte réseau](#33-reconnexion-de-la-carte-réseau-dans-vmware)
   - [3.4 Configuration du profil](#34-configuration-du-profil-utilisateur)
4. [Première connexion SSH](#4-première-connexion-ssh-avec-putty)
5. [Vérification de l'installation](#5-vérification-de-linstallation)
   - [5.1 Lancement manuel](#51-lancement-manuel-de-linstallateur-si-nécessaire)
6. [Optimisations post-installation](#6-optimisations-post-installation)
7. [Ports importants](#7-ports-importants-v1128)
8. [Snapshots recommandés](#8-snapshots-recommandés)
9. [Credentials](#9-credentials)
10. [RAM minimum réelle — la leçon du 29 juin 2026](#10-ram-minimum-réelle--la-leçon-du-29-juin-2026)

---

## 1. Paramètres de la machine virtuelle

Créer une nouvelle VM dans VMware Workstation avec les paramètres suivants :

| Paramètre | Valeur |
|-----------|--------|
| Système d'exploitation | Linux → Ubuntu 64-bit |
| RAM (installation) | 14336 MB — minimum requis par l'installateur |
| RAM (post-install) | 10240 MB — réduire après installation |
| vCPU | 1 socket × 4 cœurs |
| Disque | 150 GB SATA — thin provisioning |
| Firmware | UEFI |
| Réseau | Personnalisé (VMnet selon l'environnement) |
| Contrôleur I/O | LSI Logic (SCSI) |
| CD/DVD | SATA — pointer vers l'ISO UTMStack v11 |

> ⚠️ **État du périphérique — DÉCOCHER « Connecté » sur la carte réseau avant de démarrer la VM.**

---

## 2. Bug critique — Le DHCP fait planter l'installateur

### Symptôme

- L'installateur ISO démarre
- Une barre orange avec `[Help]` apparaît en haut de l'écran
- L'écran reste noir indéfiniment — le disque n'est jamais écrit

### Cause

Quand la carte réseau est connectée au démarrage, le serveur DHCP du réseau répond avant que l'installateur puisse configurer son environnement réseau interne, causant un conflit fatal dans le processus cloud-init d'autoinstall.

### Solution

Démarrer avec la carte réseau **déconnectée**. L'installateur affiche alors l'écran de configuration réseau permettant de saisir une IP statique, puis on reconnecte la carte dans VMware pendant l'installation.

---

## 3. Procédure d'installation

### 3.1 Boot depuis l'ISO

- Démarrer la VM (carte réseau déconnectée)
- Le menu GRUB apparaît automatiquement
- Sélectionner **« Install UTMStack v11 Community Edition »** → Entrée

### 3.2 Configuration réseau dans l'installateur

L'installateur détecte que la carte réseau est déconnectée et affiche : `disabled — autoconfiguration failed`.

- Cliquer sur l'interface réseau listée (ex : `ens33`)
- Sélectionner **« Edit IPv4 configuration »**
- Changer IPv4 Method de **Disabled → Manual**
- Remplir les champs :

| Champ | Exemple |
|-------|---------|
| Subnet | 192.168.1.0/24 |
| Address | 192.168.1.150 |
| Gateway | 192.168.1.254 |
| Name servers | 192.168.1.1, 8.8.8.8 |
| Search domains | mondomaine.local |

- Cliquer **« Save »**

### 3.3 Reconnexion de la carte réseau dans VMware

Pendant que l'installateur attend sur l'écran Network configuration :

- Dans VMware → **VM → Paramètres**
- Sélectionner la carte réseau
- Cocher **« Connecté »** dans « État du périphérique »
- Cliquer **OK**

> ℹ️ Utiliser `Alt+Tab` pour basculer entre VMware Settings et la console de la VM sans perdre le focus.

- Revenir dans l'installateur → **« Done »** ou **« Continue »**

### 3.4 Configuration du profil utilisateur

| Champ | Description |
|-------|-------------|
| Your name | Nom complet (ex : Admin UTMStack) |
| Your server's name | Nom de la machine (ex : utmstack) |
| Pick a username | Identifiant SSH (ex : admin) |
| Choose a password | Mot de passe sudo — **noter impérativement** |
| Confirm your password | Confirmation |

- L'installation Ubuntu se déroule automatiquement (10–20 minutes)
- La VM reboot automatiquement à la fin

> ℹ️ Après le reboot, le CD-ROM peut être éjecté dans les paramètres VMware.

---

## 4. Première connexion SSH avec PuTTY

| Paramètre | Valeur |
|-----------|--------|
| Hôte | IP statique configurée à l'étape 3.2 |
| Port | 22 |
| Utilisateur | Username saisi à l'étape 3.4 |
| Mot de passe | Password saisi à l'étape 3.4 |

Passer en root immédiatement après connexion :

```bash
sudo su
```

---

## 5. Vérification de l'installation

Environ 30 minutes après le début de l'installation, vérifier que tous les services UTMStack sont démarrés :

```bash
docker service ls
```

### Installation réussie — tous les services à 1/1

```
✅ utmstack_agentmanager              1/1
✅ utmstack_backend                   1/1
✅ utmstack_event-processor-manager   1/1
✅ utmstack_event-processor-worker    1/1
✅ utmstack_frontend                  1/1
✅ utmstack_node1                     1/1  ← OpenSearch
✅ utmstack_postgres                  1/1
✅ utmstack_user-auditor              1/1
✅ utmstack_web-pdf                   1/1
```

### Installation incomplète

```
❌ bash: docker: command not found
❌ Un ou plusieurs services à 0/1
❌ Aucun service listé
```

→ Lancer l'installateur manuellement (voir étape 5.1)

### 5.1 Lancement manuel de l'installateur (si nécessaire)

> ⚠️ Cette étape n'est nécessaire que si la vérification précédente indique une installation incomplète.

```bash
free -h          # Vérifier RAM disponible (minimum 12 GB libres)
sudo su
cd /opt/utmstack
./installer
```

Suivi en parallèle (second terminal PuTTY) :

```bash
tail -f /var/log/utmstack/installer.log
```

| Message affiché | Signification |
|-----------------|---------------|
| Generating Stack configuration... | Calcul de la distribution mémoire |
| Memory distribution successful | RAM suffisante — installation continue |
| Downloading images... | Téléchargement Docker (10–20 min) |
| Installing reverse proxy... | Configuration nginx |
| Initializing databases... | PostgreSQL + OpenSearch |
| Waiting for Backend to be ready... | Démarrage backend (2–3 min) |
| Generating Connection Key... | Génération token agents |
| Installation finished successfully. | Installation terminée ✔ |

**Erreur fréquente — RAM insuffisante :**
```
error balancing memory: insufficient memory: Available 7897MB < Total Minimum Required 11150MB
```
Solution : Power Off → augmenter à 14 GB dans VMware → relancer `./installer`

---

## 6. Optimisations post-installation

> ℹ️ Les étapes 6.4, 6.5 et 6.7 ne sont pas obligatoires si UTMStack dispose de 32 GB+. Les étapes 6.1, 6.2, 6.3 et 6.6 sont toujours recommandées.

### 6.1 Mise à jour du système d'exploitation

```bash
apt update && apt upgrade -y
```

### 6.2 Mises à jour de sécurité automatiques

```bash
apt install unattended-upgrades -y
dpkg-reconfigure --priority=low unattended-upgrades
```

### 6.3 Extension LVM — disque partiel par défaut

```bash
df -h /
lvextend -l +100%FREE /dev/mapper/ubuntu--vg-ubuntu--lv
resize2fs /dev/mapper/ubuntu--vg-ubuntu--lv
df -h /   # Résultat attendu : ~145 GB disponibles
```

### 6.4 Réduction mémoire OpenSearch (lab uniquement)

```bash
sed -i 's/OPENSEARCH_JAVA_OPTS=-Xms[0-9]*m -Xmx[0-9]*m/OPENSEARCH_JAVA_OPTS=-Xms1024m -Xmx1024m/' \
  /opt/utmstack/compose.yml
```

### 6.5 Suppression des réservations mémoire Docker (lab uniquement)

```bash
sed -i '/reservations:/{N;d;}' /opt/utmstack/compose.yml
```

### 6.6 Redéploiement avec les nouvelles configurations

```bash
export UTMSTACK_TAG=v11.2.8
docker stack deploy -c /opt/utmstack/compose.yml utmstack
docker service ls   # Vérifier 1/1
```

### 6.7 Réduction RAM VM à 10 GB (lab uniquement)

> ⚠️ **Voir impérativement la [section 10](#10-ram-minimum-réelle--la-leçon-du-29-juin-2026) avant d'appliquer cette étape.** 10 GB suffit au fonctionnement quotidien mais bloque silencieusement le service d'auto-mise à jour d'UTMStack.

- Power Off la VM UTMStack
- VM → Settings → Memory → **10240 MB**
- Power On — tous les services remontent automatiquement

---

## 7. Ports importants v11.2.8

| Port | Service | Usage |
|------|---------|-------|
| 443 / 10001 | Frontend | Interface web |
| 9000 | agentmanager | gRPC agents — contrôle |
| 9001 | agentmanager | HTTP agents |
| 50051 | event-processor-worker | gRPC — envoi logs agents |
| 8080 | event-processor-worker | HTTP |
| 8000 | event-processor-manager | HTTP |
| 7014 | Agent Windows | Réception syslog TCP/UDP |
| 7019 | Agent Windows | Suricata EVE JSON |

> ⚠️ Le port 7014 TCP doit être ouvert manuellement dans le Windows Firewall :

```powershell
New-NetFirewallRule -DisplayName "UTMStack Syslog TCP 7014" -Direction Inbound -Protocol TCP -LocalPort 7014 -Action Allow
```

---

## 8. Snapshots recommandés

| Nom du snapshot | Moment |
|-----------------|--------|
| UTMStack-v11.2.8-clean-install | Après installation + optimisations, avant agents |
| UTMStack-v11.2.8-operational | Après connexion de tous les agents et validation syslog |
| UTMStack-before-update | Avant chaque mise à jour manuelle de version (voir section 10) |

> ⚠️ Ne jamais restaurer un backup PostgreSQL d'une version antérieure dans une installation v11.2.8.

---

## 9. Credentials

| Accès | Valeur |
|-------|--------|
| Interface web | `https://<IP configurée>` |
| Username web | `admin` |
| Password web | Généré à l'installation — affiché en fin d'installateur |
| SSH user | Username saisi à l'étape 3.4 |
| SSH password | Password saisi à l'étape 3.4 |
| Admin interface | `https://<IP>:9090` |

> ⚠️ Le mot de passe admin est généré automatiquement et affiché **une seule fois** à la fin de l'installation. Le noter immédiatement.

---

## 10. RAM minimum réelle — la leçon du 29 juin 2026

### Ce que disait ce guide jusqu'ici

L'étape 6.7 recommandait de réduire la VM à **10 GB** après l'installation initiale, pour économiser des ressources sur un lab où UTMStack partage l'hôte avec d'autres VMs. Cette recommandation **reste valable pour le fonctionnement quotidien**, mais elle cache un piège sérieux découvert après plusieurs semaines d'exploitation continue.

### Le piège — `UTMStackComponentsUpdater`

UTMStack embarque un service systemd, **`UTMStackComponentsUpdater`**, qui tourne en arrière-plan en permanence et vérifie périodiquement s'il existe une nouvelle version sur GitHub. S'il en trouve une, il tente automatiquement de télécharger les nouvelles images Docker et de redéployer la stack — **sans aucune notification ni demande de confirmation.**

Le problème : ce processus de mise à jour a besoin de faire tourner temporairement les **anciens et les nouveaux conteneurs en parallèle** pendant la transition, ce qui exige nettement plus de RAM que le fonctionnement normal.

Sur une VM réduite à 10 GB (conformément à l'étape 6.7), ce service échoue avec :

```
error balancing memory: insufficient memory: Available 9913MB < Total Minimum Required 11150MB. (System requires 12150MB)
```

### La conséquence — une boucle d'échec silencieuse de plusieurs semaines

Sans limite de tentatives, systemd relance ce service **toutes les 2 minutes, indéfiniment**, dès qu'une mise à jour est disponible. Sur un lab resté allumé 3 semaines sans interruption, ça représente plus de **14 500 tentatives échouées** — entièrement invisibles dans l'interface UTMStack, et qui ne produisent aucune alerte.

> ⚠️ **Risque concret observé en lab :** si une opération de maintenance manuelle (redémarrage de service, `docker stack deploy`) intervient pile au moment où ce cycle d'échec de l'updater tente sa propre opération de redéploiement, les deux processus entrent en collision sur le réseau overlay Docker Swarm. Résultat observé : DNS interne instable (`server misbehaving`), table de routage IPVS désynchronisée (`no destination available` affiché en boucle sur la console), et services applicatifs (notamment `agentmanager`, responsable du SOAR) qui crashent en boucle sans lien apparent avec la cause réelle. Le diagnostic de cet incident a nécessité une journée complète, alors que la cause racine était une simple limite de RAM insuffisante pour un service qu'on ne savait même pas actif.

### Ce qu'il faut retenir

| Recommandation | Étape 6.7 (obsolète) | Validé terrain |
|---|---|---|
| RAM en fonctionnement courant | 10 GB | 10 GB *(reste valable)* |
| RAM minimum pour que l'auto-updater réussisse | Non documenté | **12 GB minimum (12150 MB exactement)** |
| RAM recommandée si l'auto-updater reste actif | Non documenté | **16 GB** (marge de sécurité pour la transition ancien/nouveau conteneurs) |

### Deux stratégies possibles

**Stratégie A — Garder le mode économique (10 GB), désactiver l'auto-updater**

Recommandé si tu préfères gérer les mises à jour manuellement, à un moment choisi :

```bash
systemctl stop UTMStackComponentsUpdater
systemctl disable UTMStackComponentsUpdater
```

Pour mettre à jour manuellement quand tu le décides : remonter temporairement la VM à 16 GB, puis lancer l'installeur existant :

```bash
/opt/utmstack/installer --install
```

L'installeur détecte l'installation existante et propose la mise à jour. Une fois terminée et le système stabilisé, redescendre la VM à 10 GB (étape 6.7).

**Stratégie B — Allouer durablement 16 GB à la VM**

Recommandé si l'hôte dispose de la RAM nécessaire pour les autres VMs du lab en plus de celle-ci. Laisse l'auto-updater fonctionner normalement en arrière-plan, sans intervention.

### Vérifier l'état du service avant de décider

```bash
systemctl status UTMStackComponentsUpdater --no-pager
journalctl -u UTMStackComponentsUpdater --no-pager | tail -20
```

Si tu vois un `restart counter` élevé (plusieurs centaines ou milliers) accompagné de `error balancing memory`, c'est le signe que ce piège est déjà actif sur ton installation — applique l'une des deux stratégies ci-dessus avant qu'une opération de maintenance ne déclenche le même type d'incident.

---

> [← Retour à l'index](index.md) | [→ Intégration Suricata](02-suricata.md)
