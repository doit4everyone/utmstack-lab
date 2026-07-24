#!/bin/bash
#
# install-heartbeat.sh
# Installe le heartbeat de supervision du pipeline SOC en service systemd.
# A executer en root sur la VM UTMStack.
#
# Prerequis : avoir adapte AGENT_SYSLOG_IP dans soc-pipeline-heartbeat.sh
#
set -e

echo "[1/5] Copie du script"
install -m 755 soc-pipeline-heartbeat.sh /usr/local/bin/soc-pipeline-heartbeat.sh

echo "[2/5] Copie des unites systemd"
install -m 644 soc-pipeline-heartbeat.service /etc/systemd/system/
install -m 644 soc-pipeline-heartbeat.timer   /etc/systemd/system/

echo "[3/5] Rechargement systemd"
systemctl daemon-reload

echo "[4/5] Activation du timer"
systemctl enable --now soc-pipeline-heartbeat.timer

echo "[5/5] Test immediat (sans attendre 08h00)"
systemctl start soc-pipeline-heartbeat.service || true

echo
echo "=== Etat ==="
systemctl status soc-pipeline-heartbeat.timer --no-pager || true
echo
echo "=== Prochaine execution planifiee ==="
systemctl list-timers soc-pipeline-heartbeat.timer --no-pager || true
echo
echo "=== Resultat du test ==="
tail -5 /var/log/soc-pipeline-heartbeat.log 2>/dev/null || echo "(pas encore de log)"
