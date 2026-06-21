#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Detect-WEF-NTLM.ps1 — Script de détection Intune pour la remediation WEF NTLM

.DESCRIPTION
    Vérifie si la souscription WEF "NTLM-Operational-Local" est présente sur la machine.
    - Exit 0 = Compliant (souscription présente, pas de remédiation nécessaire)
    - Exit 1 = Non-compliant (souscription absente, déclenche Deploy-WEF-NTLM-Intune.ps1)

.NOTES
    Déploiement   : Intune Admin Center → Devices → Scripts and Remediations → Remediations
                    Detection script field
    Cible         : Endpoints Intune (Win 11 24H2+, AAD-joined ou Hybrid)
    Auteur        : UTMStack Lab — lab.local
    Version       : 1.0
    Date          : 2026-06-16

.LINK
    Documentation : https://doit4everyone.github.io/utmstack-lab/08-ntlm-audit
#>

$SubscriptionName = "NTLM-Operational-Local"

$null = wecutil gs $SubscriptionName 2>$null
if ($LASTEXITCODE -eq 0) {
    Write-Output "Subscription '$SubscriptionName' present — compliant"
    exit 0
} else {
    Write-Output "Subscription '$SubscriptionName' missing — non-compliant"
    exit 1
}
