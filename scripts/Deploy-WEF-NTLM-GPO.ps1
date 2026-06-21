#Requires -RunAsAdministrator
# Deploy-WEF-NTLM-GPO.ps1
# Deploiement WEF pour collecte Microsoft-Windows-NTLM/Operational
# Version pour environnements AD on-prem avec GPO
# Script idempotent - verifie si la souscription existe deja avant de la creer
# Version : 1.3 - Fix FQDN au boot sans session utilisateur (2026-06-21)

$SubscriptionName       = "NTLM-Operational-Local"
$XmlPath                = "\\lab.local\SYSVOL\lab.local\scripts\ntlm-subscription.xml"
$LogFile                = "C:\Windows\Logs\Deploy-WEF-NTLM.log"
$ForwardedEventsMaxSize = 524288000
$MachineFQDN            = "$env:COMPUTERNAME.$((Get-WmiObject Win32_ComputerSystem).Domain)"

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $entry = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') [$Level] $Message"
    Add-Content -Path $LogFile -Value $entry -Encoding UTF8
    Write-Output $entry
}

Write-Log "=== Deploy-WEF-NTLM-GPO demarre sur $env:COMPUTERNAME ($MachineFQDN) ==="

# 0. Attendre que SYSVOL soit accessible (au boot, le reseau n'est pas pret immediatement)
$maxWait = 300  # 5 minutes max
$waited = 0
while (-not (Test-Path $XmlPath)) {
    if ($waited -ge $maxWait) {
        Write-Log "ERREUR : SYSVOL inaccessible apres $maxWait secondes. Abandon." "ERROR"
        exit 1
    }
    Start-Sleep -Seconds 10
    $waited += 10
}
if ($waited -gt 0) {
    Write-Log "SYSVOL accessible apres $waited secondes d'attente."
} else {
    Write-Log "SYSVOL accessible immediatement."
}

# 1. Idempotence
$null = wecutil gs $SubscriptionName 2>$null
if ($LASTEXITCODE -eq 0) {
    Write-Log "Souscription deja presente - aucune action requise."
    exit 0
}

Write-Log "Souscription absente - deploiement en cours..."

# 2. Activer le service Windows Event Collector
try {
    Set-Service -Name Wecsvc -StartupType Automatic -ErrorAction Stop
    $svc = Get-Service -Name Wecsvc
    if ($svc.Status -ne 'Running') {
        Start-Service -Name Wecsvc -ErrorAction Stop
        Write-Log "Service Wecsvc demarre."
    } else {
        Write-Log "Service Wecsvc deja en cours."
    }
} catch {
    Write-Log "ERREUR demarrage Wecsvc : $_" "ERROR"
    exit 1
}

# 3. Configurer WinRM local
try {
    $null = winrm quickconfig -quiet 2>&1
    Write-Log "WinRM configure."
} catch {
    Write-Log "AVERTISSEMENT WinRM : $_" "WARN"
}

# 4. ACL canal NTLM/Operational
try {
    $acl = "O:BAG:SYD:(A;;0xf0007;;;SY)(A;;0x7;;;BA)(A;;0x1;;;BO)(A;;0x1;;;SO)(A;;0x1;;;S-1-5-32-573)(A;;0x1;;;NS)"
    $null = wevtutil sl "Microsoft-Windows-NTLM/Operational" /ca:$acl 2>&1
    Write-Log "ACL canal NTLM/Operational appliquees."
} catch {
    Write-Log "ERREUR ACL : $_" "ERROR"
    exit 1
}

# 5. Activer et agrandir le canal ForwardedEvents
try {
    $null = wevtutil sl ForwardedEvents /e:true 2>&1
    $null = wevtutil sl ForwardedEvents /ms:$ForwardedEventsMaxSize 2>&1
    Write-Log "Canal ForwardedEvents active et agrandi a 500 MB."
} catch {
    Write-Log "AVERTISSEMENT ForwardedEvents : $_" "WARN"
}

# 6. Verifier le XML en SYSVOL
if (-not (Test-Path $XmlPath)) {
    Write-Log "ERREUR : Fichier XML introuvable : $XmlPath" "ERROR"
    exit 1
}

# 7. Initialiser le collecteur WEC
try {
    $null = wecutil qc /quiet 2>&1
    Write-Log "Collecteur WEC initialise."
} catch {
    Write-Log "AVERTISSEMENT wecutil qc : $_" "WARN"
}

# 8. Configurer le Subscription Manager (FQDN dynamique, pas localhost)
try {
    $smKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager"
    $smValue = "Server=http://${MachineFQDN}:5985/wsman/SubscriptionManager/WEC"
    if (-not (Test-Path $smKey)) {
        New-Item -Path $smKey -Force | Out-Null
    }
    Set-ItemProperty -Path $smKey -Name "1" -Value $smValue -Type String
    Write-Log "Subscription Manager configure : $smValue"
} catch {
    Write-Log "ERREUR Subscription Manager : $_" "ERROR"
}

# 9. Creer la souscription WEF
try {
    $null = wecutil cs $XmlPath 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Log "ERREUR wecutil cs (exit code $LASTEXITCODE)" "ERROR"
        exit 1
    }
    Write-Log "Souscription creee avec succes."
} catch {
    Write-Log "ERREUR creation souscription : $_" "ERROR"
    exit 1
}

# 10. Verification finale
Start-Sleep -Seconds 5
$status = wecutil gr $SubscriptionName 2>&1
Write-Log "Statut souscription : $status"

Write-Log "=== Deploiement termine sur $env:COMPUTERNAME ==="
exit 0
