<#
.DESCRIPTION
    Découvre les contrôleurs de domaine (DC) d'un domaine Active Directory
    via le DNS, puis affiche leur nom et leur adresse IP.

    - Aucune élévation de privilèges nécessaire (simple utilisateur).
    - Aucun module externe : uniquement des commandes Windows natives.
    - Principe : chaque DC s'enregistre dans le DNS avec un enregistrement SRV
      "_ldap._tcp.dc._msdcs.<domaine>". Il suffit d'interroger le même
      serveur DNS que le domaine pour tous les retrouver.

.NOTES
    À utiliser uniquement sur un réseau dont vous êtes administrateur
    ou pour lequel vous avez une autorisation explicite.
#>

param(
    [string]$Domaine,
    [string]$ExportCsv
)

# 1. Quels serveurs DNS ce poste utilise-t-il ?
$serveursDns = Get-DnsClientServerAddress -AddressFamily IPv4 |
    Where-Object { $_.ServerAddresses } |
    Select-Object -ExpandProperty ServerAddresses -Unique
Write-Host "Serveurs DNS du poste : $($serveursDns -join ', ')" -ForegroundColor Cyan

# 2. Quel est le domaine ? (paramètre > session > suffixe DNS)
if (-not $Domaine) { $Domaine = $env:USERDNSDOMAIN }
if (-not $Domaine) {
    $Domaine = (Get-DnsClient | Where-Object { $_.ConnectionSpecificSuffix } |
        Select-Object -First 1).ConnectionSpecificSuffix
}
if (-not $Domaine) {
    $Domaine = (Get-DnsClientGlobalSetting).SuffixSearchList | Select-Object -First 1
}
if (-not $Domaine) {
    Write-Warning "Domaine introuvable. Relancez avec : -Domaine 'mondomaine.local'"
    return
}
Write-Host "Domaine recherché     : $Domaine" -ForegroundColor Cyan
Write-Host ""

# 3. Interroger le DNS : quels sont les contrôleurs de domaine ?
try {
    $enregistrementsSrv = Resolve-DnsName -Name "_ldap._tcp.dc._msdcs.$Domaine" -Type SRV -ErrorAction Stop |
        Where-Object { $_.Type -eq 'SRV' }
}
catch {
    Write-Warning "Aucun contrôleur de domaine trouvé pour '$Domaine' : $($_.Exception.Message)"
    return
}

# Le DC qui détient le rôle PDC (maître des opérations)
$pdc = (Resolve-DnsName -Name "_ldap._tcp.pdc._msdcs.$Domaine" -Type SRV -ErrorAction SilentlyContinue |
    Where-Object { $_.Type -eq 'SRV' }).NameTarget

# 4. Pour chaque DC : récupérer son adresse IP
$resultats = foreach ($srv in ($enregistrementsSrv | Sort-Object NameTarget -Unique)) {
    $ips = (Resolve-DnsName -Name $srv.NameTarget -Type A -ErrorAction SilentlyContinue |
        Where-Object { $_.Type -eq 'A' }).IPAddress
    [PSCustomObject]@{
        Nom       = $srv.NameTarget
        AdresseIP = if ($ips) { $ips -join ', ' } else { 'Non résolue' }
        PDC       = if ($srv.NameTarget -eq $pdc) { 'Oui' } else { '' }
        Port      = $srv.Port
        Priorite  = $srv.Priority
    }
}

# 5. Affichage (et export CSV si demandé)
Write-Host "$($resultats.Count) contrôleur(s) de domaine trouvé(s) :" -ForegroundColor Green
$resultats | Format-Table -AutoSize

if ($ExportCsv) {
    $resultats | Export-Csv -Path $ExportCsv -NoTypeInformation -Encoding UTF8 -Delimiter ';'
    Write-Host "Résultats exportés vers : $ExportCsv" -ForegroundColor Green
}