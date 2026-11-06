# =====================================================================
#  MonPC.ps1
#
#  Vérifie, sur ce pc, que les protections de base sont actives
#  et que les services fragiles sont bien fermés (angle "blue team").
#
#  BUT: point de vue défensif. Pour chaque point, le script dit
#        si c'est OK ou A CORRIGER, et comment corriger.
#
#  - Aucun droit admin: tout est en LECTURE SEULE.
#    Le script ne change AUCUN réglage, il se contente de constater.
#  - Aucun module externe : commandes Windows natives.
#  - A utiliser sur votre propre machine.
#
#  Lancement :
#     Unblock-File .\MonPC.ps1
#     Set-ExecutionPolicy RemoteSigned -Scope CurrentUser
#     .\MonPC.ps1
# =====================================================================

$resultats = @()

# Petite fonction pour enregistrer chaque vérification
function Verif($categorie, $point, $ok, $details, $correction) {
    $script:resultats += [PSCustomObject]@{
        Categorie  = $categorie
        Point      = $point
        Statut     = if ($ok) { "OK" } else { "A CORRIGER" }
        Constat    = $details
        Correction = if ($ok) { "" } else { $correction }
    }
}

Write-Host ""
Write-Host "===== MonPC =====" -ForegroundColor Yellow
Write-Host "Machine : $env:COMPUTERNAME   Utilisateur : $env:USERNAME"
Write-Host "(Lecture seule : aucun réglage n'est modifié)"
Write-Host ""


# ---------------------------------------------------------------------
#  1. Le pare-feu est-il actif sur tous les profils ?
# ---------------------------------------------------------------------
foreach ($pf in (Get-NetFirewallProfile)) {
    Verif "Pare-feu" "Profil $($pf.Name)" $pf.Enabled `
        "Activé = $($pf.Enabled)" `
        "Activer le pare-feu pour ce profil (Paramètres > Sécurité Windows)"
}


# ---------------------------------------------------------------------
#  2. L'antivirus (Microsoft Defender) protège-t-il en temps réel ?
# ---------------------------------------------------------------------
try {
    $av = Get-MpComputerStatus -ErrorAction Stop
    Verif "Antivirus" "Protection temps réel" $av.RealTimeProtectionEnabled `
        "Temps réel = $($av.RealTimeProtectionEnabled)" `
        "Réactiver la protection en temps réel de Defender"

    $signaturesRecentes = $av.AntivirusSignatureAge -le 7
    Verif "Antivirus" "Signatures à jour" $signaturesRecentes `
        "Dernière mise à jour il y a $($av.AntivirusSignatureAge) jour(s)" `
        "Lancer une mise à jour des définitions de l'antivirus"
}
catch {
    Verif "Antivirus" "Microsoft Defender" $false `
        "Impossible de lire l'état (un autre antivirus est peut-être installé)" `
        "Vérifier que votre antivirus est actif et à jour"
}


# ---------------------------------------------------------------------
#  3. Les services fragiles sont-ils bien désactivés ?
# ---------------------------------------------------------------------
# Telnet : protocole en clair, ne devrait jamais tourner
$telnet = Get-Service -Name "TlntSvr" -ErrorAction SilentlyContinue
Verif "Services" "Telnet (en clair)" (-not $telnet -or $telnet.Status -ne "Running") `
    $(if ($telnet) { "Etat = $($telnet.Status)" } else { "Non installé" }) `
    "Arrêter et désactiver le service Telnet, utiliser SSH"


# ---------------------------------------------------------------------
#  4. Le Bureau à distance (RDP) est-il ouvert ?
# ---------------------------------------------------------------------
$rdp = (Get-ItemProperty "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -ErrorAction SilentlyContinue).fDenyTSConnections
# fDenyTSConnections = 1 signifie RDP REFUSE (donc fermé = bon)
Verif "Accès distant" "Bureau à distance (RDP)" ($rdp -eq 1) `
    $(if ($rdp -eq 1) { "RDP fermé" } else { "RDP OUVERT" }) `
    "Si vous n'utilisez pas RDP, le désactiver. Sinon ne jamais l'exposer sur Internet"


# ---------------------------------------------------------------------
#  5. Le disque est-il chiffré (BitLocker) ?
# ---------------------------------------------------------------------
try {
    $bl = Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction Stop
    Verif "Chiffrement" "BitLocker ($env:SystemDrive)" ($bl.ProtectionStatus -eq "On") `
        "Protection = $($bl.ProtectionStatus)" `
        "Activer BitLocker pour protéger les données en cas de vol du PC"
}
catch {
    Verif "Chiffrement" "BitLocker" $false `
        "Non vérifiable (édition Windows ou droits insuffisants)" `
        "Vérifier que le chiffrement du disque est actif"
}


# ---------------------------------------------------------------------
#  6. Les mises à jour Windows sont-elles récentes ?
# ---------------------------------------------------------------------
$derniereMaj = (Get-HotFix | Sort-Object InstalledOn -Descending |
    Select-Object -First 1).InstalledOn
$majRecente = $derniereMaj -and $derniereMaj -gt (Get-Date).AddDays(-45)
Verif "Mises à jour" "Dernier correctif Windows" $majRecente `
    $(if ($derniereMaj) { "Installé le $($derniereMaj.ToString('dd/MM/yyyy'))" } else { "Inconnu" }) `
    "Installer les mises à jour Windows (Paramètres > Windows Update)"


# ---------------------------------------------------------------------
#  7. Le compte Invité est-il désactivé ?
# ---------------------------------------------------------------------
try {
    $invite = Get-LocalUser -Name "Invité" -ErrorAction SilentlyContinue
    if (-not $invite) { $invite = Get-LocalUser -Name "Guest" -ErrorAction SilentlyContinue }
    if ($invite) {
        Verif "Comptes" "Compte Invité" (-not $invite.Enabled) `
            "Activé = $($invite.Enabled)" `
            "Désactiver le compte Invité"
    }
}
catch { }


# ---------------------------------------------------------------------
#  8. Résultat
# ---------------------------------------------------------------------
Write-Host "===== RESULTAT =====" -ForegroundColor Green
$resultats | Format-Table Categorie, Point, Statut, Constat -AutoSize

$aCorriger = $resultats | Where-Object { $_.Statut -eq "A CORRIGER" }
Write-Host ""
if ($aCorriger.Count -eq 0) {
    Write-Host "Tout est au vert. SUper Luc !" -ForegroundColor Green
}
else {
    Write-Host "$($aCorriger.Count) point(s) à corriger :" -ForegroundColor Red
    $aCorriger | Format-Table Point, Correction -AutoSize -Wrap
}

# Note de sécurité /100 (indicatif)
$score = [math]::Round(100 * ($resultats.Count - $aCorriger.Count) / $resultats.Count)
Write-Host "Note de sécurité : $score / 100" -ForegroundColor Cyan

$bureau  = [Environment]::GetFolderPath("Desktop")
$fichier = "$bureau\MonPC.csv"
$resultats | Export-Csv $fichier -NoTypeInformation -Encoding UTF8 -Delimiter ";"
Write-Host "Fichier enregistré : $fichier" -ForegroundColor Green