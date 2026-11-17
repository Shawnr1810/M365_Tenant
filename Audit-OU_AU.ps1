# =====================================================================
#  Audit-OU.ps1
#
#  1) ON-PREM : liste les objets du domaine (ordinateurs, utilisateurs,
#               groupes) et vérifie s'ils sont rangés dans la bonne OU
#  2) AZURE   : Entra ID, On regarde l'équivalent :
#               les unités administratives et l'origine des appareils
#
#  - Aucun droit administrateur sur le poste (pas besoin du module RSAT :
#    on utilise [adsisearcher], intégré à Windows)
#  - Lecture seule : le script ne déplace et ne modifie rien
#  - Le poste doit être dans le domaine, avec un compte du domaine
#  
#
#  Lancement :
#     Unblock-File .\Audit-OU.ps1
#     Set-ExecutionPolicy RemoteSigned -Scope CurrentUser
#     .\Audit-OU.ps1
# =====================================================================


# ---------------------------------------------------------------------
#  A ADAPTER : le nom de VOS OU (une partie du nom suffit)
# ---------------------------------------------------------------------
$ouServeurs     = "OU=Serveurs"
$ouPostes       = "OU=Postes"
$ouUtilisateurs = "OU=Utilisateurs"
$ouServices     = "OU=Comptes de service"
$ouGroupes      = "OU=Groupes"


# Petite fonction pour chercher dans l'annuaire
function Chercher($filtre) {
    $recherche = [adsisearcher]$filtre
    $recherche.PageSize = 1000          # sinon AD s'arrête à 1000 résultats
    return $recherche.FindAll()
}

# Donne l'OU (le "dossier") d'un objet à partir de son DN
function Dossier($dn) {
    return ($dn -replace '^(?:[^,\\]|\\.)+,', '')
}

# Donne le RID (le numéro de fin du SID). En dessous de 1000 = objet intégré à Windows
function Rid($sidBytes) {
    $sid = [System.Security.Principal.SecurityIdentifier]::new($sidBytes, 0)
    return [int]($sid.Value.Split("-")[-1])
}

$resultats = @()


# ---------------------------------------------------------------------
#  PARTIE 1 : ON-PREM
# ---------------------------------------------------------------------
Write-Host ""
Write-Host "===== PARTIE 1 : ON-PREM =====" -ForegroundColor Yellow
Write-Host "Domaine : $env:USERDNSDOMAIN"


# --- 1.a Les ordinateurs ---
Write-Host "Lecture des ordinateurs..."
foreach ($o in (Chercher "(objectCategory=computer)")) {

    $nom = [string]$o.Properties["name"]
    $dn  = [string]$o.Properties["distinguishedname"]
    $os  = [string]$o.Properties["operatingsystem"]
    $groupePrincipal = [int]$o.Properties["primarygroupid"][0]

    $statut = "OK"
    $raison = ""

    if ($groupePrincipal -eq 516) {
        # 516 = contrôleur de domaine
        if ($dn -notlike "*OU=Domain Controllers,*") {
            $statut = "A CORRIGER"
            $raison = "Un DC doit rester dans l'OU Domain Controllers"
        }
    }
    elseif ($dn -like "*,CN=Computers,*") {
        $statut = "A DEPLACER"
        $raison = "Conteneur par défaut : seules les GPO du domaine s'appliquent"
    }
    elseif ($os -like "*Server*" -and $dn -notlike "*$ouServeurs,*") {
        $statut = "A DEPLACER"
        $raison = "Serveur hors de l'OU $ouServeurs"
    }
    elseif ($os -notlike "*Server*" -and $dn -notlike "*$ouPostes,*") {
        $statut = "A DEPLACER"
        $raison = "Poste hors de l'OU $ouPostes"
    }

    $resultats += [PSCustomObject]@{
        Source = "On-Prem"; Type = "Ordinateur"; Nom = $nom
        Emplacement = Dossier $dn; Statut = $statut; Raison = $raison
    }
}


# --- 1.b Les utilisateurs ---
Write-Host "Lecture des utilisateurs..."
foreach ($u in (Chercher "(&(objectCategory=person)(objectClass=user))")) {

    $nom = [string]$u.Properties["samaccountname"]
    $dn  = [string]$u.Properties["distinguishedname"]
    $rid = Rid $u.Properties["objectsid"][0]
    $estService = ($u.Properties["serviceprincipalname"].Count -gt 0) -or ($nom -like "svc*")

    $statut = "OK"
    $raison = ""

    if ($rid -lt 1000) {
        $raison = "Compte intégré à Windows (normal de le laisser)"
    }
    elseif ($dn -like "*,CN=Users,*") {
        $statut = "A DEPLACER"
        $raison = "Conteneur par défaut : seules les GPO du domaine s'appliquent"
    }
    elseif ($estService -and $dn -notlike "*$ouServices,*") {
        $statut = "A DEPLACER"
        $raison = "Compte de service hors de l'OU $ouServices"
    }
    elseif (-not $estService -and $dn -notlike "*$ouUtilisateurs,*") {
        $statut = "A VERIFIER"
        $raison = "Utilisateur hors de l'OU $ouUtilisateurs"
    }

    $resultats += [PSCustomObject]@{
        Source = "On-Prem"; Type = "Utilisateur"; Nom = $nom
        Emplacement = Dossier $dn; Statut = $statut; Raison = $raison
    }
}


# --- 1.c Les groupes ---
Write-Host "Lecture des groupes..."
foreach ($g in (Chercher "(objectCategory=group)")) {

    $nom = [string]$g.Properties["name"]
    $dn  = [string]$g.Properties["distinguishedname"]
    $rid = Rid $g.Properties["objectsid"][0]

    $statut = "OK"
    $raison = ""

    if ($rid -lt 1000 -or $dn -like "*,CN=Builtin,*") {
        $raison = "Groupe intégré à Windows (normal de le laisser)"
    }
    elseif ($dn -notlike "*$ouGroupes,*") {
        $statut = "A VERIFIER"
        $raison = "Groupe hors de l'OU $ouGroupes"
    }

    $resultats += [PSCustomObject]@{
        Source = "On-Prem"; Type = "Groupe"; Nom = $nom
        Emplacement = Dossier $dn; Statut = $statut; Raison = $raison
    }
}


# --- Résumé on-prem ---
Write-Host ""
Write-Host "Nombre d'objets par OU :" -ForegroundColor Cyan
$resultats | Group-Object Emplacement | Sort-Object Count -Descending |
    Format-Table Count, Name -AutoSize

$aCorriger = $resultats | Where-Object { $_.Statut -ne "OK" }
Write-Host "Objets mal rangés : $($aCorriger.Count)" -ForegroundColor Red
$aCorriger | Format-Table Type, Nom, Statut, Raison -AutoSize


# ---------------------------------------------------------------------
#  PARTIE 2 : AZURE / ENTRA ID
# ---------------------------------------------------------------------
Write-Host ""
Write-Host "===== PARTIE 2 : AZURE / ENTRA ID =====" -ForegroundColor Yellow
Write-Host "A savoir : Entra ID n'a pas d'OU. L'équivalent pour déléguer"
Write-Host "l'administration, ce sont les unités administratives (AU)."
Write-Host ""

$reponse = Read-Host "Se connecter à Entra ID ? (O/N)"

if ($reponse -eq "O") {

    if (-not (Get-Module -ListAvailable -Name Microsoft.Graph.Identity.DirectoryManagement)) {
        Write-Host "Le module Microsoft Graph n'est pas installé. Commande (sans droits admin) :" -ForegroundColor Red
        Write-Host "Install-Module Microsoft.Graph.Identity.DirectoryManagement -Scope CurrentUser"
    }
    else {

        # Lecture seule
        Connect-MgGraph -Scopes "AdministrativeUnit.Read.All", "Device.Read.All" -NoWelcome -ErrorAction SilentlyContinue

        if (Get-MgContext) {

            # --- 2.a Les unités administratives ---
            $unites = Get-MgDirectoryAdministrativeUnit -All

            if (-not $unites) {
                Write-Host "Aucune unité administrative : tout est géré au niveau du tenant entier." -ForegroundColor Red
            }

            foreach ($au in $unites) {
                $membres = Get-MgDirectoryAdministrativeUnitMember -AdministrativeUnitId $au.Id -All
                $resultats += [PSCustomObject]@{
                    Source = "Entra ID"; Type = "Unité administrative"; Nom = $au.DisplayName
                    Emplacement = "$($membres.Count) membre(s)"; Statut = "OK"; Raison = ""
                }
            }

            # --- 2.b Les appareils : viennent-ils de l'AD ou du cloud ? ---
            foreach ($d in (Get-MgDevice -All)) {

                $origine = "Cloud uniquement"
                if ($d.OnPremisesSyncEnabled) { $origine = "Synchronisé depuis l'AD" }

                $statut = "OK"
                $raison = ""
                if ($d.OperatingSystem -like "*Server*" -and -not $d.OnPremisesSyncEnabled) {
                    $statut = "A VERIFIER"
                    $raison = "Serveur présent dans Entra mais pas dans l'AD"
                }

                $resultats += [PSCustomObject]@{
                    Source = "Entra ID"; Type = "Appareil ($($d.OperatingSystem))"; Nom = $d.DisplayName
                    Emplacement = $origine; Statut = $statut; Raison = $raison
                }
            }

            Write-Host "Entra ID : $($unites.Count) unité(s) administrative(s) trouvée(s)."
            Disconnect-MgGraph | Out-Null
        }
        else {
            Write-Host "Connexion à Entra ID impossible ou annulée." -ForegroundColor Red
        }
    }
}


# ---------------------------------------------------------------------
#  EXPORT
# ---------------------------------------------------------------------
$bureau  = [Environment]::GetFolderPath("Desktop")
$fichier = "$bureau\Audit-OU.csv"
$resultats | Export-Csv $fichier -NoTypeInformation -Encoding UTF8 -Delimiter ";"
Write-Host ""
Write-Host "Fichier enregistré : $fichier" -ForegroundColor Green