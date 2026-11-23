# =====================================================================
#  Audit-Utilisateurs.ps1
#
#  Liste les comptes et repère les risques de sécurité :
#   - comptes désactivés, expirés, ou inutilisés depuis plus de 90 jours
#   - mots de passe qui n'expirent jamais (ou non obligatoires)
#   - comptes à privilèges, comptes de service, administrateurs, invités
#
#  1) ON-PREM : Active Directory
#  2) AZURE   : Entra ID (utilisateurs, invités, rôles, applications)
#
#  - Aucun droit administrateur sur le poste (pas de module RSAT :
#    on utilise [adsisearcher], intégré à Windows)
#  - Lecture seule : le script ne désactive et ne modifie rien
#  - Le poste doit être dans le domaine, avec un compte du domaine
#  - A utiliser uniquement sur un réseau / tenant où vous êtes autorisé
#
#  Lancement :
#     Unblock-File .\Audit-Utilisateurs.ps1
#     Set-ExecutionPolicy RemoteSigned -Scope CurrentUser
#     .\Audit-Utilisateurs.ps1
# =====================================================================

$joursInactivite = 90
$limite = (Get-Date).AddDays(-$joursInactivite)
$resultats = @()


# ---------------------------------------------------------------------
#  PARTIE 1 : ON-PREM
# ---------------------------------------------------------------------
Write-Host ""
Write-Host "===== PARTIE 1 : ON-PREM =====" -ForegroundColor Yellow
Write-Host "Domaine : $env:USERDNSDOMAIN"
Write-Host "Lecture des comptes..."

$recherche = [adsisearcher]"(&(objectCategory=person)(objectClass=user))"
$recherche.PageSize = 1000          # sinon AD s'arrête à 1000 résultats

foreach ($u in $recherche.FindAll()) {

    $p   = $u.Properties
    $nom = [string]$p["samaccountname"]
    $uac = [int]$p["useraccountcontrol"][0]     # les "options" du compte
    $sid = [System.Security.Principal.SecurityIdentifier]::new($p["objectsid"][0], 0).Value

    # --- Etat du compte ---
    $desactive     = ($uac -band 2)     -ne 0   # compte désactivé
    $mdpNonRequis  = ($uac -band 32)    -ne 0   # mot de passe non obligatoire
    $mdpNExpirePas = ($uac -band 65536) -ne 0   # mot de passe qui n'expire jamais

    # Compte expiré ? (0 ou la valeur maximale = n'expire jamais)
    $expire = $false
    if ($p["accountexpires"].Count -gt 0) {
        $valeur = [int64]$p["accountexpires"][0]
        if ($valeur -ne 0 -and $valeur -ne 9223372036854775807) {
            if ([DateTime]::FromFileTime($valeur) -lt (Get-Date)) { $expire = $true }
        }
    }

    # Dernière connexion (peut avoir 14 jours de retard, c'est normal)
    $derniereConnexion = $null
    if ($p["lastlogontimestamp"].Count -gt 0) {
        $derniereConnexion = [DateTime]::FromFileTime([int64]$p["lastlogontimestamp"][0])
    }
    $inactif = (-not $derniereConnexion) -or ($derniereConnexion -lt $limite)

    # Date du dernier changement de mot de passe
    $dateMdp = $null
    if ($p["pwdlastset"].Count -gt 0 -and [int64]$p["pwdlastset"][0] -gt 0) {
        $dateMdp = [DateTime]::FromFileTime([int64]$p["pwdlastset"][0])
    }

    # --- Type de compte ---
    # adminCount = 1 : le compte est (ou a été) membre d'un groupe protégé
    # (Admins du domaine, Administrateurs de l'entreprise, Opérateurs de sauvegarde...)
    $privilegie = ($p["admincount"].Count -gt 0) -and ([int]$p["admincount"][0] -eq 1)
    $aUnSpn     = $p["serviceprincipalname"].Count -gt 0

    $type = "Utilisateur"
    if ($aUnSpn -or $nom -like "svc*") { $type = "Compte de service" }
    if ($privilegie)                   { $type = "Privilégié" }
    if ($sid -like "*-500")            { $type = "Administrateur intégré" }
    if ($sid -like "*-501")            { $type = "Invité intégré" }
    if ($sid -like "*-502")            { $type = "krbtgt (Kerberos)" }

    # --- Les risques de sécurité ---
    $risques = @()

    if ($expire)        { $risques += "Compte expiré mais toujours présent" }
    if ($mdpNonRequis)  { $risques += "Mot de passe NON obligatoire" }
    if ($mdpNExpirePas) { $risques += "Mot de passe n'expire jamais" }

    if ($inactif -and -not $desactive -and $type -ne "krbtgt (Kerberos)") {
        if ($derniereConnexion) { $risques += "Actif mais inutilisé depuis +$joursInactivite jours" }
        else                    { $risques += "Actif mais jamais utilisé" }
    }

    if ($type -eq "Invité intégré" -and -not $desactive) {
        $risques += "Compte Invité ACTIVÉ"
    }

    if ($aUnSpn -and $sid -notlike "*-502") {
        $risques += "SPN : cible du Kerberoasting (mot de passe long obligatoire)"
        if ($privilegie) { $risques += "CRITIQUE : compte de service ET privilégié" }
    }

    if ($privilegie -and $mdpNExpirePas) {
        $risques += "CRITIQUE : compte privilégié avec mot de passe éternel"
    }

    if ($type -eq "krbtgt (Kerberos)" -and $dateMdp -and $dateMdp -lt (Get-Date).AddDays(-180)) {
        $risques += "Mot de passe krbtgt jamais changé depuis +180 jours"
    }

    $resultats += [PSCustomObject]@{
        Source            = "On-Prem"
        Compte            = $nom
        Type              = $type
        Actif             = -not $desactive
        DerniereConnexion = $derniereConnexion
        Privileges        = if ($privilegie) { "Groupe protégé (adminCount=1)" } else { "" }
        Risques           = $risques -join " | "
    }
}

$onPrem = $resultats | Where-Object { $_.Source -eq "On-Prem" }
Write-Host ""
Write-Host "Comptes AD analysés           : $($onPrem.Count)"
Write-Host "Comptes privilégiés           : $(($onPrem | Where-Object { $_.Privileges }).Count)"
Write-Host "Comptes de service            : $(($onPrem | Where-Object { $_.Type -eq 'Compte de service' }).Count)"
Write-Host "Comptes avec au moins 1 risque : $(($onPrem | Where-Object { $_.Risques }).Count)" -ForegroundColor Red
$onPrem | Where-Object { $_.Risques -like "*CRITIQUE*" } | Format-Table Compte, Type, Risques -AutoSize


# ---------------------------------------------------------------------
#  PARTIE 2 : AZURE / ENTRA ID (optionnelle)
# ---------------------------------------------------------------------
Write-Host ""
Write-Host "===== PARTIE 2 : AZURE / ENTRA ID =====" -ForegroundColor Yellow

$reponse = Read-Host "Se connecter à Entra ID ? (O/N)"

if ($reponse -eq "O") {

    if (-not (Get-Module -ListAvailable -Name Microsoft.Graph.Users) -or
        -not (Get-Module -ListAvailable -Name Microsoft.Graph.Identity.DirectoryManagement)) {
        Write-Host "Modules Microsoft Graph manquants. Commandes (sans droits admin) :" -ForegroundColor Red
        Write-Host "Install-Module Microsoft.Graph.Users -Scope CurrentUser"
        Write-Host "Install-Module Microsoft.Graph.Identity.DirectoryManagement -Scope CurrentUser"
    }
    else {

        # Lecture seule
        Connect-MgGraph -Scopes "User.Read.All", "AuditLog.Read.All", "RoleManagement.Read.Directory" -NoWelcome -ErrorAction SilentlyContinue

        if (Get-MgContext) {

            # --- 2.a Qui a un rôle d'administration dans Entra ? ---
            $rolesParCompte = @{}
            $applicationsAdmin = @{}

            foreach ($role in (Get-MgDirectoryRole -All)) {
                foreach ($membre in (Get-MgDirectoryRoleMember -DirectoryRoleId $role.Id -All)) {

                    if (-not $rolesParCompte[$membre.Id]) { $rolesParCompte[$membre.Id] = @() }
                    $rolesParCompte[$membre.Id] += $role.DisplayName

                    # Ce n'est pas un humain ? (application / identité de service)
                    if ($membre.AdditionalProperties["@odata.type"] -ne "#microsoft.graph.user") {
                        $applicationsAdmin[$membre.Id] = $membre.AdditionalProperties["displayName"]
                    }
                }
            }

            # --- 2.b Les utilisateurs (dates de connexion = licence P1/P2) ---
            $proprietes = "Id,DisplayName,UserPrincipalName,AccountEnabled,UserType,PasswordPolicies,OnPremisesSyncEnabled"
            $avecConnexions = $true
            try {
                $utilisateurs = Get-MgUser -All -Property "$proprietes,SignInActivity" -ErrorAction Stop
            }
            catch {
                Write-Host "Dates de connexion indisponibles (licence Entra ID P1/P2 requise)." -ForegroundColor Red
                $utilisateurs = Get-MgUser -All -Property $proprietes
                $avecConnexions = $false
            }

            foreach ($u in $utilisateurs) {

                $roles = $rolesParCompte[$u.Id] -join ", "
                $derniereConnexion = $null
                if ($avecConnexions) { $derniereConnexion = $u.SignInActivity.LastSignInDateTime }

                $type = "Utilisateur"
                if ($u.UserType -eq "Guest") { $type = "Invité (externe)" }
                if ($roles)                  { $type = "Administrateur Entra" }

                $risques = @()

                if ($u.PasswordPolicies -like "*DisablePasswordExpiration*") {
                    $risques += "Mot de passe n'expire jamais"
                }
                if ($avecConnexions -and $u.AccountEnabled -and (-not $derniereConnexion -or $derniereConnexion -lt $limite)) {
                    $risques += "Actif mais inutilisé depuis +$joursInactivite jours"
                }
                if ($u.UserType -eq "Guest" -and $roles) {
                    $risques += "CRITIQUE : invité externe avec un rôle admin"
                }
                if ($roles -and $u.OnPremisesSyncEnabled) {
                    $risques += "CRITIQUE : admin Entra synchronisé depuis l'AD (un AD compromis = cloud compromis)"
                }

                $resultats += [PSCustomObject]@{
                    Source            = "Entra ID"
                    Compte            = $u.UserPrincipalName
                    Type              = $type
                    Actif             = $u.AccountEnabled
                    DerniereConnexion = $derniereConnexion
                    Privileges        = $roles
                    Risques           = $risques -join " | "
                }
            }

            # --- 2.c Les applications avec un rôle admin (comptes de service du cloud) ---
            foreach ($id in $applicationsAdmin.Keys) {
                $resultats += [PSCustomObject]@{
                    Source            = "Entra ID"
                    Compte            = $applicationsAdmin[$id]
                    Type              = "Application / identité de service"
                    Actif             = ""
                    DerniereConnexion = $null
                    Privileges        = $rolesParCompte[$id] -join ", "
                    Risques           = "Application avec un rôle admin : vérifier qui gère ses secrets"
                }
            }

            $entra = $resultats | Where-Object { $_.Source -eq "Entra ID" }
            Write-Host ""
            Write-Host "Comptes Entra analysés         : $($entra.Count)"
            Write-Host "Invités externes               : $(($entra | Where-Object { $_.Type -eq 'Invité (externe)' }).Count)"
            Write-Host "Comptes avec un rôle admin     : $(($entra | Where-Object { $_.Privileges }).Count)"
            Write-Host "Comptes avec au moins 1 risque : $(($entra | Where-Object { $_.Risques }).Count)" -ForegroundColor Red
            $entra | Where-Object { $_.Risques -like "*CRITIQUE*" } | Format-Table Compte, Type, Risques -AutoSize

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
$fichier = "$bureau\Audit-Utilisateurs.csv"
$resultats | Export-Csv $fichier -NoTypeInformation -Encoding UTF8 -Delimiter ";"
Write-Host ""
Write-Host "Fichier enregistré : $fichier" -ForegroundColor Green
Write-Host "ATTENTION : ce fichier liste les failles de vos comptes. Ne le partagez pas, supprimez-le après usage." -ForegroundColor Red
