# SlinkyCat v1.0
# Lares Labs - https://labs.lares.com/
# Neil Lines & Andy Gill, 2023

<#
.SYNOPSIS
    This script performs a series of AD enumeration tasks, giving output to the terminal or option to output to terminal.

.DESCRIPTION
    Slinky Cat has been developed to automate some of the methods introduced in living off the land and to supplement ScrapingKit. To help security and IT teams reduce their AD exposures and uncover quick wins and fixes designed for pen-testers and defenders alike.

.PARAMETER domain
    The domain to be run against, it will default to whatever domain lives in USERDNSDOMAIN, but can be supplied as FQDN.

.EXAMPLE
    Invoke-SlinkyCat

    SlinkyCat will open the menu system and give you the option to select ADSI or DotNet followed by a series of functions, there is also the option to run each of the individual functions by themselves.

#>



function ListFunctions {
    $ListFuncs = @"
************************ List of Functions ************************

Individual Functions Available in this script:

EnumerateAllDomainHosts
EnumerateAllDomainControllers
EnumerateAllDomainUsers
ListDomainAdmins
ListAccountsWithSPN
ListAllDomainGroups
ListPasswordNeverExpire
ListUsersNoPasswordRequired
ListUsersPasswordMustChange
ListNonDCWindows7Computers
ListNonDCWindows10Computers
ListNonDCWindows11Computers
ListAllServers
ListServer2008
ListServer2012
ListServer2016
ListServer2019
ListServer2022
ListDomainGroupsLocalAdmin
ListAllTrusts
ListExchangeServers
ListNeverLoggedInAccounts
ListCompletedDescriptionField
ListDescriptionContainsPass
ListUsersPasswordNotChanged
ListUsersLastPasswordChange
TestWinRMMachines
TestRDPMachines
FindAdminAccessComputers

Dot Net Functions:
DNet-EnumerateAllDomainUserAccounts
DNet-ListDomainUserAccountsWithCompletedADDescription
DNet-ListAccountsByDescription
DNet-ListUsersInDomainAdminsGroup
************************ SlinkyCat ************************
"@
Write-Output $ListFuncs
Write-Output "Press Enter to Continue"
Read-Host
}


function CombinedMenu {

    do {
        Clear-Host
         Write-Output "=== Menu ==="
         Write-Output "1. ADSI Enumeration"
         Write-Output "2. Dot NET System.DirectoryServices.AccountManagement Namespace Enumeration"
         Write-Output "3. List Available Individual Functions"
         Write-Output "Q. Quit"
        $choice = Read-Host "Enter your choice: "

        switch ($choice) {
            "1" {
                ADSIMenu
            }
            "2" {
                DotNetMenu
            }
            "3" {
                ListFunctions
            }
            "Q" {
                 Write-Output "Exiting..."
               }
           
            default {
                 Write-Output "Invalid choice. Please try again."
            }
        }
    } while ($choice -ne "Q")
}

function EnumerateAllDomainHosts {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$false)]
        [String]$OutputPath
    )

    $result = "Option: ADSI Enumerate all domain hosts`n"
    $computers = ([adsisearcher]'(objectCategory=computer)').FindAll()
       # Create an array to store the computer names
    $computerNames = @()
       foreach ($computer in $computers) {
        $computerName = $computer.Properties['name']
        $computerNames += $computerName
        
        $result += "$computerName`n"
    }


       # Export the computer names to the specified CSV file if OutputPath is provided
    if ($OutputPath) {
        Write-Output $result
        $result | Out-File -FilePath $OutputPath
    } else {
        Write-Host $result
    }

    Write-Host "Press Enter to Continue"
         Read-Host
       "`n"
}

function EnumerateAllDomainControllers {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$false)]
        [String]$OutputPath
    )

    $result = "Option: ADSI Enumerate all domain controllers`n"
    $computers = ([adsisearcher]'(&(objectCategory=computer)(primaryGroupID=516))').FindAll()
    foreach ($computer in $computers) {
        $computerName = $computer.Properties['name'][0]
        $result += "$computerName`n"
    }
       # Output the result to the console
    if ($OutputPath) {
        Write-Output $result
        $result | Out-File -FilePath $OutputPath
    } else {
        Write-Host $result
    }
        Write-Host "Press Enter to Continue"
         Read-Host
       "`n"
}


function EnumerateAllDomainUsers {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$false)]
        [String]$OutputPath
    )

    $result = "Option: ADSI Enumerate all domain users`n"
    $users = ([adsisearcher]'(objectCategory=user)').FindAll()
    foreach ($user in $users) {
        $userName = $user.Properties['sAMAccountName']
        $result += "$userName`n"
    }

    if ($OutputPath) {
        Write-Output $result
        $result | Out-File -FilePath $OutputPath
    } else {
        Write-Host $result
    }
       Write-Host "Press Enter to Continue"
         Read-Host
    "`n"

}

function ListDomainAdmins {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$false)]
        [String]$OutputPath
    )
    $result = "Option: List all users in the domain admins group`n"

    $domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
    $domainDN = $domain.GetDirectoryEntry().distinguishedName

    $users = ([adsisearcher]"(memberOf=cn=Domain Admins,CN=Users,$domainDN)").FindAll()
    foreach ($user in $users) {
        $userName = $user.Properties['sAMAccountName']
        $result += "$userName`n"
    }


    if ($OutputPath) {
        Write-Output $result
        $result | Out-File -FilePath $OutputPath
    } else {
        Write-Host $result
    }

    Write-Host "Press Enter to Continue"
         Read-Host 
}


function ListAccountsWithSPN {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$false)]
        [String]$OutputPath
    )

    $warningMessage = @"
************************ WARNING ************************
This *might* trigger alerts for Kerberoasting due to searching for wildcard SPN searching.

Are you sure you want to continue? (Y/N)
"@
    $confirm = Read-Host -Prompt $warningMessage
    if ($confirm -ne 'Y') {
         Write-Output "[!] Operation Cancelled."
        return
    }
    $result = "Option: ADSI List all accounts with an SPN`n"
    $users = ([adsisearcher]'(&(objectCategory=user)(servicePrincipalName=*))').FindAll()
    foreach ($user in $users) {
        $userName = $user.Properties['sAMAccountName']
        $result += "$userName`n"
    }

    if ($OutputPath) {
        Write-Output $result
        $result | Out-File -FilePath $OutputPath
    } else {
        Write-Host $result
    }

    Write-Host "Press Enter to Continue"
     Read-Host
     "`n"

}

function ListAllDomainGroups {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$false)]
        [String]$OutputPath
    )
    $result = "Option: ADSI List all domain groups`n"
    $users = ([adsisearcher]'(&(objectCategory=group))').FindAll()
    foreach ($user in $users) {
        $userName = $user.Properties['name']
        $result += "$userName`n"
    }

    if ($OutputPath) {
        Write-Output $result
        $result | Out-File -FilePath $OutputPath
    } else {
        Write-Host $result
    }

     Write-Host "Press Enter to Continue"
     Read-Host
     "`n"
   }

function ListPasswordNeverExpire {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$false)]
        [String]$OutputPath
    )

    $result = "Option: ADSI List all passwords set to never expire`n"
    $users = ([adsisearcher]'(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=66048))').FindAll()
    foreach ($user in $users) {
        $userName = $user.Properties['sAMAccountName']
        $result += "$userName`n"
    }

    if ($OutputPath) {
        Write-Output $result
        $result | Out-File -FilePath $OutputPath
    } else {
        Write-Host $result
    }

     Write-Host "Press Enter to Continue"
     Read-Host
     "`n"
   }

function ListUsersNoPasswordRequired {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$false)]
        [String]$OutputPath
    )

    $result = "Option: ADSI List all users which do not require a password`n"
    $users = ([adsisearcher]'(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=544))').FindAll()
    foreach ($user in $users) {
        $userName = $user.Properties['sAMAccountName']
        $result += "$userName`n"
    }

    if ($OutputPath) {
        Write-Output $result
        $result | Out-File -FilePath $OutputPath
    } else {
        Write-Host $result
    }

     Write-Host "Press Enter to Continue"
     Read-Host
     "`n"
   }

function ListUsersPasswordMustChange {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$false)]
        [String]$OutputPath
    )
    $result = "Option: ADSI List all users with password must change at next logon`n"
    $users = ([adsisearcher]'(&(objectCategory=person)(objectClass=user)(pwdLastSet=0))').FindAll()
    foreach ($user in $users) {
        $userName = $user.Properties['sAMAccountName']
 
         $result += "$userName`n"
    }

    if ($OutputPath) {
        Write-Output $result
        $result | Out-File -FilePath $OutputPath
    } else {
        Write-Host $result
    }

     Write-Host "Press Enter to Continue"
     Read-Host
     "`n"
   }

function ListNonDCWindows7Computers {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$false)]
        [String]$OutputPath
    )
    $result = "Option: ADSI List all computers that are not Domain Controllers and are Windows 7`n"

       $users = ([adsisearcher]'(&(objectCategory=computer)(operatingSystem=Windows 7*)(!(userAccountControl:1.2.840.113556.1.4.803:=8192)))').FindAll()
    foreach ($user in $users) {
        $userName = $user.Properties['name']
 
         $result += "$userName`n"
    }

    if ($OutputPath) {
        Write-Output $result
        $result | Out-File -FilePath $OutputPath
    } else {
        Write-Host $result
    }

     Write-Host "Press Enter to Continue"
     Read-Host
     "`n"
   }

function ListNonDCWindows10Computers {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$false)]
        [String]$OutputPath
    )
    $result = "Option: ADSI List all computers that are not Domain Controllers and are Windows 10`n"

       $users = ([adsisearcher]'(&(objectCategory=computer)(operatingSystem=Windows 10*)(!(userAccountControl:1.2.840.113556.1.4.803:=8192)))').FindAll()
    foreach ($user in $users) {
        $userName = $user.Properties['name']
 
         $result += "$userName`n"
    }

    if ($OutputPath) {
        Write-Output $result
        $result | Out-File -FilePath $OutputPath
    } else {
        Write-Host $result
    }

     Write-Host "Press Enter to Continue"
     Read-Host
     "`n"
   }

function ListNonDCWindows11Computers {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$false)]
        [String]$OutputPath
    )
    $result = "Option: ADSI List all computers that are not Domain Controllers and are Windows 11`n"

       $users = ([adsisearcher]'(&(objectCategory=computer)(operatingSystem=Windows 11*)(!(userAccountControl:1.2.840.113556.1.4.803:=8192)))').FindAll()
    foreach ($user in $users) {
        $userName = $user.Properties['name']
 
         $result += "$userName`n"
    }

    if ($OutputPath) {
        Write-Output $result
        $result | Out-File -FilePath $OutputPath
    } else {
        Write-Host $result
    }

     Write-Host "Press Enter to Continue"
     Read-Host
     "`n"
   }

function ListAllServers {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$false)]
        [String]$OutputPath
    )
    $result = "Option: ADSI List all servers`n"

       $users = ([adsisearcher]'(&(objectCategory=computer)(operatingSystem=*server*))').FindAll()
    foreach ($user in $users) {
        $userName = $user.Properties['name']
 
         $result += "$userName`n"
    }

    if ($OutputPath) {
        Write-Output $result
        $result | Out-File -FilePath $OutputPath
    } else {
        Write-Host $result
    }

     Write-Host "Press Enter to Continue"
     Read-Host
     "`n"
   }

function ListServer2008 {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$false)]
        [String]$OutputPath
    )
    $result = "Option: ADSI List all Server 2008`n"

       $users = ([adsisearcher]'(&(objectCategory=computer)(operatingSystem=Windows Server 2008*))').FindAll()
    foreach ($user in $users) {
        $userName = $user.Properties['name']
 
         $result += "$userName`n"
    }

    if ($OutputPath) {
        Write-Output $result
        $result | Out-File -FilePath $OutputPath
    } else {
        Write-Host $result
    }

     Write-Host "Press Enter to Continue"
     Read-Host
     "`n"
   }

function ListServer2012 {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$false)]
        [String]$OutputPath
    )

    $result = "Option: ADSI List all Server 2012`n"

       $users = ([adsisearcher]'(&(objectCategory=computer)(operatingSystem=Windows Server 2012*))').FindAll()
    foreach ($user in $users) {
        $userName = $user.Properties['name']
 
         $result += "$userName`n"
    }

    if ($OutputPath) {
        Write-Output $result
        $result | Out-File -FilePath $OutputPath
    } else {
        Write-Host $result
    }

     Write-Host "Press Enter to Continue"
     Read-Host
     "`n"
   }

function ListServer2016 {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$false)]
        [String]$OutputPath
    )
    $result = "Option: ADSI List all Server 2016`n"

       $users = ([adsisearcher]'(&(objectCategory=computer)(operatingSystem=Windows Server 2016*))').FindAll()
    foreach ($user in $users) {
        $userName = $user.Properties['name']
 
         $result += "$userName`n"
    }

    if ($OutputPath) {
        Write-Output $result
        $result | Out-File -FilePath $OutputPath
    } else {
        Write-Host $result
    }

     Write-Host "Press Enter to Continue"
     Read-Host
     "`n"
   }

function ListServer2019 {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$false)]
        [String]$OutputPath
    )
    $result = "Option: ADSI List all Server 2019`n"

       $users = ([adsisearcher]'(&(objectCategory=computer)(operatingSystem=Windows Server 2019*))').FindAll()
    foreach ($user in $users) {
        $userName = $user.Properties['name']
 
         $result += "$userName`n"
    }

    if ($OutputPath) {
        Write-Output $result
        $result | Out-File -FilePath $OutputPath
    } else {
        Write-Host $result
    }

     Write-Host "Press Enter to Continue"
     Read-Host
     "`n"
   }

function ListServer2022 {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$false)]
        [String]$OutputPath
    )
    $result = "Option: ADSI List all Server 2022`n"

       $users = ([adsisearcher]'(&(objectCategory=computer)(operatingSystem=Windows Server 2022*))').FindAll()
    foreach ($user in $users) {
        $userName = $user.Properties['name']
 
         $result += "$userName`n"
    }

    if ($OutputPath) {
        Write-Output $result
        $result | Out-File -FilePath $OutputPath
    } else {
        Write-Host $result
    }

     Write-Host "Press Enter to Continue"
     Read-Host
     "`n"
   }

function ListDomainGroupsLocalAdmin {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$false)]
        [String]$OutputPath
    )
    $result = "Option: ADSI List domain groups which are a member of the local admin group`n"

   
    $domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
    $domainDN = $domain.GetDirectoryEntry().distinguishedName

    $users = ([adsisearcher]"(memberOf=CN=Administrators,CN=Builtin,$domainDN)").FindAll()
    foreach ($user in $users) {
        $groupName = $user.Properties['name']
        $result += "$groupName`n"
    }


    if ($OutputPath) {
        Write-Output $result
        $result | Out-File -FilePath $OutputPath
    } else {
        Write-Host $result
    }

     Write-Host "Press Enter to Continue"
     Read-Host
     "`n"
   }

function ListAllTrusts {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$false)]
        [String]$OutputPath
    )
    $result = "Option: ADSI List all trusts established with a domain`n"

       $users = ([adsisearcher]'(objectClass=trustedDomain)').FindAll()
    foreach ($user in $users) {
        $userName = $user.Properties['name']
 
         $result += "$userName`n"
    }

 if ($OutputPath) {
        Write-Output $result
        $result | Out-File -FilePath $OutputPath
    } else {
        Write-Host $result
    }

     Write-Host "Press Enter to Continue"
     Read-Host
     "`n"
   }

function ListExchangeServers {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$false)]
        [String]$OutputPath
    )
    $result = "Option: ADSI List all Exchange servers`n"

       $users = ([adsisearcher]'(objectCategory=msExchExchangeServer)').FindAll()
    foreach ($user in $users) {
        $userName = $user.Properties['name']
 
         $result += "$userName`n"
    }

    if ($OutputPath) {
        Write-Output $result
        $result | Out-File -FilePath $OutputPath
    } else {
        Write-Host $result
    }

     Write-Host "Press Enter to Continue"
     Read-Host
     "`n"
   }

function ListNeverLoggedInAccounts {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$false)]
        [String]$OutputPath
    )
    $result = "Option: ADSI List all accounts that have never logged in`n"

       $users = ([adsisearcher]'(&(objectCategory=person)(objectClass=user) (lastlogon=0))').FindAll()
    foreach ($user in $users) {
        $userName = $user.Properties['sAMAccountName']
 
         $result += "$userName`n"
    }

    if ($OutputPath) {
        Write-Output $result
        $result | Out-File -FilePath $OutputPath
    } else {
        Write-Host $result
    }

     Write-Host "Press Enter to Continue"
     Read-Host
     "`n"
   }

function ListCompletedDescriptionField {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$false)]
        [String]$OutputPath
    )
    $result = "Option: ADSI List all domain user accounts which have a completed AD description field`n"
    $adsisearcher = New-Object System.DirectoryServices.DirectorySearcher
    $adsisearcher.Filter = '(&(objectCategory=person)(objectClass=user)(description=*))'
    $users = $adsisearcher.FindAll()
    foreach ($user in $users) {
        $username = $user.Properties['sAMAccountName']
        $description = $user.Properties['description']
        if ($description -ne $null) {
             Write-Output "Username: $username"
             Write-Output "Description: $description"
            Write-Host
            $result += "Username: $username`n"
            $result += "Description: $description`n`n"
        }
    }

    if ($OutputPath) {
        Write-Output $result
        $result | Out-File -FilePath $OutputPath
    } else {
        Write-Host $result
    }
        Write-Host "Press Enter to Continue"
     Read-Host
     "`n"
   }

function ListDescriptionContainsPass {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$false)]
        [String]$OutputPath
    )

    $result = "Option: ADSI List all accounts that reference 'pass' in their AD description field`n"

       $adsisearcher = New-Object System.DirectoryServices.DirectorySearcher
    $adsisearcher.Filter = '(&(objectCategory=person)(objectClass=user)(description=*passw*))'
    $users = $adsisearcher.FindAll()
    foreach ($user in $users) {
        $username = $user.Properties['sAMAccountName']
        $description = $user.Properties['description']
        if ($description -ne $null) {
            $result += "Username: $username`n"
            $result += "Description: $description`n`n"
        }
    }

    if ($OutputPath) {
        Write-Output $result
        $result | Out-File -FilePath $OutputPath
    } else {
        Write-Host $result
    }

     Write-Host "Press Enter to Continue"
     Read-Host
     "`n"
   }

function ListUsersPasswordNotChanged {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$false)]
        [String]$OutputPath
    )
    $result = "Option: ADSI List all users who have not changed their password in over 1 year`n"

       $users = ([adsisearcher]"(&(objectcategory=user)(pwdLastSet<=$((Get-Date).AddDays(-365).ToFileTime())))").findall()
    foreach ($user in $users) {
        $userName = $user.Properties['sAMAccountName']
 
         $result += "$userName`n"
    }

    if ($OutputPath) {
        Write-Output $result
        $result | Out-File -FilePath $OutputPath
    } else {
        Write-Host $result
    }

     Write-Host "Press Enter to Continue"
     Read-Host
     "`n"
   }
function ListUsersLastPasswordChange {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$false)]
        [String]$OutputPath
    )
    $result = "Option: ADSI List all users' last password change date and time`n"

   
    $as = [adsisearcher]"(&(objectCategory=user)(objectClass=user))"
    $as.PropertiesToLoad.Add('sAMAccountName')
    $as.PropertiesToLoad.Add('pwdLastSet')

    $users = $as.FindAll() | ForEach-Object {
        $props = @{
            'name'       = $_.Properties.Item('sAMAccountName') -join ''
            'pwdLastSet' = [datetime]::FromFileTime($_.Properties.Item('pwdLastSet') -join '')
        }
        New-Object psObject -Property $props
    }

    $users | ForEach-Object {
        $passwordInfo = "Username: $($_.name), Last Password Set: $($_.pwdLastSet)"
        $result += "$passwordInfo`n"
    }


    if ($OutputPath) {
        Write-Output $result
        $result | Out-File -FilePath $OutputPath
    } else {
        Write-Host $result
    }

     Write-Host "Press Enter to Continue"
     Read-Host
     "`n"
   }

function TestWinRMMachines {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$false)]
        [String]$OutputPath
    )
    $warningMessage = @"
************************ WARNING ************************
This operation will be noisy and could
potentially compromise operational security (OPSEC).

This is also slow to scan big networks...

This will scan the whole network for port 5985

Are you sure you want to continue? (Y/N)
"@
    $confirm = Read-Host -Prompt $warningMessage
    if ($confirm -ne 'Y') {
         Write-Output "[!] Operation Cancelled."
        return
    }

  $result = "Option: Test computers for port 5985`n"

   
    $computers = ([adsisearcher]"(&(objectCategory=computer)(objectClass=computer))").FindAll()
    $computers | ForEach-Object {
        $computerName = $_.Properties.name
        $testResult = Test-NetConnection -ComputerName $computerName -Port 5985 -ErrorAction SilentlyContinue
        if ($testResult.TcpTestSucceeded -eq $true) {
            $result = @{
                'ComputerName' = $computerName
            }
            $result
        }
    } | Select-Object ComputerName


    if ($OutputPath) {
        Write-Output $result
        $result | Out-File -FilePath $OutputPath
    } else {
        Write-Host $result
    }
   }

function TestRDPMachines {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$false)]
        [String]$OutputPath
    )
    $warningMessage = @"
************************ WARNING ************************
This operation will be noisy and could
potentially compromise operational security (OPSEC).

This will scan the whole network for port 3389

Are you sure you want to continue? (Y/N)
"@
    $confirm = Read-Host -Prompt $warningMessage
    if ($confirm -ne 'Y') {
         Write-Output "[!] Operation Cancelled."
        return
    }

 Write-Output $result = "Option: Test computers for port 3389`n"

   
    $computers = ([adsisearcher]"(&(objectCategory=computer)(objectClass=computer))").FindAll()
    $computers | ForEach-Object {
        $computerName = $_.Properties.name
        $testResult = Test-NetConnection -ComputerName $computerName -Port 3389 -ErrorAction SilentlyContinue
        if ($testResult.TcpTestSucceeded -eq $true) {
            $result = @{
                'ComputerName' = $computerName
            }
            $result
        }
    } | Select-Object ComputerName


    if ($OutputPath) {
        Write-Output $result
        $result | Out-File -FilePath $OutputPath
    } else {
        Write-Host $result
    }

     Write-Host "Press Enter to Continue"
     Read-Host
     "`n"
   }

function FindAdminAccessComputers {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$false)]
        [String]$OutputPath
    )
    $currentUser = [System.Environment]::UserName
    $warningMessage = @"
************************ WARNING ************************
This operation will be noisy and could
potentially compromise operational security (OPSEC).

You are running as $currentUser

This will scan the whole network for where your current user has local admin access.

Are you sure you want to continue? (Y/N)
"@
    $confirm = Read-Host -Prompt $warningMessage
    if ($confirm -ne 'Y') {
         Write-Output "[!] Operation Cancelled."
        return
    }

    $result = "`nOption: Find computers with admin access"

   
    $searcher = [adsisearcher]"(&(objectCategory=computer)(lastlogon>=$((Get-Date).AddDays(-31).ToUniversalTime().ToFileTime())))"
    $computer_list = $searcher.FindAll() | ForEach-Object { $_.Properties.name }
       foreach ($computer in $computer_list) {
        try {
            $path = "\\" + $computer + "\C$\"
            if (Test-Path $path -ErrorAction SilentlyContinue) {
                $string = "`n[*] User " + $currentUser + " has local Admin access(OR C$ is shared to everyone) to: " + $computer
                Write-Host $string
                $result += "$string`n"
            }
        } catch {
            # Ignore any errors and continue to the next computer
        }
    }
      
    if ($OutputPath) {
        Write-Output "`n"
        $result | Out-File -FilePath $OutputPath
    } else {
        Write-Output "`n"
    }
        Write-Output "`nPress Enter to continue"
        Read-Host
}
function Invoke-SlinkyCat {

    param(
        [string]$domain = $env:USERDNSDOMAIN
    )
#### DotNet Functions
function DNet-EnumerateAllDomainUserAccounts {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$false)]
        [String]$OutputPath
    )

    $result = "Option: Dot NET Enumerate all domain user accounts`n"

    Add-Type -AssemblyName System.DirectoryServices.AccountManagement

    # Get the domain name from the environment variables
    $domainName = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().Name

    # Create a context to connect to the domain
    $context = New-Object System.DirectoryServices.AccountManagement.PrincipalContext([System.DirectoryServices.AccountManagement.ContextType]::Domain, $domainName)

    # Create a user principal object
    $userPrincipal = New-Object System.DirectoryServices.AccountManagement.UserPrincipal($context)

    # Create a principal searcher for searching user objects
    $searcher = New-Object System.DirectoryServices.AccountManagement.PrincipalSearcher($userPrincipal)

    # Perform the search and retrieve the results
    $users = $searcher.FindAll()

    # Check if any user accounts were found
    if ($users.GetEnumerator().MoveNext()) {
        # Iterate through the user objects and display the account names
        foreach ($user in $users) {
            $accountName = $user.SamAccountName
            Write-Host $accountName
            $result += "$accountName`n"
        }

        # Output the result
        if ($OutputPath) {
            Write-Output $result
            $result | Out-File -FilePath $OutputPath
        } else {
            Write-Output $result
        }
    } else {
        Write-Output "No user accounts found."
    }

    Write-Host "Press Enter to Continue"
         Read-Host
    "`n"
}


function DNet-ListDomainUserAccountsWithCompletedADDescription {

    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$false)]
        [String]$OutputPath
    )
    $result = "`nOption: Dot NET List all domain user accounts which have a completed AD description field`n"

   
    Add-Type -AssemblyName System.DirectoryServices.AccountManagement

    # Get the domain name from the environment variables
    $domainName = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().Name

    # Create a context to connect to the domain
    $context = New-Object System.DirectoryServices.AccountManagement.PrincipalContext([System.DirectoryServices.AccountManagement.ContextType]::Domain, $domainName)

    # Create a user principal object
    $userPrincipal = New-Object System.DirectoryServices.AccountManagement.UserPrincipal($context)

    # Set the filter to search for user accounts with non-empty description
    $userPrincipal.Description = "*"

    # Create a principal searcher for searching user objects
    $searcher = New-Object System.DirectoryServices.AccountManagement.PrincipalSearcher($userPrincipal)

    # Perform the search and retrieve the results
    $users = $searcher.FindAll()

    # Iterate through the user objects and display the account names and descriptions
    foreach ($user in $users) {
        $accountName = $user.SamAccountName
        $description = $user.Description
         Write-Output "Account Name: $accountName"
         Write-Output "Description: $description"
         Write-Output "----------------------"
        $result += "Account Name: $accountName`nDescription: $description`n----------------------`n"
    }

    if ($OutputPath) {
        Write-Output $result
        $result | Out-File -FilePath $OutputPath
    } else {
        Write-Host $result
    }

     Write-Host "Press Enter to Continue"
     Read-Host
     "`n"
   }

function DNet-ListAccountsByDescription {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$false)]
        [String]$OutputPath
    )
    Add-Type -AssemblyName System.DirectoryServices.AccountManagement

    $result = "`nOption: Dot NET List all accounts that reference pass in their AD description field`n"

    # Get the domain name from the environment variables
    $domainName = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().Name

    # Create a context to connect to the domain
    $context = New-Object System.DirectoryServices.AccountManagement.PrincipalContext([System.DirectoryServices.AccountManagement.ContextType]::Domain, $domainName)

    # Create a user principal object
    $userPrincipal = New-Object System.DirectoryServices.AccountManagement.UserPrincipal($context)

    # Perform the search and retrieve the results
    $searcher = New-Object System.DirectoryServices.AccountManagement.PrincipalSearcher($userPrincipal)
    $users = $searcher.FindAll() | Where-Object { $_.Description -like "*passw*" -or $_.Description -like "*Passw*" }

    # Iterate through the user objects and display the account names and descriptions
    foreach ($user in $users) {
        $accountName = $user.SamAccountName
        $description = $user.Description
         Write-Output "Account Name: $accountName"
         Write-Output "Description: $description"
         Write-Output "----------------------"
        $result += "Account Name: $accountName`nDescription: $description`n----------------------`n"
    }

   
    if ($OutputPath) {
        Write-Output $result
        $result | Out-File -FilePath $OutputPath
    } else {
        Write-Host $result
    }

     Write-Host "Press Enter to Continue"
     Read-Host
     "`n"
   }

function DNet-ListUsersInDomainAdminsGroup {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$false)]
        [String]$OutputPath
    )
    Add-Type -AssemblyName System.DirectoryServices.AccountManagement

    $result = "Option: Dot NET List all users in the domain admins group"

   
    # Get the domain name from the environment variables
    $domainName = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().Name

    # Create a context to connect to the domain
    $context = New-Object System.DirectoryServices.AccountManagement.PrincipalContext([System.DirectoryServices.AccountManagement.ContextType]::Domain, $domainName)

    # Get the domain admin group
    $group = [System.DirectoryServices.AccountManagement.GroupPrincipal]::FindByIdentity($context, "Domain Admins")

    # Check if the group exists
    if ($group -ne $null) {
        # Retrieve the members of the group
        $members = $group.GetMembers()

        # Iterate through the group members and display their names
        foreach ($member in $members) {
            $memberName = $member.SamAccountName
             Write-Output "Member: $memberName"
            $result += "Member: $memberName`n"
        }
    }
    else {
         Write-Output "Group 'Domain Admins' not found"
        $result += "Group 'Domain Admins' not found`n"
    }

   
    if ($OutputPath) {
        Write-Output $result
        $result | Out-File -FilePath $OutputPath
    } else {
        Write-Host $result
    }

     Write-Host "Press Enter to Continue"
     Read-Host
     "`n"
}

################################################################################################
# Run All ADSI Options within Menu
################################################################################################

function RunAllFunctions-ADSI {
    $warningMessage = @"
************************ WARNING ************************
This will run all of the functions available then write a file to disk and may compromise operational security, all other options print out to terminal.

Functions to be run:

EnumerateAllDomainHosts
EnumerateAllDomainControllers
EnumerateAllDomainUsers
ListDomainAdmins
ListAccountsWithSPN
ListAllDomainGroups
ListPasswordNeverExpire
ListUsersNoPasswordRequired
ListUsersPasswordMustChange
ListNonDCWindows7Computers
ListNonDCWindows10Computers
ListNonDCWindows11Computers
ListAllServers
ListServer2008
ListServer2012
ListServer2016
ListServer2019
ListServer2022
ListDomainGroupsLocalAdmin
ListAllTrusts
ListExchangeServers
ListNeverLoggedInAccounts
ListCompletedDescriptionField
ListDescriptionContainsPass
ListUsersPasswordNotChanged
ListUsersLastPasswordChange
TestWinRMMachines
TestRDPMachines
FindAdminAccessComputers

[!] THIS WILL ALSO CREATE AN OUTPUT FOLDER ON DISK [!]

This will run each function and you will need to hit return till it itterates through the functions.

Are you sure you want to continue? (Y/N)
"@
    $confirm = Read-Host -Prompt $warningMessage
    if ($confirm -ne 'Y') {
         Write-Output "[!] Operation Cancelled."
        return
    }


    # Run each individual function and append the results to the recordedResults variable
    $Functions =  {
        mkdir output
        EnumerateAllDomainHosts -OutputPath "output/AllDomainHosts.txt"
        EnumerateAllDomainControllers -OutputPath "output/AllDomainControllers.txt"
        EnumerateAllDomainUsers -OutputPath "output/AllDomainUsers.txt"
        ListDomainAdmins -OutputPath "output/DomainAdmins.txt"
        ListAccountsWithSPN -OutputPath "output/AccountsWithSPN.txt"
        ListAllDomainGroups -OutputPath "output/AllDomainGroups.txt"
        ListPasswordNeverExpire -OutputPath "output/PasswordNeverExpire.txt"
        ListUsersNoPasswordRequired -OutputPath "output/UsersNoPasswordRequired.txt"
        ListUsersPasswordMustChange -OutputPath "output/UsersPasswordMustChange.txt"
        ListNonDCWindows7Computers -OutputPath "output/NonDCWindows7Computers.txt"
        ListNonDCWindows10Computers -OutputPath "output/NonDCWindows10Computers.txt"
        ListNonDCWindows11Computers -OutputPath "output/NonDCWindows11Computers.txt"
        ListAllServers -OutputPath "output/AllServers.txt"
        ListServer2008 -OutputPath "output/AllServers2k8.txt"
        ListServer2012 -OutputPath "output/AllServers2k12.txt"
        ListServer2016 -OutputPath "output/AllServers2k16.txt"
        ListServer2019 -OutputPath "output/AllServers2k19.txt"
        ListServer2022 -OutputPath "output/AllServers2k22.txt"
        ListDomainGroupsLocalAdmin -OutputPath "output/DomainGroupsLocalAdmin.txt"
        ListAllTrusts -OutputPath "output/AllTrusts.txt"
        ListExchangeServers -OutputPath "output/ExchangeServers.txt"
        ListNeverLoggedInAccounts -OutputPath "output/NeverLoggedInAccounts.txt"
        ListCompletedDescriptionField -OutputPath "output/CompletedDescriptionField.txt"
        ListDescriptionContainsPass -OutputPath "output/DescriptionContainsPass.txt"
        ListUsersPasswordNotChanged -OutputPath "output/UsersPasswordNotChanged.txt"
        ListUsersLastPasswordChange -OutputPath "output/UsersLastPasswordChange.txt"
        TestWinRMMachines -OutputPath "output/WinRMMachines.txt"
        TestRDPMachines -OutputPath "output/RDPMachines.txt"
        FindAdminAccessComputers -OutputPath "output/AdminAccessComputers.txt"
    }

    $results = foreach ($function in $Functions) {
        & $function.Invoke()
    }

    $results

    Write-Output "All functions executed successfully!"
    Read-Host

}

function RunAllFunctions-DNet {
    $warningMessage = @"
************************ WARNING ************************
This will run all of the functions available then write a file to disk and may compromise operational security, all other options print out to terminal.

Functions to be run:

DNet-EnumerateAllDomainUserAccounts
DNet-ListDomainUserAccountsWithCompletedADDescription
DNet-ListAccountsByDescription
DNet-ListUsersInDomainAdminsGroup

[!] THIS WILL ALSO CREATE AN OUTPUT FOLDER ON DISK [!]

Are you sure you want to continue? (Y/N)
"@
    $confirm = Read-Host -Prompt $warningMessage
    if ($confirm -ne 'Y') {
         Write-Output "[!] Operation Cancelled."
        return
    }

    # Run each individual function and append the results to the recordedResults variable
    $DNETFunctions =  {
        mkdir output
        DNet-EnumerateAllDomainUserAccounts -OutputPath "output/AllDomainUserAccounts.txt"
        DNet-ListDomainUserAccountsWithCompletedADDescription -OutputPath "output/DomainUserAccountsWithCompletedADDescription.txt"
        DNet-ListAccountsByDescription -OutputPath "output/DNETAccountsByDescription.txt"
        DNet-ListUsersInDomainAdminsGroup -OutputPath "output/UsersInDomainAdminsGroup.txt"

    }

    $results = foreach ($function in $DNETFunctions) {
        & $function.Invoke()
    }

    Write-Host $results

     Write-Output "All functions executed successfully!"
     Write-Host "Press Enter to Continue"
     Read-Host

}

################################################################################################
# ADSI Menu Options
################################################################################################
function ADSIMenu {
    Write-Output "ADSI Options Menu Please select an option:"
    Write-Output "1. Enumerate All Domain Hosts"
    Write-Output "2. Enumerate All Domain Controllers"
    Write-Output "3. Enumerate All Domain Users"
    Write-Output "4. List All Users in the Domain admins group"
    Write-Output "5. List All accounts with an SPN"
    Write-Output "6. List All Domain groups"
    Write-Output "7. List All password set to never expire"
    Write-Output "8. List All Users which do not require a password"
    Write-Output "9. List All Users with password must change at next logon"
    Write-Output "10. List All Computers that are not Domain Controllers and are Windows 7"
    Write-Output "11. List All Computers that are not Domain Controllers and are Windows 10"
    Write-Output "12. List All Computers that are not Domain Controllers and are Windows 11"
    Write-Output "13. List All Servers"
    Write-Output "14. List All Server 2008"
    Write-Output "15. List All Server 2012"
    Write-Output "16. List All Server 2016"
    Write-Output "17. List All Server 2019"
    Write-Output "18. List All Server 2022"
    Write-Output "19. List Domain Groups which are a Member of the local admin group"
    Write-Output "20. List All Trusts Established with a Domain"
    Write-Output "21. List All Exchange Servers"
    Write-Output "22. List All Accounts that have never logged in"
    Write-Output "23. List All Domain User Accounts which have a completed AD description field"
    Write-Output "24. List All accounts that reference 'pass' in their AD description field"
    Write-Output "25. List All Users who have not changed their password in over 1 year"
    Write-Output "26. List All Users' last password change date and time"
    Write-Output "27. List All Systems with WinRM Open (Not OPSEC SAFE!)"
    Write-Output "28. List All Systems with RDP Open (Not OPSEC SAFE!)"
    Write-Output "29. Find All Machines where the current user has local admin access (Not OPSEC Safe, will list All Computers then attempt to mount C$)"
    Write-Output "A. Run All Functions and Export to an Output Folder Full of txt Files"
    Write-Output "Q. Quit"

    $option = Read-Host "Enter your choice"

    switch ($option) {
        "1" {
            EnumerateAllDomainHosts
        }
        "2" {
            EnumerateAllDomainControllers
        }
        "3" {
            EnumerateAllDomainUsers
        }
        "4" {
            ListDomainAdmins
        }
        "5" {
            ListAccountsSPN
        }
        "6" {
            ListDomainGroups
        }
        "7" {
            ListPasswordNeverExpire
        }
        "8" {
            ListUsersNoPassword
        }
        "9" {
            ListUsersPasswordMustChange
        }
        "10" {
            ListNonDCWindows7Computers
        }
        "11" {
            ListNonDCWindows10Computers
        }
        "12" {
            ListNonDCWindows11Computers
        }
        "13" {
            ListAllServers
        }
        "14" {
            ListServer2008
        }
        "15" {
            ListServer2012
        }
        "16" {
            ListServer2016
        }
        "17" {
            ListServer2019
        }
        "18" {
            ListServer2022
        }
        "19" {
            ListDomainGroupsLocalAdmins
        }
        "20" {
            ListAllTrusts
        }
        "21" {
            ListExchangeServers
        }
        "22" {
            ListNeverLoggedInAccounts
        }
        "23" {
            ListCompletedDescriptionField
        }
        "24" {
            ListDescriptionContainsPass
        }
        "25" {
            ListUsersPasswordNotChanged
        }
        "26" {
            ListUsersLastPasswordChange
        }
        "27" {
            TestWinRMMachines
        }
        "28" {
            TestRDPMachines
        }
        "29" {
            FindAdminAccessComputers
        }
        "A" {
            RunAllFunctions-ADSI
        }
        "Q" {
             Write-Output "[!] Exiting!"
        }
        default {
             Write-Output "[*] Invalid choice. Please try again."
            ADSIMenu
        }
    }
}

function DotNetMenu {

    do {
        Clear-Host
         Write-Output "=== Dot Net Options Menu ==="
         Write-Output "1. Enumerate All Domain User Accounts"
         Write-Output "2. List Domain user accounts with completed AD description"
         Write-Output "3. List Accounts by Description"
         Write-Output "4. List Users in the Domain Admins group"
         Write-Output "A. Run All Functions and Export to an output folder full of txt files"
         Write-Output "Q. Quit"
        $choice = Read-Host "Enter your choice"

        switch ($choice) {
            "1" {
                DNet-EnumerateAllDomainUserAccounts
            }
            "2" {
                DNet-ListDomainUserAccountsWithCompletedADDescription
            }
            "3" {
                DNet-ListAccountsByDescription
            }
            "4" {
                DNet-ListUsersInDomainAdminsGroup
            }
            "A"{
                RunAllFunctions-DNet
            }
            "Q" {
                 Write-Output "Exiting..."
               }
            default {
                 Write-Output "Invalid choice. Please try again."
            }
        }
    } while ($choice -ne "Q")
    Clear-Host
    # Display recorded results
    Write-Output "Recorded Results: `n"
    Write-Output $result
   }
CombinedMenu
}

# Run the main function so we get the menu!
# Invoke-SlinkyCat