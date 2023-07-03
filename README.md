# SlinkyCat
## v1.0 Release
Brought to you by [Neil Lines](https://twitter.com/myexploit2600) & [Andy Gill](https://twitter.com/ZephrFish) at [Lares Labs](https://labs.lares.com).
Funny name, right? We thought so, too; Neil's cat is called slinky, and we love to have fun here!

## What It Is
Slinky Cat has been developed to automate some of the methods introduced in living off the land and to supplement ScrapingKit. To help security and IT teams reduce their AD exposures and uncover quick wins and fixes designed for pen-testers and defenders alike.

Slinky Cat attempts to give users an easy-to-navigate menu offering predefined Active Directory Service Interfaces (ADSI) and .NET System.DirectoryServices.AccountManagement namespace queries which can be used to enumerate a Windows domain.
## How to Setup/Use
Simply import the module then execute it:
```
ipmo .\SlinkyCat.ps1
Invoke-SlinkyCat
```

## Notes & Known Errors
Each function has the ability to be run individually and also has an added output option, therefore if you want to run without the menu system you can load slinkycat, select option 3 from the menu then run whatever function you want. For example:

```
FindAdminAccessComputers -OutputPath AdminAccess.txt
```

This will find where the local user has admin access OR where the C$ is shared then echo the results back.

### Known Errors
If you select either option 1 or 2 then option A to run all functions, the script will run all functions and prompt you to hit return each time, at the end it will error but in the background it has run all the functions as required. We are working on a fix for this but the function works as intended, if anyone knows a fix ping @ZephrFish.

## Example Running
```
PS C:\Users\user1> Import-Module .\SlinkyCat.ps1
```
This will bring up the menu.
```
=== Menu ===
1. ADSI Enumeration
2. Dot NET System.DirectoryServices.AccountManagement Namespace Enumeration
Q. Quit
Select an option:
```


Option 1 offers you pre-defined ADSI one liners to help enumerate the domain. The result will echo to console, for those that don’t want to save to disk, but you also get an option to save all the results you created to disk via option S on the initial menu, and are also asked again when you quit.


 Select option 1 redirects you to the ADSI Enumeration option menu. 
```
=== ADSI Enumeration ===
ADSI Options Menu Please select an option:
1. Enumerate all domain hosts
2. Enumerate all domain controllers
3. Enumerate all domain users
4. List all users in the domain admins group
5. List all accounts with an SPN
6. List all domain groups
7. List all password set to never expire
8. List all users which do not require a password
9. List all users with password must change at next logon
10. List all computers that are not Domain Controllers and are Windows 7
11. List all computers that are not Domain Controllers and are Windows 10
12. List all computers that are not Domain Controllers and are Windows 11
13. List all servers
14. List all Server 2008
15. List all Server 2012
16. List all Server 2016
17. List all Server 2019
18. List all Server 2022
19. List domain groups which are a member of the local admin group
20. List all trusts established with a domain
21. List all Exchange servers
22. List all accounts that have never logged in
23. List all domain user accounts which have a completed AD description field
24. List all accounts that reference 'pass' in their AD description field
25. List all users who have not changed their password in over 1 year
26. List all users' last password change date and time
27. List all systems with WinRM Open (Not OPSEC SAFE!)
28. List all systems with RDP Open (Not OPSEC SAFE!)
29. Find all machines where the current user has local admin acess (Not OPSEC Safe, will list all computers then attempt to mount C$)
A. Run all functions and export to a HTML report
Q. Quit
```
Select option 5 List all accounts with an SPN see the result below

Select an option: 5
Option: List all accounts with an SPN
```
krbtgt
svc_afds
svc_test
svc_mssql1
svc_mssql2
svc_lab
svc_admin
```


Quitting from the main menu without saving
```
=== Menu ===
1. ADSI Enumeration
2. Dot NET System.DirectoryServices.AccountManagement Namespace Enumeration
Q. Quit
Select an option: q

Goodbye!
PS C:\Users\user1>
```

Reading the output after closing.
```
PS C:\Users\user1> type happy1.txt

Option: Password last set
Username: krbtgt, Last Password Set: 05/04/2023 14:51:59
Username: svc_afds, Last Password Set: 05/04/2023 15:37:40
Username: svc_test, Last Password Set: 05/04/2023 15:37:41
Username: svc_mssql1, Last Password Set: 05/04/2023 15:37:41
Username: svc_mssql2, Last Password Set: 05/04/2023 15:37:42
Username: svc_lab, Last Password Set: 05/04/2023 15:37:42
Username: svc_admin, Last Password Set: 05/04/2023 15:37:43
```

## Future Plans
- Add more enumeration and output formats
