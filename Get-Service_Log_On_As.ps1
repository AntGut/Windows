<#
.SYNOPSIS
    Get information about the services on the local machine with focus on the "Log on as" account details.

.PARAMETER Filtered
    Services are filtered to those not using "built-in" accounts.
    Basically ignore services where "Log on as" is "LocalSystem", "NTAuthority\NetorkService" and similar.

.PARAMETER Export
    Service information is exported to CSV.
    Otherwise output is dumped to console.

.NOTES
--==--==--==--==--==--==--==--== DISCLAIMER ==--==--==--==--==--==--==--==--
This Sample Code is provided for the purpose of illustration only and is not intended to be used in a production environment.  
THIS SAMPLE CODE AND ANY RELATED INFORMATION ARE PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED, 
INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A PARTICULAR PURPOSE.  
We grant you a nonexclusive, royalty-free right to use and modify the sample code and to reproduce and distribute the object 
code form of the Sample Code, provided that you agree: 
    (i)   to not use our name, logo, or trademarks to market your software product in which the sample code is embedded; 
    (ii)  to include a valid copyright notice on your software product in which the sample code is embedded; and 
    (iii) to indemnify, hold harmless, and defend us and our suppliers from and against any claims or lawsuits, including 
          attorneys' fees, that arise or result from the use or distribution of the sample code.
Please note: None of the conditions outlined in the disclaimer above will supercede the terms and conditions contained within 
the Premier Customer Services Description.

--==--==--==--==--==
Version History
--==--==--==--==--==
20180927.0: 29 SEP 2018, Anthony 'AntGut' F. Gutierrez (Sr. PFE)
    Move to GitHub.
20180830.0: 30 AUG 2018, Anthony 'AntGut' F. Gutierrez (Sr. PFE)
    Initial write-up.

#>

Param (
    [switch]$Filtered=$false,
    [switch]$Export=$false
)

#--==--==--==--==--==--==--==--==--==--==--==--==--==--==--==--==--==--==--==--==
function Get-All_Services {
#--==--==--==--==--==--==--==--==--==--==--==--==--==--==--==--==--==--==--==--==
    return Get-WmiObject win32_Service
}

#--==--==--==--==--==--==--==--==--==--==--==--==--==--==--==--==--==--==--==--==
function Get-Filtered_Services {
#--==--==--==--==--==--==--==--==--==--==--==--==--==--==--==--==--==--==--==--==
    return Get-WmiObject win32_Service | Where-Object {$_.StartName -notin $ExcludedSvcAccounts -and $_.StartName}
}

#--==--==--==--==--==--==--==--==--==--==--==--==--==--==--==--==--==--==--==--==
# Main
#--==--==--==--==--==--==--==--==--==--==--==--==--==--==--==--==--==--==--==--==

# Script version
$ThisScriptVersion = "20180929.0"

# "Log on as" accounts to ignore
$ExcludedSvcAccounts = @("LocalSystem","NT AUTHORITY\LocalService","NT AUTHORITY\NetworkService")

# Output path; complex but robust way to get path where this script is executed from
$OutputPath = (Split-Path ((Get-Variable MyInvocation -Scope Script).Value).MyCommand.Path) + '\Logs'

# Create the output path if it doesn't exist.
if (!(Test-Path -Path $OutputPath)) {
    New-Item -Force -ItemType Directory -Path $OutputPath > $null
}

# Output file with Date/Time (to ms) and name of computer script was executed on
$OutputFile = $OutputPath + "\" + (get-date -Format yyyyMMdd_HHmmssff).ToString() + "-" + $env:COMPUTERNAME + "-Service_Accounts-Log_On_As.csv"

# Store info about local services in a collection
if ($Filtered) {
    $WindowsServices = Get-Filtered_Services
} else {
    $WindowsServices = Get-All_Services
}

# Either export to CSV or dump to console
if ($Export) {
    $WindowsServices | Select Name, Startname, StartMode, State, Displayname, Description | Export-Csv -NoTypeInformation $OutputFile
} else {
    $WindowsServices | Select Name, Startname, StartMode, State, Displayname, Description
}
