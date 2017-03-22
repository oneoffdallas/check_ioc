#
# check_ioc.ps1 - v1.4 - 6November2016 - by Dallas Haselhorst
#	Look for the associated SANS Gold Paper to describe this work in greater detail as well if you'd like to learn more.
#	https://www.sans.org/reading-room/whitepapers/critical/uncovering-indicators-compromise-ioc-powershell-event-logs-traditional-monitorin-36352
#	The most up-to-date version of the Gold Paper may also be found on my blog post.
# 	http://linuxincluded.com/uncovering-indicators-of-compromise/
#	
#	This script attempts to locate indicators of compromise on Windows systems. Much of the legwork was performed by the
#	National Security Agency (NSA) in the white paper, "Spotting the Adversary with Windows Event Log Monitoring" (16Dec2013) so a
#	huge thank you to them. The various checks below are notated with the corresponding section from the white paper wherever valid.
#	Example: (4.1) ties to section 4.1 Application Whitelisting in the NSA white paper 
#
#	Heavily modified from the script, watch-eventlogs.ps1, found on Nagios Exchange and originally written by Aaron Wurthmann. 
#	Nonetheless, thanks for the framework and various bits of code Aaron!
#
#	If you are using this from a command line and not Nagios, simply type the script name followed by the amount of time from now
#	to check. Running in this mode will likely be helpful in incident handling and incident response to track down what changed in
#	the last 3 hours, 24 hours, or whatever timeframe you decide.
#	Examples: 
#	.\check_ioc.ps1 30 -- this line would search for the "selected" indicators of compromise (below) in the last 30 minutes 
#	.\check_ioc.ps1 30 > output.txt -- this line would do the same the above but send the output to an output file
#	.\check_ioc.ps1 (60*24) -- would search for the "selected" indicators of compromise (below) in the last 24 hours (too lazy for math)
#
#	For Nagios XI NCPA usage, the following line should be copied to the $ARG1$ text box
#	-t '<token>' -P <port number> -M 'agent/plugin/check_ioc.ps1/<ArgLastMinutes>'
#	For testing from the Nagios command line, add './check_ncpa.py -H <IP address>' (minus quotes) to the above line
#	Notes: 
#	ArgLastMinutes should be populated with the time to check in minutes, e.g. 30 (for 30 minutes), 120 (for 2 hours), etc.
#	Levels: 0 for all logs (LogAlways), 1 for Critical, 2 for Error, 3 for Warning, 4 for Informational, 5 for Verbose
#	Example:
#	-t 'TokenPass' -P 5693 -M 'agent/plugin/check_ioc.ps1/120' 
#	-- above line would search for the "selected" indicators of compromise (below) in the last 2 hours 
#
#	If running the pass-the-hash (PtH) checks on a domain controller this will work without any modifications
#	If running on a non-domain system, you will need to enable "Audit logon events" using the following steps
#	1) Click Start, click Run, type "gpedit.msc" and hit Enter 2) On the left hand side, navigate to Local Computer Policy > 
#	Computer Configuration > Windows Settings > Security Settings > Local Policies > Audit Policy 3) On the right hand side, double-click 
#	“Audit logon events” 4) Check the boxes for Success and Failure, click OK.
#	If in doubt, check your event viewer for Event IDs 4624 or 4625. If they are not there, it's either not turned on or it's logging 
#	elsewhere. ScheduledTaskCheck, RegKeyModCheck, and FileFolderModCheck all require "Audit object access" to be modified. This can be 
#	accomplished in the same manner "Audit logon events" is enabled above. 
#
#	If you are still reading this, great! For Nagios users, it may not make sense to check multiple IoC in single check. Instead, 
#	I would strongly suggest putting several logical selections together. For example, enable all the account-related tests and put them 
#	in their own separate check, enable all the kernel driver signing checks and put them in their own check, etc. Also, if you worried
# 	about log integrity, I would *strongly* recommend forwarding the logs and possibly even monitoring the event log service itself to 
#	ensure it does not get disabled in order to thwart all the log monitoring goodness of this script.
#

# 1 if you are running command for Nagios, comment out or change to 0 if you are running it interactively 
$Nagios = 0

# Prevent PowerShell from auto-wrapping at 80 characters (for Nagios), cause newline characters on write-output otherwise
if ($Nagios -eq 1) {
	if( $Host -and $Host.UI -and $Host.UI.RawUI ) {
	$rawUI = $Host.UI.RawUI
	$oldSize = $rawUI.BufferSize
	$typeName = $oldSize.GetType( ).FullName
	$newSize = New-Object $typeName (500, $oldSize.Height)
	$rawUI.BufferSize = $newSize
	}
}

Function CreateEventsOutput # Should receive argument to reflect what it is working on. For example: SuccessfulPtH or FailedPtH
{

$EntryCount = 0
$LogCount = 0

	If ($Events) { 
	$LogCount = $Events.Count
	If ((($args -eq "FailedUserAcctLogin") -And ($LogCount -ge $FailedUserAcctThreshold)) -Or ($args -ne "FailedUserAcctLogin"))
	{ 
	# set global critical flag if events exist
	$script:CriticalFlag = 1 
	# separate out each of the checks so they can be read more easily
	$script:FullOutput+="
------------------$args Events------------------
	"
	# loop through the entries and format the output
    ForEach ($LogEntry in $Events) {
		$Level=$LogEntry.Level.ToString()
		$Message=$LogEntry.Message.Substring(0,[System.Math]::Min($EventMessageLength, $LogEntry.Message.Length)).TrimEnd().ToString()+'...' 
		$ProviderName=$LogEntry.ProviderName.ToString()
		$LogName=$LogEntry.LogName.ToString()
        $TimeCreated=$LogEntry.TimeCreated.ToString()
        $Id=$LogEntry.Id.ToString()
        $EntryCount++ 
         
                $script:EventResults=@"

$EntryCount - At: $TimeCreated
$EntryCount - LogName: $LogName  
$EntryCount - Level: $Level  
$EntryCount - Event ID: $Id
$EntryCount - Source: $ProviderName
$EntryCount - Message: $Message

$EventResults
"@
    }
	$script:FullOutput+=$EventResults 
	# empty the global eventresults 
	$script:EventResults = ""
	}
}

#If ($CondensedOutput) { $script:CondensedOutput+="; " }
If (($args -eq "FailedUserAcctLogin") -And ($LogCount -lt $FailedUserAcctThreshold))
{ $script:CondensedOutput+="$args` below threshold:$LogCount " }
Else { $script:CondensedOutput+="$args`:$EntryCount " }

}


# Pull in time argument if given, otherwise, default to [last] 30 mins 
$ArgLastMinutes = $args[0]
if (!$ArgLastMinutes) { $ArgLastMinutes = 30 }
$ArgTimeQuery = ($ArgLastMinutes*60*1000) # XML queries must be in micro seconds 
$EventMessageLength = 800 # main event information is about 30; should be around 800 to get a majority of details including the message text

# Change the values to 0 for items you do not want to check
$SuccessfulPtHCheck = 1 #(4.15) detects pass the hash attempts; may include false indicators in cases where remote desktop or remoteapp is utilized; added KeyLength to improve reliability (Thanks Dave Kennedy)
$FailedPtHCheck = 1 #(4.15) detects failed pass the hash attempts; same false indicator warning as PtH above
$LogClearCheck = 1 # (4.6) checks for all types of event log clears
$FirewallRuleModCheck = 1 # (4.5) checks for firewall rule adds, changes and deletions, may cause false indicators
$ServiceAddCheck = 1 # (4.7) checks for new Windows services
$AppErrorCheck = 0 # (4.2) may cause false indicators as applications do crash on their own; very useful in well-known environments
$AppHangCheck = 0 # (4.2) may cause false indicators as applications do crash on their own; very useful in well-known environments
$BSODCheck = 0 # (4.2) may cause false indicators as applications do crash on their own; very useful in well-known environments
$WindowsErrorReportingCheck = 0 # (4.2) may cause false indicators 
$ServiceFailCrashCheck = 0 # (4.3) may cause false indicators 
$AppLockerBlockCheck = 0 # (4.1) AppLocker must be configured
$AppLockerWarningCheck = 0 # (4.1) AppLocker must be configured
$SRPBlockCheck = 0 # (4.1) software restriction polices must be configured
$EMETCheck = 0 # (4.2) EMET must be configured and it will cause errors if you don't have it installed
$NewKernelFilterDriverCheck = 0 # (4.7) causes quite a few false indicators so you would have to add exceptions
$AppInstallCheck = 0 # (4.7) may cause false indicators Note: does not work in Win8 
$MSIInstallCheck = 0 # (4.7) may cause false indicators; very useful in well-known environments
$AccountLockoutCheck = 0 # (4.8) may cause false indicators if the # of invalid password attempts to lockout in group policy is low (recommend 25)
$UserAddPrivGroupCheck = 0 # (4.8) user added to privileged group
$SecEnabledGroupModCheck = 0 # (4.8) security-enabled group modification
$FailedUserAcctLoginCheck = 1 # (4.8) failed user account login, works with FailedUserAcctThreshold value below
# FailedUserAcctThreshold works in conjunction with the check above, FailedUserAcctLoginCheck
# Find out what a "standard" baseline number is for the period of time you are checking for and then add a bit more to avoid false indicators
$FailedUserAcctThreshold = 50 # threshold for the number of failed logins before 'critical' is triggered 
$InvalidImageHashFileCheck  = 1 # (4.9) kernel driver signing - detected an invalid image hash of a file
$InvalidPageHashFileCheck = 1 # (4.9) kernel driver signing - detected an invalid page hash of an image file
$CodeIntegrityCheck = 0 # (4.9) kernel driver signing - code integrity check
$FailedKernelDriverCheck = 1 # (4.9) kernel driver signing - failed kernel driver loading
$LSASAMPassChangesCheck = 0 # indicators code is loaded into LSA (Local Security Authority) or SAM (Security Account Manager) and watching for password changes (Thanks Jessica Payne)
$NewMassStorageInstallCheck = 0 # (4.13) new mass storage installation; this occurs every time the device is inserted (not just the first time)
# Recommend to disable all customer experience tasks to avoid false indicators with line below. Turn off in "Action Center" and then disable *ALL* jobs under 
# "Microsoft/Windows/Application Experience" and "Customer Experience Improvement Program" (and "Server" jobs if it exists under the latter library)
$ScheduledTaskCheck = 0 # checks for various changes to the scheduled tasks (for persistent access)
# auditing must be enabled/configured for registry keys you want to monitor, the check below is looking for "CurrentVersion" in the message
$RegKeyModCheck = 1 # checks for changes to the various registry keys that might be used for persistent access 
# auditing must be enabled/configured for the files or folders you want to monitor
#$FileFolderModCheck = 1 # checks for changes to high value files you specify. Note: Do not attempt to audit the entire c:\windows directory 

# set default properties we will pull with each query
$Properties='Level','Message','ProviderName','TimeCreated','Id','LogName'

If ($SuccessfulPtHCheck -eq 1) {
$SuccessPtHQuery = @'
<QueryList> 
	<Query Id="0"> 
		<Select Path="Security"> 
		*[System[(EventID="4624")
		and 
		(Level=4 or Level=0) 
		and 
		TimeCreated[timediff(@SystemTime) &lt;= 
'@
$SuccessPtHQuery += $ArgTimeQuery
$SuccessPtHQuery += @'
		] ]]
		and
		*[EventData[Data[@Name="LogonType"] and (Data="3")]]
		and
		*[EventData[Data[@Name="AuthenticationPackageName"] = "NTLM"]]
		and
		*[EventData[Data[@Name="KeyLength"] = "0"]]
		and
		*[EventData[Data[@Name="TargetUserName"] != "ANONYMOUS LOGON"]]
		</Select> 
		</Query> 
</QueryList>
'@
$Events = Get-winevent -FilterXml $SuccessPtHQuery -ea SilentlyContinue | Select-Object -Property $Properties
CreateEventsOutput "SuccessfulPtH"
}

If ($FailedPtHCheck -eq 1) {
$FailedPtHQuery = @'
<QueryList> 
	<Query Id="0"> 
		<Select Path="Security"> 
		*[System[(EventID="4625")
		and 
		(Level=4 or Level=0) 
		and 
		TimeCreated[timediff(@SystemTime) &lt;= 
'@
$FailedPtHQuery += $ArgTimeQuery
$FailedPtHQuery += @'
		] ]]
		and
		*[EventData[Data[@Name="LogonType"] and (Data="3")]]
		and
		*[EventData[Data[@Name="AuthenticationPackageName"] = "NTLM"]]
		and
		*[EventData[Data[@Name="KeyLength"] = "0"]]
		and
		*[EventData[Data[@Name="TargetUserName"] != "ANONYMOUS LOGON"]]
		</Select> 
		</Query> 
</QueryList>
'@
$Events = Get-winevent -FilterXml $FailedPtHQuery -ea SilentlyContinue | Select-Object -Property $Properties
CreateEventsOutput "FailedPtH"
}

If ($LogClearCheck -eq 1) {
$Events = Get-winevent -FilterHashtable @{logname='Security','System'; id=1102,104; Level=4; StartTime = (Get-Date).AddMinutes(-$ArgLastMinutes) } -ea SilentlyContinue | Select-Object -Property $Properties 
CreateEventsOutput "LogClear"
}

If ($FirewallRuleModCheck -eq 1) {
$Events = Get-winevent -FilterHashtable @{logname='Microsoft-Windows-Windows Firewall With Advanced Security/Firewall'; id=2003,2004,2005,2006,2033; StartTime = (Get-Date).AddMinutes(-$ArgLastMinutes) } -ea SilentlyContinue | Select-Object -Property $Properties 
CreateEventsOutput "FirewallRuleMod"
}

If ($ServiceAddCheck -eq 1) {
$Events = Get-winevent -FilterHashtable @{logname='System'; id=7045; StartTime = (Get-Date).AddMinutes(-$ArgLastMinutes) } -ea SilentlyContinue | Select-Object -Property $Properties 
CreateEventsOutput "ServiceAdd"
}

If ($AppErrorCheck -eq 1) {
$Events = Get-winevent -FilterHashtable @{logname='Application'; ProviderName='Application Error'; id=1000; Level = 2; StartTime = (Get-Date).AddMinutes(-$ArgLastMinutes) } -ea SilentlyContinue | Select-Object -Property $Properties 
CreateEventsOutput "AppError"
}

If ($AppHangCheck -eq 1) {
$Events = Get-winevent -FilterHashtable @{logname='Application'; ProviderName='Application Hang'; id=1002; Level = 2; StartTime = (Get-Date).AddMinutes(-$ArgLastMinutes) } -ea SilentlyContinue | Select-Object -Property $Properties 
CreateEventsOutput "AppHang"
}

If ($BSODCheck -eq 1) {
$Events = Get-winevent -FilterHashtable @{logname='System'; id=1001; Level = 2; StartTime = (Get-Date).AddMinutes(-$ArgLastMinutes) } -ea SilentlyContinue | Select-Object -Property $Properties 
CreateEventsOutput "BSOD"
}

If ($WindowsErrorReportingCheck -eq 1 ) {
$Events = Get-winevent -FilterHashtable @{logname='Application'; id=1001; Level = 4; ProviderName='Windows Error Reporting'; StartTime = (Get-Date).AddMinutes(-$ArgLastMinutes) } -ea SilentlyContinue | Select-Object -Property $Properties 
CreateEventsOutput "WindowsErrorReporting"
}

If ($ServiceFailCrashCheck -eq 1) {
$Events = Get-winevent -FilterHashtable @{logname='System'; id=7022,7023,7024,7026,7031,7032,7034; Level = 2; StartTime = (Get-Date).AddMinutes(-$ArgLastMinutes) } -ea SilentlyContinue | Select-Object -Property $Properties 
CreateEventsOutput "ServiceFailsCrash"
}

If ($AppLockerBlockCheck -eq 1) {
$Events = Get-winevent -FilterHashtable @{logname='Microsoft-Windows-AppLocker/EXE and DLL'; id=8003,8004; Level = 2,3; StartTime = (Get-Date).AddMinutes(-$ArgLastMinutes) } -ea SilentlyContinue | Select-Object -Property $Properties 
CreateEventsOutput "AppLockerBlock"
}

If ($AppLockerWarningCheck -eq 1) {
$Events = Get-winevent -FilterHashtable @{logname='Microsoft-Windows-AppLocker/MSI and Script'; id=8006,8007; Level = 2,3; StartTime = (Get-Date).AddMinutes(-$ArgLastMinutes) } -ea SilentlyContinue | Select-Object -Property $Properties 
CreateEventsOutput "AppLockerWarning"
}

If ($EMETCheck -eq 1) {
$Events = Get-winevent -FilterHashtable @{logname='Application'; ProviderName='EMET'; id=1,2; StartTime = (Get-Date).AddMinutes(-$ArgLastMinutes) } -ea SilentlyContinue | Select-Object -Property $Properties 
CreateEventsOutput "EMET"
}

If ($NewKernelFilterDriverCheck -eq 1) {
$Events = Get-winevent -FilterHashtable @{logname='System'; id=6; StartTime = (Get-Date).AddMinutes(-$ArgLastMinutes) } -ea SilentlyContinue | Select-Object -Property $Properties 
CreateEventsOutput "NewKernelFilterDriver"
}

If ($AppInstallCheck -eq 1) {
$Events = Get-winevent -FilterHashtable @{logname='Microsoft-Windows-Application-Experience/Program-Inventory'; id=903,904; ProviderName='Microsoft-Windows-Application-Experience'; Level=4; StartTime = (Get-Date).AddMinutes(-$ArgLastMinutes) } -ea SilentlyContinue | Select-Object -Property $Properties 
CreateEventsOutput "AppInstall"
}

If ($MSIInstallCheck -eq 1) {
$Events = Get-winevent -FilterHashtable @{logname='Application'; id=1022,1033; ProviderName='MsiInstaller'; Level=4; StartTime = (Get-Date).AddMinutes(-$ArgLastMinutes) } -ea SilentlyContinue | Select-Object -Property $Properties 
CreateEventsOutput "MSIInstall"
}

If ($AccountLockoutCheck -eq 1) {
$Events = Get-winevent -FilterHashtable @{logname='Security'; id=4740; ProviderName='Microsoft-Windows-Security-Auditing'; Level=4; StartTime = (Get-Date).AddMinutes(-$ArgLastMinutes) } -ea SilentlyContinue | Select-Object -Property $Properties 
CreateEventsOutput "AccountLockout"
}

If ($UserAddPrivGroupCheck -eq 1) {
$Events = Get-winevent -FilterHashtable @{logname='Security'; id=4728,4732,4756; ProviderName='Microsoft-Windows-Security-Auditing'; StartTime = (Get-Date).AddMinutes(-$ArgLastMinutes) } -ea SilentlyContinue | Select-Object -Property $Properties 
CreateEventsOutput "UserAddPrivGroup"
}

If ($SecEnabledGroupModCheck -eq 1) {
$Events = Get-winevent -FilterHashtable @{logname='Security'; id=4735; ProviderName='Microsoft-Windows-Security-Auditing'; StartTime = (Get-Date).AddMinutes(-$ArgLastMinutes) } -ea SilentlyContinue | Select-Object -Property $Properties 
CreateEventsOutput "SecEnabledGroupMod"
}

If ($FailedUserAcctLoginCheck -eq 1) {
$Events = Get-winevent -FilterHashtable @{logname='Security'; id=4625; ProviderName='Microsoft-Windows-Security-Auditing'; Level=0; StartTime = (Get-Date).AddMinutes(-$ArgLastMinutes) } -ea SilentlyContinue | Select-Object -Property $Properties 
CreateEventsOutput "FailedUserAcctLogin"
}

If ($InvalidImageHashFileCheck -eq 1) {
$Events = Get-winevent -FilterHashtable @{logname='Security'; id=5038; ProviderName='Microsoft-Windows-Security-Auditing'; Level=0; StartTime = (Get-Date).AddMinutes(-$ArgLastMinutes) } -ea SilentlyContinue | Select-Object -Property $Properties 
CreateEventsOutput "InvalidImageHashFile"
}

If ($InvalidPageHashFileCheck -eq 1) {
$Events = Get-winevent -FilterHashtable @{logname='Security'; id=6281; ProviderName='Microsoft-Windows-Security-Auditing'; Level=0; StartTime = (Get-Date).AddMinutes(-$ArgLastMinutes) } -ea SilentlyContinue | Select-Object -Property $Properties 
CreateEventsOutput "InvalidPageHashFile"
}

If ($CodeIntegrityCheck -eq 1) {
$Events = Get-winevent -FilterHashtable @{logname='Microsoft-Windows-CodeIntegrity/Operational'; id=3001,3002,3003,3004,3010,3023; ProviderName='Microsoft-Windows-CodeIntegrity'; Level=2,3; StartTime = (Get-Date).AddMinutes(-$ArgLastMinutes) } -ea SilentlyContinue | Select-Object -Property $Properties 
CreateEventsOutput "CodeIntegrity"
}

If ($FailedKernelDriverCheck -eq 1) {
$Events = Get-winevent -FilterHashtable @{logname='System'; id=219; ProviderName='Microsoft-Windows-Kernel-PnP'; Level=3; StartTime = (Get-Date).AddMinutes(-$ArgLastMinutes) } -ea SilentlyContinue | Select-Object -Property $Properties 
CreateEventsOutput "FailedKernelDriver"
}

If ($LSASAMPassChangesCheck -eq 1) {
$Events = Get-winevent -FilterHashtable @{logname='Security'; id=4610,4611,4614,4622; Level=0; StartTime = (Get-Date).AddMinutes(-$ArgLastMinutes) } -ea SilentlyContinue | Select-Object -Property $Properties 
CreateEventsOutput "LSASAMPassChanges"
}

If ($NewMassStorageInstallCheck -eq 1) {
$Events = Get-winevent -FilterHashtable @{logname='Microsoft-Windows-Kernel-PnP/Configuration'; id=400,410; ProviderName='Microsoft-Windows-Kernel-PnP'; StartTime = (Get-Date).AddMinutes(-$ArgLastMinutes) } -ea SilentlyContinue | Select-Object -Property $Properties 
CreateEventsOutput "NewMassStorageInstall"
}

If ($ScheduledTaskCheck -eq 1) {
$Events = Get-winevent -FilterHashtable @{logname='Security'; id=4698,4699,4700,4701,4702; StartTime = (Get-Date).AddMinutes(-$ArgLastMinutes) } -ea SilentlyContinue | Select-Object -Property $Properties 
CreateEventsOutput "ScheduledTask"
}

If ($RegKeyModCheck -eq 1) {
$Events = Get-winevent -FilterHashtable @{logname='Security'; id=4657; StartTime = (Get-Date).AddMinutes(-$ArgLastMinutes) } -ea SilentlyContinue | where-object {$_.Message -like "*CurrentVersion*" } | Select-Object -Property $Properties 
CreateEventsOutput "RegKeyMod"
}
<#
If ($FileFolderModCheck -eq 1) {
$Events = Get-winevent -FilterHashtable @{logname='Security'; id=4656,4658; StartTime = (Get-Date).AddMinutes(-$ArgLastMinutes) } -ea SilentlyContinue | where-object {$_. -eq "" } | Select-Object -Property $Properties 
CreateEventsOutput "FileFolderMod"
}
#>

If ($CriticalFlag -eq 1) { 
# write the "summary" at the top and bottom so you don't have to hunt for it
# write-host is used first so it returns one line to Nagios without newline characters
# write-output allows us to easily re-direct the script from the command line to a separate file 
$OutputString = "Critical: $CondensedOutput"
$OutputString += "in the last $ArgLastMinutes minutes" 
write-output $OutputString
write-output $FullOutput 
write-output $OutputString
exit 2 # the 2 returns to Nagios as a critical event
} 
else { 
$OutputString = "OK: $Status$CondensedOutput"
$OutputString += "in the last $ArgLastMinutes minutes" 
write-output $OutputString
exit 0 # the 0 returns to Nagios as all is well 
}

