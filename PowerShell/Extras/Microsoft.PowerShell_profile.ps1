<#
	Script Name   : Microsoft.PowerShell_profile.ps1
	Author        : Luke Leigh
	Created       : 16/03/2019
	Notes         : This script has been created in order pre-configure the following setting:-
					- Shell Title - Rebranded
					- Shell Dimensions configured to 170 Width x 45 Height
					- Buffer configured to 9000 lines

- Loads the following Functions

	CommandType     Name
	-----------     ----
	Function        Format-Console
	Function        Get-ContainedCommand
	Function        Get-Password
	Function        Get-PatchTue
	Function        New-AdminShell
	Function        New-GitDrives
	Function        New-Greeting
	Function        New-O365Session
	Function        New-ObjectToHashTable
	Function        New-Password
	Function        New-PSDrives
	Function        Remove-O365Session
	Function        Restart-Profile
	Function        Select-FolderLocation
	Function        Show-IsAdminOrNot
	Function        Show-ProfileFunctions
	Function        Show-PSDrive
	Function        Test-IsAdmin

Displays
- whether or not running as Administrator in the WindowTitle
- the Date and Time in the Console Window
- a Greeting based on day of week
- whether or not running as Administrator in the Console Window

When run from Elevated Prompt
- Preconfigures Executionpolicy settings per PowerShell Process Unrestricted
(un-necessary to configure execution policy manually
each new PowerShell session, is configured at run and disposed of on exit)
- Amend PSModulePath variable to include 'OneDrive\PowerShellModules'
- Configure LocalHost TrustedHosts value
- Measures script running performance and displays time upon completion

#>

#--------------------
# Start
$Stopwatch = [system.diagnostics.stopwatch]::startNew()


# Function        Get-ContainedCommand
function Get-ContainedCommand {
	param
	(
		[Parameter(Mandatory)][string]
		$Path,

		[string][ValidateSet('FunctionDefinition', 'Command' )]
		$ItemType
	)

	$Token = $Err = $null
	$ast = [Management.Automation.Language.Parser]::ParseFile( $Path, [ref] $Token, [ref] $Err)

	$ast.FindAll( { $args[0].GetType(). Name -eq "${ItemType}Ast" }, $true )

}


# Function        New-Password
function New-Password {
	<# Example

	.EXAMPLE
	Save-Password -Label UserName

	.EXAMPLE
	Save-Password -Label Password

	#>
	param([Parameter(Mandatory)]
		[string]$Label)
	$securePassword = Read-host -Prompt 'Input password' -AsSecureString | ConvertFrom-SecureString
	$directoryPath = Select-FolderLocation
	if (![string]::IsNullOrEmpty($directoryPath)) {
		Write-Host "You selected the directory: $directoryPath"
	}
	else {
		"You did not select a directory."
	}
	$securePassword | Out-File -FilePath "$directoryPath\$Label.txt"
}


# Function        Get-Password
function Get-Password {
	<#
	.EXAMPLE
	$user = Get-Password -Label UserName
	$pass = Get-Password -Label password

	.OUTPUTS
	$user | Format-List

	.OUTPUTS
	Label           : UserName
	EncryptedString : domain\administrator

	.OUTPUTS
	$pass | Format-List
	Label           : password
	EncryptedString : SomeSecretPassword

	.OUTPUTS
	$user.EncryptedString
	domain\administrator

	.OUTPUTS
	$pass.EncryptedString
	SomeSecretPassword

	#>
	param([Parameter(Mandatory)]
		[string]$Label)
	$directoryPath = Select-FolderLocation
	if (![string]::IsNullOrEmpty($directoryPath)) {
		Write-Host "You selected the directory: $directoryPath"
	}
	$filePath = "$directoryPath\$Label.txt"
	if (-not (Test-Path -Path $filePath)) {
		throw "The password with Label [$($Label)] was not found!"
	}
	$password = Get-Content -Path $filePath | ConvertTo-SecureString
	$decPassword = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($password))
	[pscustomobject]@{
		Label           = $Label
		EncryptedString = $decPassword
	}
}


# Function        Get-PatchTue
function Get-PatchTue {
	<#
	.SYNOPSIS
	Get the Patch Tuesday of a month
	.PARAMETER month
	The month to check
	.PARAMETER year
	The year to check
	.EXAMPLE
	Get-PatchTue -month 6 -year 2015
	.EXAMPLE
	Get-PatchTue June 2015
	#>
	param(
		[string]$month = (get-date).month,
		[string]$year = (get-date).year)
	$firstdayofmonth = [datetime] ([string]$month + "/1/" + [string]$year)
	(0..30 | ForEach-Object {
			$firstdayofmonth.adddays($_)
		} |
		Where-Object {
			$_.dayofweek -like "Tue*"
		})[1]
}


# Function        Restart-Profile
function Restart-Profile {
	@(
		$Profile.AllUsersAllHosts,
		$Profile.AllUsersCurrentHost,
		$Profile.CurrentUserAllHosts,
		$Profile.CurrentUserCurrentHost
	) |
	ForEach-Object {
		if (Test-Path $_) {
			Write-Verbose "Running $_"
			. $_
		}
	}
}


# Function        New-GitDrives
function New-GitDrives {
	$PSRootFolder = Select-FolderLocation
	$Exist = Test-Path -Path $PSRootFolder
	if (($Exist) = $true) {
		$PSDrivePaths = Get-ChildItem -Path "$PSRootFolder\"
		foreach ($item in $PSDrivePaths) {
			$paths = Test-Path -Path $item.FullName
			if (($paths) = $true) {
				New-PSDrive -Name $item.Name -PSProvider "FileSystem" -Root $item.FullName
			}
		}
	}
}


# Function        New-Greeting
function New-Greeting {
	$Today = $(Get-Date)
	Write-Host "   Day of Week  -"$Today.DayOfWeek " - Today's Date -"$Today.ToShortDateString() "- Current Time -"$Today.ToShortTimeString()
	Switch ($Today.dayofweek) {
		Monday { Write-host "   Don't want to work today" }
		Friday { Write-host "   Almost the weekend" }
		Saturday { Write-host "   Everyone loves a Saturday ;-)" }
		Sunday { Write-host "   A good day to rest, or so I hear." }
		Default { Write-host "   Business as usual." }
	}
}


# Function        New-ObjectToHashTable
function New-ObjectToHashTable {
	param([
		Parameter(Mandatory , ValueFromPipeline)]
		$object)
	process	{
		$object |
		Get-Member -MemberType *Property |
		Select-Object -ExpandProperty Name |
		Sort-Object |
		ForEach-Object { [PSCustomObject ]@{
				Item  = $_
				Value = $object. $_
			}
		}
	}
}


# Function        New-PSDrives
function New-PSDrives {
	$PSRootFolder = Select-FolderLocation
	$PSDrivePaths = Get-ChildItem -Path "$PSRootFolder\"
	foreach ($item in $PSDrivePaths) {
		$paths = Test-Path -Path $item.FullName
		if (($paths) = $true) {
			New-PSDrive -Name $item.Name -PSProvider "FileSystem" -Root $item.FullName
		}
	}
}


# Function        Select-FolderLocation
function Select-FolderLocation {
	<#
        Example.
        $directoryPath = Select-FolderLocation
        if (![string]::IsNullOrEmpty($directoryPath)) {
            Write-Host "You selected the directory: $directoryPath"
        }
        else {
            "You did not select a directory."
        }
    #>
	[Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms") | Out-Null
	[System.Windows.Forms.Application]::EnableVisualStyles()
	$browse = New-Object System.Windows.Forms.FolderBrowserDialog
	$browse.SelectedPath = "C:\"
	$browse.ShowNewFolderButton = $true
	$browse.Description = "Select a directory for your report"
	$loop = $true
	while ($loop) {
		if ($browse.ShowDialog() -eq "OK") {
			$loop = $false
		}
		else {
			$res = [System.Windows.Forms.MessageBox]::Show("You clicked Cancel. Would you like to try again or exit?", "Select a location", [System.Windows.Forms.MessageBoxButtons]::RetryCancel)
			if ($res -eq "Cancel") {
				#Ends script
				return
			}
		}
	}
	$browse.SelectedPath
	$browse.Dispose()
}


# Function        Show-IsAdminOrNot
function Show-IsAdminOrNot {
	$IsAdmin = Test-IsAdmin
	if ( $IsAdmin -eq "False") {
		Write-Warning -Message "Admin Privileges!"
	}
	else {
		Write-Warning -Message "User Privileges"
	}
}


# Function        Show-ProfileFunctions
function Show-ProfileFunctions {
	$Path = $profile
	$functionNames = Get-ContainedCommand $Path -ItemType FunctionDefinition |	Select-Object -ExpandProperty Name
	$functionNames | Sort-Object
}


# Function        Show-PSDrive
function Show-PSDrive {
	Get-PSDrive | Format-Table -AutoSize
}


# Function        Stop-Outlook
function Stop-Outlook {
	$OutlookRunning = Get-Process -ProcessName "Outlook"
	if (($OutlookRunning) = $true) {
		Stop-Process -ProcessName Outlook
	}
}


# Function        Test-IsAdmin
function Test-IsAdmin {
	<#
	.Synopsis
	Tests if the user is an administrator
	.Description
	Returns true if a user is an administrator, false if the user is not an administrator
	.Example
	Test-IsAdmin
	#>
	$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
	$principal = New-Object Security.Principal.WindowsPrincipal $identity
	$principal.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
}


# Function        New-AdminShell
function New-AdminShell {
	<#
	.Synopsis
	Starts an Elevated PowerShell Console.
	.Description
	Opens a new PowerShell Console Elevated as Administrator. If the user is already running and elevated
	administrator shell, a message is printed to the screen.
	.Example
	New-AdminShell
	#>
	$Process = Get-Process | Where-Object { $_.Id -eq "$($PID)" }
	if (Test-IsAdmin = $True) {
		Write-Warning -Message "Admin Shell already running!"
	}
	else {
		if ($Process.Name -eq "powershell") {
			Start-Process -FilePath "powershell.exe" -Verb runas -PassThru
		}
		else {
			Start-Process -FilePath "pwsh.exe" -Verb runas -PassThru
		}
	}
}


# Function		New-O365Session
function New-O365Session {
	$Session = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri https://outlook.office365.com/powershell-liveid/ -Credential (Get-Credential) -Authentication Basic -AllowRedirection
	Import-PSSession $Session
}


# Function		Remove-O365Session
function Remove-O365Session {
	Get-PSSession | Remove-PSSession
}


# Set-ExecutionPolicy
Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope Process -Force


#--------------------
# Display running as Administrator in WindowTitle

$whoami = whoami /Groups /FO CSV | ConvertFrom-Csv -Delimiter ','
$MSAccount = $whoami."Group Name" | Where-Object { $_ -like 'MicrosoftAccount*' }
$LocalAccount = $whoami."Group Name" | Where-Object { $_ -like 'Local' }

#$MSAccount.Split('\')[1]
#$env:USERNAME

if ((Test-IsAdmin) -eq $true) {
	if (($MSAccount)) {
		$host.UI.RawUI.WindowTitle = "$($MSAccount.Split('\')[1]) - Admin Privileges"
	}
	else {
		$host.UI.RawUI.WindowTitle = "$($LocalAccount) - Admin Privileges"
	}
}	
else {
	if (($LocalAccount)) {
		$host.UI.RawUI.WindowTitle = "$($MSAccount.Split('\')[1]) - User Privileges"
	}
	else {
		$host.UI.RawUI.WindowTitle = "$($LocalAccount) - User Privileges"
	}
}	


#--------------------
# Configure Powershell Console Window Size/Preferences
function Format-Console {
	param (
		[int]$WindowHeight,
		[int]$WindowWidth,
		[int]$BufferHeight,
		[int]$BufferWidth
	)
	[System.Console]::SetWindowSize($WindowWidth, $WindowHeight)
	[System.Console]::SetBufferSize($BufferWidth, $BufferHeight)
}
Format-Console -WindowHeight 45 -WindowWidth 170 -BufferHeight 9000 -BufferWidth 170


#--------------------
# Aliases
New-Alias -Name 'Notepad++' -Value 'C:\Program Files\Notepad++\notepad++.exe' -Description 'Launch Notepad++'


#--------------------
# Fresh Start
# Clear-Host


#--------------------
# Profile Starts here!
Show-IsAdminOrNot
Write-Host ""
New-Greeting
Write-Host ""
Set-Location -Path C:\GitRepos


#--------------------
# Display Profile Load time and Stop the timer
$Stopwatch.Stop()
# End --------------#>
