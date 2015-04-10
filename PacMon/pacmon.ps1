# PacMon - Dependency Check Runner for TeamCity

function parseDependencies($dependencies) {
	Foreach ($dependency IN $dependencies) {
		parseDependency($dependency)
	}
}

function parseDependency($dependency) {
	[string]$name = cleanString($dependency.fileName)
	[string]$description = cleanString($dependency.description)
	$vulnerabilities = $dependency.vulnerabilities.vulnerability
	
	startTest $name
	
	if ($description) {
		updateTest $name $description
	}
	
	if ($dependency.vulnerabilities) {
		parseVulnerabilities $name $vulnerabilities
	}
	
	endTest($name)
}

function parseVulnerabilities([string]$name, $vulnerabilities){
	Foreach ($vulnerability in $vulnerabilities) {
		parseVulnerability $name $vulnerability
	}
}

function parseVulnerability([string]$name, $vulnerability){
	[string]$vulnerabilityName = cleanString($vulnerability.name)
	[string]$vulnerabilitySeverity = cleanString($vulnerability.severity)
	[string]$vulnerabilityDescription = cleanString($vulnerability.description)

	[string]$error = "{0} ({1}): {2}" -f $vulnerabilityName, $vulnerabilitySeverity, $vulnerabilityDescription
	
	errorTest $name $error
}

function hasVulnerability($dependencies) {
	$vulnerabilityFound = $FALSE
	Foreach ($dependency IN $dependencies) {
		if ($dependency.vulnerabilities) {
			$vulnerabilityFound = $TRUE
		}
	}
	$vulnerabilityFound
}

function startTest([string]$name){
	[string]$formattedOutput = "##teamcity[testStarted name='{0}']" -f $name
	Write-Output $formattedOutput
}

function updateTest([string]$name, [string]$text){
	[string]$formattedOutput = "##teamcity[testStdOut name='{0}' out='{1}']" -f $name, $text
	Write-Output $formattedOutput
}

function errorTest([string]$name, [string]$error){
	[string]$formattedOutput = "##teamcity[testStdErr name='{0}' out='{1}']" -f $name, $error
	Write-Output $formattedOutput
}

function endTest([string]$name){
	[string]$formattedOutput = "##teamcity[testFinished name='{0}']" -f $name
	Write-Output $formattedOutput
}

function cleanString([string]$string){
	$string = $string -replace "`t|`n|`r",""
	$string = $string -replace " ;|; ",";"
	$string = $string -replace "'",""
	$string
}

#http://stackoverflow.com/questions/1183183/path-of-currently-executing-powershell-script
function Get-ScriptDirectory
{
	$Invocation = (Get-Variable MyInvocation -Scope 1).Value
	Split-Path $Invocation.MyCommand.Path
}

#https://confluence.jetbrains.com/display/TCD9/PowerShell
function Set-PSConsole {
	if (Test-Path env:TEAMCITY_VERSION) {
		try {
			$rawUI = (Get-Host).UI.RawUI
			$m = $rawUI.MaxPhysicalWindowSize.Width
			$rawUI.BufferSize = New-Object Management.Automation.Host.Size ([Math]::max($m, 500), $rawUI.BufferSize.Height)
			$rawUI.WindowSize = New-Object Management.Automation.Host.Size ($m, $rawUI.WindowSize.Height)
		} catch {}
	}
}

### BEGIN SCRIPT

[string]$basePath = Get-ScriptDirectory
[string]$inputPath = '{0}\Lambchop' -f $basePath #$args[0]
[string]$dcPath = '{0}\dc\scripts\dependency-check.bat' -f $basePath
[string]$xmlFilename = 'output.xml'
[string]$xmlPath = '{0}\{1}' -f $basePath, $xmlFilename
[string]$htmlFilename = 'vulnerabilities.html'
[string]$htmlPath = '{0}\{1}' -f $basePath, $htmlFilename

[string]$checkCommand = '{0} -a "VulnerabilityScan" -s "{1}" -o "{2}" -f "XML"' -f $dcPath, $inputPath, $xmlFilename
[string]$artifactCommand = '{0} -a "VulnerabilityScan" -s "{1}" -o "{2}" -f "HTML"' -f $dcPath, $inputPath, $htmlFilename
[string]$deleteCommand = 'DEL {0}' -f $xmlFilename

Write-Output ("Executing cmd.exe /C {0}" -f $checkCommand)
cmd.exe /C $checkCommand

if (Test-Path $xmlPath) {
	Write-Output ("Parsing XML output: {0}" -f $xmlPath)
} else {
	Write-Error ("XML output not found: {0}" -f $xmlPath)
	exit(1)
}

[xml]$xml = Get-Content $xmlPath	

if (!$xml.analysis) {
	Write-Error "XML contains no analysis"
	Invoke-Expression $deleteCommand
	exit(1)
}

$dependencies = $xml.analysis.dependencies.dependency

Set-PSConsole

parseDependencies $dependencies

Invoke-Expression $deleteCommand

if (hasVulnerability $dependencies) {
	Write-Output ("Vulnerability found -- generating report artifact: {0}" -f $htmlFilename)
	cmd.exe /C $artifactCommand
	exit(1)
}

exit(0)

### END SCRIPT