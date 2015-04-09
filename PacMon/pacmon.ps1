# PacMon - Dependency Check XML Parser for TeamCity

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

### BEGIN SCRIPT
[string]$inputPath = $args[0]
[string]$dcPath = 'dc\bin\dependency-check.bat'
[string]$xmlPath = '.\output.xml'

[string]$checkCommand = '{0} -a "VulnerabilityScan" -s "{1}" -o "{2}" -f "XML"' -f $dcPath, $inputPath, $xmlPath
[string]$deleteCommand = 'DEL {0}' -f $xmlPath

Invoke-Expression $checkCommand

[xml]$xml = Get-Content $xmlPath

$dependencies = $xml.analysis.dependencies.dependency

parseDependencies($dependencies)

Invoke-Expression $deleteCommand

### END SCRIPT