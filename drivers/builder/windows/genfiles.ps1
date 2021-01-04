#
# Generate visr.inf
#
param(
	[string]$SolutionDir = "vs2019"
)

# Copy $InFileName -> $OutFileName replacing $Token$_.Key$Token with $_.Value from
# $Replacements
Function Copy-FileWithReplacements {
	param(
		[Parameter(Mandatory = $true)]
		[string]$InFileName,
		[Parameter(Mandatory = $true)]
		[string]$OutFileName,
		[hashtable]$Replacements,
		[string]$Token = "@"
	)

	Write-Host "Copy-FileWithReplacements"
	Write-Host $InFileName" -> "$OutFileName

	(Get-Content $InFileName) |
	ForEach-Object {
		$line = $_
		$Replacements.GetEnumerator() | ForEach-Object {
			$key = [string]::Format("{0}{1}{2}", $Token, $_.Name, $Token)
			if (([string]::IsNullOrEmpty($_.Value)) -and ($line.Contains($key))) {
				Write-Host "Skipping Line Containing " $_.Name
				$line = $null
			}
			$line = $line -replace $key, $_.Value
		}
		$line
	} |
	Set-Content $OutFileName
}

#
# Script Body
#
$InfDate = Get-Date -UFormat "%m/%d/%Y"

# [ordered] makes output easier to parse by humans
$Replacements = [ordered]@{
	'MAJOR_VERSION' = $Env:MAJOR_VERSION;
	'MINOR_VERSION' = $Env:MINOR_VERSION;
	'MICRO_VERSION' = $Env:MICRO_VERSION;
	'BUILD_NUMBER' = $Env:BUILD_NUMBER;
	'INF_DATE' = $InfDate;
}

$Replacements | Out-String | Write-Host

$slnpath = Resolve-Path $SolutionDir
$slnpath | Out-String | Write-Host

$src = "$PSScriptRoot\builder.inf"
$dst = Join-Path -Path $slnpath -ChildPath "builder\builder.inf"
Copy-FileWithReplacements $src $dst -Replacements $Replacements
