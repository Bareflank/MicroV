#
# Store symbols for archived build
#
param(
	[string]$SymbolServer = "c:\symbols",
	[Parameter(Mandatory = $true)]
	[string]$Arch
)

Function Add-Symbols {
	param(
		[string]$DriverName,
		[string]$ArchivePath,
		[string]$SymbolServer,
		[string]$Arch
	)

	Write-Host Store symbols from (Resolve-Path $ArchivePath)

	$cwd = Get-Location
	Set-Location $ArchivePath

	$path = Join-Path -Path ([string]::Format("{0}Debuggers", $env:WDKContentRoot)) -ChildPath $Arch
	$symstore = Join-Path -Path $path -ChildPath "symstore.exe"

	$inffile = [string]::Format("{0}.inf", $DriverName)
	$Version = (Get-Content -Path $inffile | Select-String "DriverVer").Line.Split(',')[1]

	Get-ChildItem -Path "." -Include "*.pdb" -Name | Write-Host
	& $symstore "add" "/s" $SymbolServer "/r" "/f" "*.pdb" "/t" $DriverName "/v" $Version

	Set-Location $cwd
}

$archivepath = Join-Path -Path (Resolve-Path "xennet") -ChildPath $Arch
Add-Symbols "xennet" $archivepath $SymbolServer $Arch
