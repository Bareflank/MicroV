
param(
        [string]$Prefix
)

if ([string]::IsNullOrEmpty($Env:BUILD_NUMBER)) {
	if (Test-Path "$Prefix\.build_number") {
		$BuildNum = Get-Content -Path "$Prefix\.build_number"
		Set-Content -Path "$Prefix\.build_number" -Value ([int]$BuildNum + 1)
	} else {
		$BuildNum = '0'
		Set-Content -Path "$Prefix\.build_number" -Value '1'
	}

	Set-Item -Path Env:BUILD_NUMBER -Value $BuildNum
}

