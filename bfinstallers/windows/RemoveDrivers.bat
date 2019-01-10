@echo off
setlocal EnableDelayedExpansion

for /F "tokens=2 delims=:" %%a in ('pnputil -e') do for /F "tokens=*" %%b in ("%%a") do (
  if "%%b" equ "Assured Information Security, Inc." (
    pnputil /delete-driver !line1prior!
  ) else (
    set "line1prior=%%b"
  )
)
endlocal