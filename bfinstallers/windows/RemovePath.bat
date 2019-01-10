@echo on&cls
setlocal EnableDelayedExpansion
set pathline=%path%
set pathline=%pathline: =#%
set pathline=%pathline:;= %

for %%a in (!pathline!) do echo %%a | find /i "Bareflank" || set $newpath=!$newpath!;%%a
set $newpath=!$newpath:#= !
echo pathline
echo !$newpath:~1!
echo setx /m PATH !$newpath:~1!
set $TEMP=!$newpath:~1!
endlocal & setx /m PATH "%$TEMP%"