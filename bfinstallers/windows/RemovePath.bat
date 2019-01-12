REM
REM Copyright (C) 2019 Assured Information Security, Inc.
REM
REM Permission is hereby granted, free of charge, to any person obtaining a copy
REM of this software and associated documentation files (the "Software"), to deal
REM in the Software without restriction, including without limitation the rights
REM to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
REM copies of the Software, and to permit persons to whom the Software is
REM furnished to do so, subject to the following conditions:
REM
REM The above copyright notice and this permission notice shall be included in all
REM copies or substantial portions of the Software.
REM
REM THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
REM IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
REM FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
REM AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
REM LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
REM OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
REM SOFTWARE.

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
