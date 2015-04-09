CALL dc\bin\dependency-check.bat -a "VulnerabilityScan" -s %1 -o "output.xml" -f "XML"
CALL PowerShell.exe .\parsexml.ps1 .\output.xml
DEL .\output.xml