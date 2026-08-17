@echo off
setlocal EnableExtensions

REM -----------------------------------------------------------------------------
REM WMI query test generator for Windows 7 / 8 / 10 / 11.
REM Uses Windows PowerShell Get-WmiObject because it is available on Windows 7+
REM and avoids depending on WMIC, which is removed/optional on newer Windows 11.
REM
REM Recommended test flow:
REM   1) Run wmi_etw_consumer.exe as Administrator.
REM   2) In another cmd.exe, run this BAT.
REM   3) Compare [TEST xx] below with ClientProcessId / Operation in ETW output.
REM -----------------------------------------------------------------------------

echo.
echo ================================================================
echo WMI query ETW test generator
echo ================================================================
echo This BAT intentionally runs both successful and failing WMI queries.
echo Expected PowerShell errors are part of the test.
echo.

where powershell.exe >nul 2>&1
if errorlevel 1 (
    echo [FATAL] powershell.exe was not found.
    exit /b 1
)

powershell.exe -NoProfile -ExecutionPolicy Bypass -Command ^
 "$ErrorActionPreference='Stop';" ^
 "$tests=@(" ^
 " @{Id='01'; Name='SUCCESS - operating system'; Ns='root\cimv2'; Q='SELECT * FROM Win32_OperatingSystem'; Expect='SUCCESS'}," ^
 " @{Id='02'; Name='SUCCESS - process projection'; Ns='root\cimv2'; Q='SELECT Name,ProcessId,ExecutablePath FROM Win32_Process'; Expect='SUCCESS'}," ^
 " @{Id='03'; Name='SUCCESS - logical disks'; Ns='root\cimv2'; Q='SELECT * FROM Win32_LogicalDisk'; Expect='SUCCESS'}," ^
 " @{Id='04'; Name='SUCCESS EMPTY - impossible PID'; Ns='root\cimv2'; Q='SELECT * FROM Win32_Process WHERE ProcessId = 4294967295'; Expect='SUCCESS (usually zero rows)'}," ^
 " @{Id='05'; Name='SYNTAX ERROR - misspelled SELECT'; Ns='root\cimv2'; Q='SELEC * FROM Win32_Process'; Expect='ERROR'}," ^
 " @{Id='06'; Name='SEMANTIC ERROR - nonexistent class'; Ns='root\cimv2'; Q='SELECT * FROM Ajiant_Class_That_Does_Not_Exist'; Expect='ERROR'}," ^
 " @{Id='07'; Name='SEMANTIC ERROR - nonexistent property'; Ns='root\cimv2'; Q='SELECT AjiantPropertyThatDoesNotExist FROM Win32_Process'; Expect='ERROR'}," ^
 " @{Id='08'; Name='NAMESPACE ERROR - nonexistent namespace'; Ns='root\AjiantNamespaceThatDoesNotExist'; Q='SELECT * FROM Win32_Process'; Expect='ERROR'}," ^
 " @{Id='09'; Name='SUCCESS/SENSITIVE - shadow copies'; Ns='root\cimv2'; Q='SELECT * FROM Win32_ShadowCopy'; Expect='SUCCESS or provider-specific error'}," ^
 " @{Id='10'; Name='SUCCESS - services'; Ns='root\cimv2'; Q='SELECT Name,State,ProcessId FROM Win32_Service'; Expect='SUCCESS'}" ^
 ");" ^
 "Write-Host ('PowerShell Client PID = ' + $PID);" ^
 "Write-Host 'The ETW ClientProcessId for these local queries should normally match this PID.';" ^
 "Write-Host '';" ^
 "foreach($t in $tests){" ^
 " Write-Host ('------------------------------------------------------------');" ^
 " Write-Host ('[TEST ' + $t.Id + '] ' + $t.Name);" ^
 " Write-Host ('PID       : ' + $PID);" ^
 " Write-Host ('Namespace : ' + $t.Ns);" ^
 " Write-Host ('Query     : ' + $t.Q);" ^
 " Write-Host ('Expected  : ' + $t.Expect);" ^
 " try {" ^
 "   $r = Get-WmiObject -Namespace $t.Ns -Query $t.Q -ErrorAction Stop;" ^
 "   $count = @($r).Count;" ^
 "   Write-Host ('Result    : SUCCESS, rows=' + $count);" ^
 " } catch {" ^
 "   Write-Host ('Result    : ERROR - ' + $_.Exception.Message);" ^
 " }" ^
 " Start-Sleep -Milliseconds 700;" ^
 "}" ^
 "Write-Host ('------------------------------------------------------------');" ^
 "Write-Host 'Done. Check wmi_etw_consumer output for Event IDs 1, 11, 5858 and field coverage.';"

set "RC=%ERRORLEVEL%"
echo.
echo PowerShell exit code: %RC%
echo.
echo Notes:
echo   - Event 1 exists in the supplied Windows 7 WMI-Activity manifest.
echo   - Event 11 and 5858 are not in that Windows 7 manifest and are expected on newer Windows generations.
echo   - 5858 is an error event. Not every failed client-side operation is guaranteed to become the same WMI provider event on every OS build.
echo   - Run the C++ consumer as Administrator for real-time ETW access.
echo.
exit /b %RC%
