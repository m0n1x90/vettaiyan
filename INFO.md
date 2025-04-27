# Setting Up Dependencies

Go to project's root directory

```powershell
vcpkg integrate project

@'
{
  "name": "anti-malware",
  "version": "0.1.0",
  "dependencies": [
    "yara"
  ]
}
'@ | Out-File -Encoding utf8 vcpkg.json

vcpkg x-update-baseline --add-initial-baseline

vcpkg install --triplet x64-windows

vcpkg install
```

And the add the header includes and library directories

C/C++ → General → Additional Include Directories 
```bash
$(ProjectDir)vcpkg_installed\x64-windows\include
```

Linker → General → Additional Library Directories
```bash
$(ProjectDir)vcpkg_installed\x64-windows\lib
```

Linker → Input → Additional Dependencies
```bash
$(ProjectDir)vcpkg_installed\x64-windows\libcrypto.lib
$(ProjectDir)vcpkg_installed\x64-windows\libssl.lib
$(ProjectDir)vcpkg_installed\x64-windows\libyara.lib
```

# Compiling Yara Rules

https://github.com/InQuest/awesome-yara

```bash
find rules/ -name "*.yar" -print0 | xargs -0 -I {} yarac {} vettaiyan.rules
```

# Vettaiyan Agent

`HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Vettaiyan` is the path for the service, delete the hive folder to clear the service

Create context menu for all files via registry to perform scanning via right click

```powershell
reg add "HKLM\Software\Classes\*\shell\ScanWithVettaiyan" /ve /d "Scan with Vettaiyan" /f

reg add "HKLM\Software\Classes\*\shell\ScanWithVettaiyan" /v Icon /d "C:\Users\monis\source\repos\VettaiyanEDR\x64\Debug\Assets\icons\VettaiyanLogo.ico" /f

reg add "HKLM\Software\Classes\*\shell\ScanWithVettaiyan\command" /ve /d 'cmd.exe /k \"C:\Users\monis\source\repos\VettaiyanEDR\x64\Debug\VettaiyanScanner.exe\" \"%1\"' /f
```

Remove the context menu

```powershell
reg delete "HKLM\Software\Classes\*\shell\ScanWithVettaiyan" /f
```

Check the scanner pipe exists or not

```powershell
Test-Path '\\.\pipe\VettaiyanScanner' 
```

Run the agent

```powershell
 sc.exe create Vettaiyan binPath= "C:\Users\monis\source\repos\VettaiyanEDR\x64\Debug\VettaiyanAgent.exe"             

sc.exe start Vettaiyan

sc.exe stop Vettaiyan

sc.exe delete Vettaiyan
 ```

## MpClient

https://github.com/pettro98/mpclient