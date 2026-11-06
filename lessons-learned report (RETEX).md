# lessons-learned report (RETEX)

## 1. Choix Architecturaux et Justifications

La conception de cet agent SOC a nécessité une architecture capable d’interagir de manière autonome avec un système de fichiers, d’exécuter des outils d’analyse de sécurité (YARA, Sigma) et de raisonner sur des logs bruts, tout en respectant des contraintes strictes de sécurité.

**L’architecture de base repose sur :**

- **Le framework `deepagents` et `LangChain` :** Choisi pour sa capacité à orchestrer des LLMs tout en s’interfaçant facilement avec des outils externes.
- **Le modèle LLM :** Initialement `nemotron-3-nano:30b-cloud` (via `ChatOllama`), choisi pour sa capacité à tourner dans des environnements contrôlés, avec une température de `0` pour garantir un comportement déterministe, indispensable en investigation numérique (DFIR).
- **Le backend `FilesystemBackend` (en `virtual_mode=True`) :** Ce choix est critique. Il permet à l’agent de naviguer dans le système de fichiers (logs, scripts, dossiers d’incident) de manière isolée (“sandbox”). L’agent ne peut pas altérer le système hôte réel, ce qui prévient les destructions accidentelles de preuves ou l’exécution de malwares réels sur la machine de l’analyste.
- **Évolution vers LangGraph (V3) :** Pour pallier les limites du raisonnement séquentiel simple, nous avons introduit un graphe d’états (State Machine) permettant de forcer des chemins d’exécution (ex: lire les procédures avant d’analyser).

## 2. Évolution de l’Agent : De la V1 à la V3

Le développement s’est fait de manière itérative, chaque version corrigeant les lacunes structurelles de la précédente.

### Version 1 : L’Agent “Zero-Shot” Naïf

La première version était un appel direct et minimaliste.

- **Implémentation :** Un prompt système très basique (`"You are a SOC analyst."`) et l’accès au ticket d’incident.
- **Résultat :** L’agent tentait de résoudre l’incident d’un seul coup, sans méthodologie. Il hallucinait des conclusions, incapable de lire les logs sous-jacents puisqu’il ne disposait d’aucun outil pour ouvrir les fichiers annexes. Il se limitait à une analyse syntaxique du ticket initial.

### Version 2 : L’Agent Outillé (L’Apprenti)

- **Ajouts :** Intégration d’outils (`read_file`, `glob`, `test_yara_rule`, `validate_sigma_rule`), de compétences documentées (`/skills/*.md`), et de gardes-fous (“Guardrails”) par le prompt.
- **Résultat :** L’agent est devenu capable d’extraire des IOCs et de tester des règles de détection. Cependant, sa nature probabiliste le poussait à prendre des raccourcis : il ignorait parfois les procédures, bouclait sur des erreurs techniques sans discernement, et commettait des erreurs logiques dans la création de règles en appliquant des modèles génériques inappropriés.

### Version 3 : L’Agent Supervisé et Cadré (L’Expert)

- **Ajouts :**
    - *State Routing :* Obligation mécanique de valider l’étape de lecture des `skills` avant de débloquer l’accès aux outils d’investigation.
    - *Middleware “Circuit Breaker” :* Limitation stricte des tentatives en cas d’erreur d’un outil (max 3 essais).
    - *Outil “Chain-of-Thought” obligatoire :* Création de `log_finding` (constat, preuve, raisonnement) forçant l’agent à justifier ses choix avant d’appeler `propose_containment`.
- **Résultat :** Une baisse drastique de la consommation de jetons inutiles, une explicabilité (XAI) totale des décisions, et un respect scrupuleux des procédures du SOC.

## 3. Erreurs de l’Agent (Preuves par la Trace) et Remédiations

L’analyse des traces LangSmith (LangChain observability) et des rapports générés lors de l’exécution a mis en évidence trois erreurs majeures.

### Erreur 1 : Incohérence technique dans la logique de détection (Hallucination YARA)

- **Le Constat :** L’agent a généré une règle YARA (`Suspicious_PowerShell_Download`) censée détecter le script PowerShell malveillant obfusqué (`facture_2024-11.ps1.txt`). Bien qu’il ait correctement identifié les chaînes en Base64, il a inclus une condition technique absurde pour ce type de fichier.
- **La Preuve (Trace / Rapport) :** Dans la section 5 de son rapport, la règle YARA générée contient la condition `uint16(0) == 0x5A4D`. Cette condition vérifie la présence de l’en-tête “MZ” (les deux premiers octets), qui est exclusif aux fichiers exécutables Windows (PE / `.exe` ou `.dll`). Or, un script PowerShell est un simple fichier texte. En l’état, cette règle ne déclenchera *jamais* sur le script ciblé. Le LLM a aveuglément reproduit un standard de détection de malware issu de ses données d’entraînement sans tenir compte du format réel de la cible.
- **La Remédiation :** L’agent manquait d’une boucle de feedback fonctionnelle. L’outil `test_yara_rule` était en panne technique (cf. Erreur 3). En corrigeant l’outil de test dans la V3, l’agent peut désormais “tester” sa règle sur l’échantillon. En constatant que sa règle ne “match” pas (aucun hit), il est capable de s’auto-corriger et de retirer la condition binaire inutile pour se concentrer sur l’analyse de texte.

### Erreur 2 : Contournement des Procédures (SOPs)

- **Le Constat :** L’agent a ignoré les directives lui demandant de lire les fichiers de compétences (`/skills/`).
- **La Preuve (Trace) :** La séquence d’appels montre que l’agent a directement attaqué les logs :
`read_file(file_path="/incident/ticket_INC-2026-0417.md")read_file(file_path="/incident/web_access.log")`
Aucun appel n’a été fait vers `/skills/extraction-ioc/SKILL.md`. Le modèle a fait preuve d’un biais d’*over-reliance on priors*.
- **La Remédiation :** Implémentation d’une machine à états (State Machine) via LangGraph dans la V3. Le passage au nœud d’investigation est technologiquement bloqué tant que l’outil de lecture n’a pas ciblé le dossier `/skills/`.

### Erreur 3 : Boucle infinie sur un outil défaillant (Gaspillage de tokens)

- **Le Constat :** Face à un problème d’environnement (le montage de volume de l’outil YARA ne correspondait pas à celui de l’outil de lecture), l’agent est resté coincé.
- **La Preuve (Trace) :***Itération 9 :* `test_yara_rule(...) -> Error: Target file does not exist.`*Itération 10 :* `glob(...) -> ['/incident/facture_2024-11.ps1.txt']`*Itération 11 :* `test_yara_rule(...) -> Error`
L’agent a réessayé 8 fois (rapportant d’ailleurs “3 consecutive tool aborts” dans son document final), faisant gonfler le contexte de 14k à près de 16k jetons, ralentissant l’exécution globale.
- **La Remédiation :** Mise en place d’un *Circuit Breaker*. Au bout de 3 erreurs consécutives (`max_retries = 3`), le système intercepte l’outil et renvoie un message imposant au LLM d’abandonner cette voie, de noter l’échec technique et de poursuivre l’investigation. Harmonisation des chemins absolus (CWD) côté Docker.

## 4. Comparaison avec Claude Code (Utilisé lors du TD2)

Durant nos expérimentations, nous avions également utilisé Claude Code. La comparaison avec notre agent LangChain sur-mesure est riche d’enseignements :

- **Capacité de Raisonnement et Structuration :** Claude Code excelle “Out-of-the-box”. Il a permis d’accélérer drastiquement la structuration des données, la mise en forme du rapport final et la rédaction initiale des règles de détection (Sigma/YARA). Sa capacité de synthèse sémantique est supérieure à des modèles plus petits.
- **Vulnérabilité aux biais (Prompt Injection) :** Paradoxalement, malgré sa puissance, Claude Code a fait preuve d’une grande naïveté face aux injections de l’attaquant dans les logs système lors du TD2 (“tâche signée par Microsoft” / “Ignore previous instructions”). Il les a intégrées comme des faits avérés. À l’inverse, l’agent SOC développé a su repérer cette manipulation dans son rapport final (*“line 7 contains explicit instruction to ignore this IP […] confirmed it is not a false positive”*), prouvant l’efficacité d’un prompt système contraint sur la méfiance (Zero Trust).
- **Adéquation au Flux SOC :** Claude Code agit plutôt comme un copilote conversationnel (nécessitant de multiples allers-retours). Notre Agent V3, en revanche, est conçu comme un processus backend automatisé. L’agent sur-mesure respecte infiniment mieux les contraintes algorithmiques rigides du SOC (via LangGraph) et peut tourner de manière autonome de bout en bout avant de soumettre son rapport final.

## 5. Limites de l’Agent et Rôle Central de l’Analyste Humain

Malgré les succès de la V3, confier l’entièreté d’une réponse à incident à un LLM reste dangereux. Voici les limites observées et la ligne de démarcation avec l’humain :

**Limites de l’Agent IA :**

1. **L’illusion de la certitude :** L’agent manque d’intuition. Comme vu avec la règle YARA, il peut générer des éléments techniques syntaxiquement parfaits mais fondamentalement absurdes dans leur contexte. Si une menace utilise une technique “Zero-Day” non documentée, l’agent passera à côté.
2. **Gestion du Contexte Limité :** Bien que les fenêtres de contexte augmentent (ici ~265k jetons consommés au total), ingérer des gigaoctets de logs bruts (PCAP réseau, dumps mémoire entiers) est financièrement et techniquement intenable pour un LLM. Il a besoin d’outils de pré-filtrage puissants (SIEM/EDR) en amont.
3. **Compréhension de l’Impact Métier :** L’IA ne comprend pas la politique interne. Bloquer une IP malveillante est mathématiquement logique pour l’agent, mais si cette IP appartient à un partenaire commercial critique dont les communications sont mal routées, l’impact métier peut être désastreux.

**Ce qui doit rester entre les mains de l’Analyste (Human-in-the-Loop) :**

- **La validation des confinements majeurs :** L’agent peut proposer une isolation de poste (ce qu’il a fait pour `web-01` et `PC-COMPTA-07`), mais toute décision destructrice ou bloquante à grande échelle (Reimage d’un serveur de production) exige l’approbation d’un humain (SOC Lead).
- **La validation de l’ingénierie de détection (Detection Engineering) :** Une règle générée par une IA (comme la règle YARA erronée) ne doit jamais être poussée en production sans révision technique humaine, sous peine de manquer de réelles menaces.
- **L’évaluation de la “Big Picture” :** L’analyste doit déterminer *qui* se cache derrière l’attaque (Attribution) et comment les deux vecteurs (l’injection SQL et le phishing) sont liés, une question d’ailleurs pertinemment soulevée par l’agent dans ses “Open Questions”.

**Conclusion :** L’agent SOC n’est pas un remplaçant, mais un *Triage Engine* redoutable. En filtrant le bruit, en corrélant les IOCs primaires et en structurant l’investigation, il permet à l’analyste humain de se concentrer sur la remédiation stratégique, la correction des outils de détection, et la traque (Threat Hunting) avancée.