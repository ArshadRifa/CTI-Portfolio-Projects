
# 🔐 Threat Actor Profile Template
_Designed for CTI teams, researchers, and security analysts_

## 1. Threat Actor Overview
- **Name(s)**: APT28 (a.k.a. Fancy Bear, Sofacy, STRONTIUM)  
- **Associated Nation-State**: Russia  
- **Attribution Confidence**: High / Medium / Low (cite sources)  
- **First Identified**: YYYY  
- **Affiliated Entity**: GRU (Unit 26165)  
- **Motivation**: Espionage, Disinformation, Strategic Advantage  
- **Activity Status**: Active / Dormant / Disbanded

## 2. Aliases & Naming
| Alias Name | Attribution Source |
|------------|--------------------|
| Fancy Bear | CrowdStrike        |
| STRONTIUM  | Microsoft          |
| Sednit     | ESET               |
| Sofacy     | FireEye            |

## 3. Motivations and Objectives
- Long-term cyber espionage against NATO-aligned governments  
- Influence political processes (e.g., election interference)  
- Exfiltrate sensitive military, diplomatic, or economic data  
- Undermine trust in democratic institutions  

## 4. Target Sectors
- Government and military institutions  
- Critical infrastructure (energy, telecom, transport)  
- International bodies (e.g., WADA, OPCW, DNC)  
- Think tanks, media, and NGOs  

## 5. Geographic Focus
- NATO member states  
- Eastern Europe and Transcaucasia  
- North America and select EU countries  

## 6. Tactics, Techniques, and Procedures (TTPs)  
(Mapped to **MITRE ATT&CK**)

| Tactic | Technique ID | Technique Name | Description |
|--------|--------------|----------------|-------------|
| Initial Access | T1566.001 | Spearphishing Attachment | Malicious Word docs with embedded macro |
| Execution | T1203 | Exploitation for Client Execution | Exploits CVE-2017-11292, CVE-2014-4114 |
| Persistence | T1547 | Boot or Logon Autostart Execution | Registry keys, scheduled tasks |
| C2 | T1071.001 | Web Protocols | HTTP(S) beaconing to C2 |

## 7. Toolset and Malware Used
| Malware | Description | Notes |
|---------|-------------|-------|
| GAMEFISH | Custom backdoor used in phishing attachments | Tied to DNC intrusion |
| XAgent | Modular backdoor | Windows, Linux, macOS variants |
| Sedkit | Exploit kit targeting Flash and browsers | Delivered via watering hole |
| Chopstick | Keylogger module | Used alongside XAgent |

## 8. Notable Campaigns
| Campaign Name | Year | Description |
|---------------|------|-------------|
| DNC Hack | 2016 | Breach and leak of Democratic National Committee emails |
| WADA Intrusion | 2016 | Targeted World Anti-Doping Agency after Olympic sanctions |
| TV5Monde Attack | 2015 | Took French TV channel offline temporarily |
| Hotel Wi-Fi Phishing | 2017 | Targeted hospitality sector with spoofed hotel reservation emails |

## 9. Known CVEs Exploited
| CVE ID | Description | Context |
|--------|-------------|---------|
| CVE-2017-11292 | Adobe Flash zero-day | Used in phishing campaign in 2017 |
| CVE-2014-4114 | Windows OLE (Sandworm) | Used against NATO & Ukrainian targets |
| CVE-2015-1701 | Win32k.sys PrivEsc | Post-exploitation stage |

## 10. Indicators of Compromise (IOCs)
- **Domains**: `mvtband.net`, `mvband.net`, `sovetnik.center`  
- **IP Addresses**: 176.31.112.10 (example)  
- **File Hashes**: `7e3f6fbd17a5c4f30aa6d2d41e6a62f3`  

## 11. Attribution Evidence
- Technical overlaps (malware code reuse)  
- Operational behavior  
- Infrastructure reuse  
- Intelligence community reports (NSA, CISA, FireEye, etc.)  
- Public statements by Google, CrowdStrike, Microsoft

## 12. References
- Mwiki, H., Dargahi, T., Dehghantanha, A., & Choo, K. K. R. (2019). *Analysis and triage of advanced hacking groups targeting Western countries' critical national infrastructure.* In *Critical Infrastructure Security and Resilience* (pp. 221–237). Springer. https://doi.org/10.1007/978-3-030-00024-0_13  
- MITRE ATT&CK: [APT28 profile](https://attack.mitre.org/groups/G0007/)  
- FireEye. (2014). APT28: A Window into Russia’s Cyber Espionage Operations.  
- CrowdStrike. (2020). Global Threat Report.  
