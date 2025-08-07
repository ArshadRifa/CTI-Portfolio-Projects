# Threat Actor Profile: APT28

### Threat Actor Overview

* Name(s): APT28 (a.k.a. Fancy Bear, Sofacy, STRONTIUM- other referencesIRON TWILIGHT, SNAKEMACKEREL, Swallowtail, Group 74, Sednit, Sofacy, Pawn Storm, Fancy Bear, STRONTIUM, Tsar Team, Threat Group-4127, TG-4127, Forest Blizzard, FROZENLAKE, GruesomeLarch [(MITRE ATT\&CK®, 2017\)](https://www.zotero.org/google-docs/?C2Lw1k)

* Associated Nation-State: Russia

* First Identified: 2004 

* Affiliated Entity: Main Intelligence Directorate of the Russian General Staff (Glavnoye razvedyvatel'noye upravleniye, or GRU) Unit 26165  
    
* Motivation: Espionage, Disinformation, Strategic Advantage

* Activity Status: Active / Dormant / Disbanded

### Alias and Naming

| Alias Name | Attribution Source |
| ----- | ----- |
| Sofacy (Palo Alto)  | [(Falcone, 2018\)](https://www.zotero.org/google-docs/?6JVJbB) |
| Sednit (ESET) | [(ESET, 2016\)](https://www.zotero.org/google-docs/?OeNrLh) |
| PawnStorm (Trend Micro)  | [(Trend Micro (US), 2019\)](https://www.zotero.org/google-docs/?zq6UTN) |
| Fancy Bear (Crowdstrike) | [(CrowdStrike, 2019\)](https://www.zotero.org/google-docs/?3jfzGu) |
| Tsar Team (Trustwave) | [(Trustwave, 2015\)](https://www.zotero.org/google-docs/?2pVj7h) |
| Group 74 (Talos), | [(Cisco Talos, 2017\)](https://www.zotero.org/google-docs/?E5Hekd) |
| TG-4127 / Threat Group-4127 | [(SecureWorks, 2016\)](https://www.zotero.org/google-docs/?T4Skdf) |
| Forest Blizzard / STRONTIUM (Microsoft) | [(Microsoft Inc, 2024\)](https://www.zotero.org/google-docs/?Wamm5v) |
| UAC-0001 (Socprime) | [(Telychko, 2025\)](https://www.zotero.org/google-docs/?kn45ac) |

### History

The group’s roots can be traced back to the mid-2000s, with its operations believed to have begun around 2008\. The group is widely associated with the Russian military intelligence agency GRU, and its operations closely mirror the strategic interests of the Russian government. [(Radware, 2024\)](https://www.zotero.org/google-docs/?jVTqrI)

In its early operations, the APTgroup demonstrated a sophisticated approach to cyber espionage. The group employed a range of tactics such as spear-phishing messages and credential harvesting using spoofed websites. Over time, their campaigns grew more sophisticated, reflecting an escalating cyber arms race between attackers and defenders. Their primary implant, known as XAgent, has been ported across multiple operating systems for conventional computers as well as mobile platforms.

Fancy Bear’s rise to prominence can be attributed to several high-profile cyberattacks. The group is thought to be responsible for cyberattacks on the German parliament, the Norwegian parliament, the French television station TV5Monde, the White House, NATO, the Democratic National Committee, the Organization for Security and Co-operation in Europe and the campaign of French presidential candidate Emmanuel Macron. In 2018, an indictment by the United States Special Counsel identified Fancy Bear (APT28) as GRU Unit 261651, further solidifying its notoriety in the world of cybersecurity.

### Motive 

* Political and Military Intelligence: APT28 activities are intended to collect intelligence for Russian Foreign Policy decisions and military strategy, spy on government departments, security agencies, high-level NATO member countries 'mainly Eastern Europe or thereabouts [(Radware, 2024\)](https://www.zotero.org/google-docs/?2yAXz1).   
    
* Influence operations: The group has been involved in operations intended to influence public opinion and political outcome — the most notorious example is the interference with 2016 US Presidential elections. Such activities often involve spreading disinformation, releasing sensitive information. And engineering public perception to create disunity among the populace and this affect political events [(Radware, 2024\)](https://www.zotero.org/google-docs/?GpHe0Q).  
    
* Strategic disruption: In addition to espionage activities APT28 also engages in acts inimical to the military, economic or political capacities of other countries. Such acts will include planting malicious software that can be used to destroy internal computer systems and disrupting major infrastructure [(Radware, 2024\)](https://www.zotero.org/google-docs/?h32YF9).

### Target sectors

Targeted sectors include Governments, military organisations, aerospace, media firms, research companies, energy, journalists, politicians, telecommunications, embassies, and information technology. 

Targeted regions include Europe (mostly NATO members), North America, the UAE, the Middle East, and Syria.

### Campaigns by APT28

Since 2008, the Russian cyberespionage group APT 28, has targeted many industries, including energy, government, media, aerospace, and defence, via phishing campaigns and credential harvesting and its efforts continue to be covert, motivated by gathering intelligence. Below is a list demonstrating the threats and attacks committed between the 2016-2024 period, draws the functionality of APT28, and maps the magnitude of mitigation measures to be undertaken to prevent the threats [(Radware, 2024\)](https://www.zotero.org/google-docs/?TyHkmD).

* 2016 US Presidential Election Fancy Bear is well-known for hacking into the Democratic National Committee (DNC) email servers to influence the outcome of the 2016 US presidential election. They attacked targets by sending spear-phishing emails and installing malware (Radware 2024).   
* German Bundestag Fancy Bear has been publicly linked to hacking into the German Bundestag. They deployed spear-phishing attacks on government officials and malware to gain network access (Radware 2024\)  
* TV5 Monde French TV Station In April 2015, Fancy Bear was linked to an intrusion into France's TV5 Monde. They gained network access using effective malware and hacking techniques (Radware 2024).   
* NotPetya Malware Attack In 2017, Fancy Bear was linked to the NotPetya malware attack. This was a damaging cyberattack that resulted in severe financial losses and disruption (Radware 2024).   
* Worldwide Anti-doping Agency The group has been linked to hacking and leak operations against the World Anti-doping Agency. This incident appeared to be retaliation for the International Olympic Committee's decision to ban Russia from competing in the 2018 Olympics due to performance-enhancing drug use (Radware 2024).   
* Brute-Force Attacks Authorities in the United States and the United Kingdom have warned that Fancy Bear is using a Kubernetes cluster to launch a global campaign of brute-force password-spraying attacks on hundreds of governments and private sector targets (Radware 2024).   
* Attacks on Ukrainians In July 2022, Fancy Bear sent malicious documents containing an exploit for a Microsoft zero-day vulnerability known as Follina (CVE-2022-30190), which targeted Ukrainians (Radware 2024).   
* Ukraine and NATO Countries The confrontation between Ukraine and Russia fuelled the new wave of attacks where APT28 was in the lead. During their latest research, Palo Alto discovered that the grouping had targeted infrastructure, energy, pipeline operations, government agencies, and member countries of NATO including Ukraine, Jordan, and the UAE by exploiting weaknesses within Outlook in 14 strategic intelligence-valued countries.  
* Cisco Routers Abused In April, Fancy Bear members exploited an RCE vulnerability (CVE-2017-6742) in Cisco routers' SNMP configuration. A joint alert by Western security agencies showed that attackers used this approach to backdoor Cisco routers around the world, including in Europe, US government institutions, and around 250 Ukrainian victims [(Levy, 2023\)](https://www.zotero.org/google-docs/?lVqria). 


On **July 10, 2025**, [**CERT-UA**](https://cert.gov.ua/) reported a phishing campaign targeting Ukraine's executive authorities. The emails impersonated government officials and included a **.pdf.zip archive** containing a disguised **.pif executable**, built using PyInstaller. The malware, dubbed **LAMEHUG**, is attributed with **moderate confidence to APT28** [(Telychko, 2025\)](https://www.zotero.org/google-docs/?6QicCG).

### APT28 Across the Cyber Kill Chain

In the following section, APT28 activities are examined based on Cyber Kill Chain framework. The analysis is cited by Mwiki et al. (2019).

**1\. Reconnaissance**  
APT28 begins its operations by identifying and profiling specific targets using open-source intelligence (OSINT). Their reconnaissance phase includes scanning for vulnerabilities in public-facing web applications—like cross-site scripting (XSS) or SQL injection points. Notably, between **February 10–14, 2015**, they scanned exactly **8,536,272 IP addresses** in Ukraine to identify weak spots. Their target selection is often manual and deliberate. For instance, one script they used had **11 IP classes hardcoded**, indicating pre-selection rather than random scanning. They’ve also exploited vulnerabilities like **CVE-2014-4114 (Sandworm)**, used against NATO, EU governments, and the Ukrainian administration.

**2\. Weaponization**  
Once intelligence is gathered, APT28 crafts payloads tailored to the vulnerabilities they've identified. This could include developing custom malware, using known exploits, or deploying tools purchased from third-party sources. They often spoof legitimate domain names to host malicious content. Their spear-phishing campaigns are backed by solid social engineering—using fake login portals or official-looking emails to lure users in. Weaponization is not rushed; the group’s funding and skilled operators allow them to invest time into preparing effective, targeted attacks.

**3\. Delivery**  
APT28 primarily delivers malware through phishing emails—often attaching malicious documents (DOC, RTF, DOCX) that exploit vulnerabilities in Microsoft Word or Adobe Flash. For example, in 2017, they used a Word document that exploited **CVE-2017-11292**, an Adobe Flash vulnerability. In another case, they sent out fake hotel reservation emails to distribute malware. They’ve also compromised websites commonly visited by targets and, in some cases, used USB removable media—as seen in February 2015—to deliver payloads directly in physically isolated environments.

**4\. Exploitation**  
The group is quick to adopt zero-day exploits. Their targets span multiple platforms: Windows, macOS, Linux, and Chrome OS. Exploits have included flaws in **Adobe Flash**, **Microsoft Word**, **Internet Explorer**, **Java Runtime Environment**, and **Windows kernel components**. One attack chain involved exploiting a Flash vulnerability to execute arbitrary code, which then triggered further privilege escalations. They’ve also used tools like the **Browser Exploitation Framework (BeEF)** to exploit legitimate websites and run browser-based attacks.

**5\. Installation**  
To maintain persistence, APT28 installs multi-layered backdoors. On Windows, they use techniques like modifying AutoStart extensibility point (ASEP) registry entries and deploying **kernel-mode rootkits** or **bootkits** that infect the Master Boot Record (MBR). On macOS, they use **XAgentOSX**, installed via a downloader called **Komplex**. Malicious Office documents might use a method called “Office test” to load Trojans every time an application is opened. The group takes extensive anti-forensic measures—like disabling crash logs and deleting traces with methods such as NSFileManager:removeFileAtPath.

**6\. Command and Control (C2)**  
Once installed, the malware communicates with APT28’s C2 infrastructure using protocols like **HTTP, SMTP, or POP3**. In one case, a dropper contacted a **primary C2 domain**, then downloaded components for secondary connections. FireEye researchers in 2017 observed a campaign using **Visual Basic macros** embedded in Word docs to reach C2 servers like **mvtband.net** and **mvband.net**—both later blacklisted. C2 traffic can be tunneled through proxies, direct connections, or browser injection to evade detection.

**7\. Actions on Objectives**  
APT28’s ultimate goals are intelligence collection, disruption, and long-term access. They’ve been linked to major incidents like the **2015 cyberattack on TV5Monde**, which temporarily knocked the French broadcaster off-air. They also exfiltrated athlete medical records from the **International Olympic Committee in 2016**, and harvested hotel guest data during a campaign targeting the **hospitality sector**. Their toolkit supports keylogging, email scraping, USB content harvesting, and file extraction—allowing them to steal and manipulate sensitive data at scale.  
More about DNC attack by APT28 \- https://www.crowdstrike.com/en-us/blog/bears-midst-intrusion-democratic-national-committee/

### Tactics, Techniques, and Procedures (TTPs)

| Malware Attacks  | The criminal group uses multiple types of malwares, including custom-built tools. APT28 is responsible for spreading malware such as Sofacy, X-Agent, Sednit, and Zebrocy. |
| :---- | :---- |
| Watering Hole Attacks | APT28 uses tactics to steal credentials, such as keyloggers or credential harvesting tools, to gain access to systems and networks. |
| Persistence Mechanisms | APT28 uses various types of mechanisms to keep long-term access to compromised systems. This could include building backdoors, running scheduled processes, or modifying system functions. |
| Domain Registration and Infrastructure | APT28 is known for registering domain names that resemble real ones, resulting in a false infrastructure for its operations. |
| Use of Virtual Private Servers (VPS) | The group uses VPS providers to host its command and control (C2) servers, which helps them hidden their tracks and makes traceability difficult. |
| Geopolitical Targeting | APT28's campaigns usually connect with geopolitical advances, which means that the group operates to support Russian official interests. |
| Phishing Techniques | They mostly register domain names that closely resemble those of the real organisations they intend to target, creating phishing sites that look and feel like the victim's web-based email services. This is done with the purpose of fooling victims into disclosing their credentials. |
| Zero-Day Attacks | APT28 is known for using zero-day vulnerabilities in its attacks. These are vulnerabilities that are unknown to people interested in mitigating them, including the target software's vendor. By exploiting these vulnerabilities before they are patched, APT28 can get unauthorised access to systems and data. |

Table: APT28 Tactics, Techniques, and Procedures [(Sam, 2024\)](https://www.zotero.org/google-docs/?gFnGCA)	

### Tools used by APT28

APT28 employs a diverse range of tools in its cyberespionage operations. These tools include Cannon, certutil, Computrace, CORESHELL, DealersChoice, Downdelph, Drovorub, Foozer, GooseEgg, Graphite, Headlace, HIDEDRV, Impacket, JHUHUGIT, Koadic, Komplex, LoJax, MASEPIE, Mimikatz, Nimcy, OCEANMAP, OLDBAIT, PocoDown, ProcDump, PythocyDbg, Responder, Sedkit, Sedreco, SkinnyBoy, SMBExec, STEELHOOK, USBStealer, VPNFilter, Winexe, WinIDS, X-Agent, X-Tunnel and Zebrocy . [(Cyble, 2025\)](https://www.zotero.org/google-docs/?meho98)

### Exploited Vulnerabilities 

The APT28 group has exploited various vulnerabilities in its campaigns. We have listed some important vulnerabilities targeted below: 

* CVE-2024-21413: Microsoft Outlook Remote Code Execution Vulnerability   
* CVE-2024-21413: Microsoft Exchange Server Elevation of Privilege Vulnerability   
* CVE-2023-23397: Microsoft Outlook Elevation of Privilege Vulnerability   
* CVE-2023-23397: Microsoft Outlook Information Disclosure Vulnerability   
* CVE-2023-38831: RARLAB WinRAR Code Execution Vulnerability   
* CVE-2022-38028: Windows Print Spooler Elevation of Privilege Vulnerability   
* CVE-2021-34527: Microsoft Windows Print Spooler Remote Code Execution Vulnerability   
* CVE-2021-1675: Microsoft Windows Print Spooler Remote Code Execution Vulnerability

National Cyber Security Centre UK has published the signatures and Indicators of Compromise (IoCs) to thwart activities of APT28 can be downloaded [here](https://www.ncsc.gov.uk/news/indicators-of-compromise-for-malware-used-by-apt28).

### Conclusion

The Sofacy APT group employs sophisticated, multifaceted attack strategies and persistence mechanisms. By exploiting a range of vulnerabilities, including those in Print Spooler, PrintNightmare, and WinRAR, they effectively infiltrate and maintain access to targeted systems. Their use of various scripts and malicious files, alongside leveraging legitimate services for C\&C communication, demonstrates their adaptability and resourcefulness in cyber espionage, posing a significant threat to global cybersecurity.

### References

[Cisco Talos. (2017, October 22). *“Cyber Conflict” Decoy Document Used In Real Cyber Conflict*. Cisco Talos Blog. https://blog.talosintelligence.com/cyber-conflict-decoy-document/](https://www.zotero.org/google-docs/?ZPamjp)   
[CrowdStrike. (2019, February). *Fancy Bear Hackers (APT28): Targets & Methods*. CrowdStrike.Com. https://www.crowdstrike.com/en-us/blog/who-is-fancy-bear/](https://www.zotero.org/google-docs/?ZPamjp)   
[Cyble. (2025, February). *Sofacy: Threat Actor Profile*. https://cyble.com/threat-actor-profiles/sofacy/\#elementor-toc\_\_heading-anchor-1](https://www.zotero.org/google-docs/?ZPamjp)   
[ESET. (2016, October). *Dissection of Sednit Espionage Group*. ESET. https://www.eset.com/afr/about/newsroom/press-releases-afr/research/dissection-of-sednit-espionage-group-1/](https://www.zotero.org/google-docs/?ZPamjp)   
[Falcone, B. L., Mike Harbison, Robert. (2018, February 28). Sofacy Attacks Multiple Government Entities. *Unit 42*. https://unit42.paloaltonetworks.com/unit42-sofacy-attacks-multiple-government-entities/](https://www.zotero.org/google-docs/?ZPamjp)   
[Levy, E. (2023, April 19). *APT28 Attacks on Cisco Routers: What We Know So Far*. Security Engineering Notebook. https://www.securityengineering.dev/apt28-cisco-routers-vulnerability-april-2023/](https://www.zotero.org/google-docs/?ZPamjp)   
[Microsoft Inc. (2024, January). *Threat Actor Forest Blizzard | Security Insider*. https://www.microsoft.com/en-us/security/security-insider/threat-landscape/forest-blizzard](https://www.zotero.org/google-docs/?ZPamjp)   
[MITRE ATT\&CK®. (2017, May 31). *APT28, Group G0007*. https://attack.mitre.org/groups/G0007/](https://www.zotero.org/google-docs/?ZPamjp)   
[Radware. (2024). *Fancy Bear (APT28) Threat Actor*. https://www.radware.com/cyberpedia/ddos-attacks/fancy-bear-apt28-threat-actor/](https://www.zotero.org/google-docs/?ZPamjp)   
[Sam, J. (2024). *A Research Report on Advanced Persistent Threat*.](https://www.zotero.org/google-docs/?ZPamjp)   
[SecureWorks. (2016). *Threat Group 4127 Targets Hillary Clinton Presidential Campaign*. Secureworks. https://www.secureworks.com/research/threat-group-4127-targets-hillary-clinton-presidential-campaign](https://www.zotero.org/google-docs/?ZPamjp)   
[Telychko, V. (2025, July 18). UAC-0001 (APT28) Attack Detection: The russia-Backed Actor Uses LLM-Powered LAMEHUG Malware to Target Security and Defense Sector. *SOC Prime*. https://socprime.com/blog/detect-uac-0001-attacks-with-lamehug-malware/](https://www.zotero.org/google-docs/?ZPamjp)   
[Trend Micro (US). (2019). *Pawn Storm’s Lack of Sophistication as a Strategy*. https://www.trendmicro.com/en\_us/research/20/l/pawn-storm-lack-of-sophistication-as-a-strategy.html](https://www.zotero.org/google-docs/?ZPamjp)   
[Trustwave. (2015, July 29). *Tsar Team Microsoft Office Zero Day CVE-2015-2424*. https://www.trustwave.com/en-us/resources/blogs/spiderlabs-blog/tsar-team-microsoft-office-zero-day-cve-2015-2424/](https://www.zotero.org/google-docs/?ZPamjp) 
