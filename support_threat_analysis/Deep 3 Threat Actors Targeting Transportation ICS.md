[[MITRE]]
[[Glydways]]
[[Transportation]]
[[threat model]]
[[Glydways MITRE Threat Model]]

## Background

Subject: Glydways MITRE Threat Model
Author: Jim Mckenney
Date of last revision: 2024-12-27
Version:  .03
# Emerging Threat Actors Targeting Transportation ICS

The transportation sector is increasingly reliant on Industrial Control Systems (ICS) to manage and operate critical infrastructure, including railway systems, traffic management, and maritime navigation. This reliance has made the sector a prime target for cyberattacks, with threat actors seeking to disrupt operations, steal data, or cause physical damage. This report investigates emerging threat actors targeting transportation ICS and their known Tactics, Techniques, and Procedures (TTPs) using publicly available information.

## Recent Cyberattacks Targeting Transportation ICS

Recent cyberattacks demonstrate the growing threat to transportation ICS. In one instance, Iranian government-affiliated and pro-Russia actors gained access to and, in some cases, manipulated critical US industrial control systems (ICS) in various sectors, including food and agriculture, healthcare, and water and wastewater systems in late 2023 and 20241. These attacks highlight the potential for malicious actors to cause physical damage and deny critical services within these sectors. Outdated software, poor password security, the use of default credentials, and limited resources for system updates render ICS devices vulnerable to compromise, as they are commonly connected to corporate IT networks and increasingly to the Internet1. For example, in November 2023, IRGC-affiliated actors operating under the Cyber Av3ngers persona gained access to the Israeli-made Unitronics Series ICS PLCs in multiple US entities, mostly water and wastewater systems, and defaced the PLCs' touch screens with an anti-Israel message1. In response to the defacement, a few of the water-sector victims briefly shut down their systems and switched to manual operations1. Pro-Russia hacktivists also compromised several water plants and claimed to compromise two dairies, remotely manipulating control systems within these facilities1.

In another incident, a cyberattack disrupted Elron's ticketing system in September 2023, impacting sales at train terminals, onboard trains, and online purchases2. Passengers were permitted to travel for free or pay in cash to the train attendant2. While this attack was linked to Distributed Denial of Service (DDoS) attacks on Rindago, a third-party ticketing system provider, by individuals expressing support for Russia, the attackers' specific affiliation or motivation remains unclear2. This incident highlights the vulnerability of transportation systems to cyberattacks and the potential for disruption of essential services.

The transportation and logistics sector experienced 27 publicly reported cyber incidents between July 2023 and July 2024, second only to the manufacturing sector2. These attacks resulted in data loss for companies like the Belt Railway Company of Chicago, Welsh haulage company Owens Group, and Australian fuel distributor North Coast Petroleum2.

Several companies in the transportation and logistics sector have been victims of cyberattacks, including GCA, AB Texel, and Radiant Logistics3. These attacks underscore the vulnerability of this sector and the need for robust cybersecurity measures.

Another notable attack involved the emergence of FrostyGoop malware in August 20244. This malware targets control systems that utilize ModbusTCP communications, a common industrial protocol4. FrostyGoop is the first reported ICS malware to successfully exploit ModbusTCP for control system manipulation, demonstrating a concerning evolution in ICS malware capabilities4.

## Known Threat Actors Targeting Transportation ICS


|Threat Actor Type|Motivation|Example TTPs|
|---|---|---|
|Cybercriminals|Financial gain|Ransomware, data theft, extortion|
|Nation-state actors|Geopolitical advantage, espionage|Disrupting critical infrastructure, intelligence gathering|
|Hacktivists|Social or political activism|Disrupting services, website defacement|

Several known threat actors pose a significant risk to transportation ICS. These include:

- Earth Centaur (Tropic Trooper): This long-running cyberespionage group has been active since 2011, targeting transportation companies and government agencies related to transportation5. Their tactics include exploiting vulnerabilities, conducting Active Directory (AD) discovery, spreading tools via Server Message Block (SMB), and using intranet penetration tools to establish connections with their command-and-control (C&C) servers5.
    
- Dragonfly/Energetic Bear: This group, suspected of having Russian affiliations, targets energy and utility companies in Europe and North America6. They employ HAVEX malware, designed for targeting ICS within critical infrastructure sectors6.
    
- XENOTIME: Linked to cyberattacks on critical infrastructure in the Middle East, particularly in the oil and gas sectors6. They deployed TRISIS (Triton) malware to infiltrate industrial safety systems6.
    
- Unit 29155: This group targets critical infrastructure and key resource sectors, including transportation systems, of NATO members, the EU, Central American, and Asian countries7. They engage in website defacements, infrastructure scanning, data exfiltration, and data leaking7. Their TTPs include exploiting public-facing applications using known vulnerabilities (e.g., CVE-2021-33044, CVE-2021-33045, CVE-2022-26134, and CVE-2022-26138), targeting IP ranges within government and critical infrastructure organizations, and using default accounts to authenticate to devices like IP cameras8.
    

As Operational Technology (OT) and Information Technology (IT) converge, attacks that begin on the corporate network and pivot to compromise critical physical environments will likely increase9. This convergence expands the attack surface and requires organizations to adopt a more holistic approach to cybersecurity.

## Emerging Threat Actors and Trends in Transportation ICS

While known threat actors continue to pose a risk, new and emerging actors are also entering the landscape. These actors often exhibit evolving TTPs and increasing sophistication, making them a significant concern for transportation cybersecurity10.

One example is the Ransomhub Group, which emerged in February 202411. This Ransomware-as-a-Service (RaaS) group targets ICS, as demonstrated by their attack on a Spanish bioenergy plant11. The rise of RaaS models lowers the barrier to entry for cybercriminals, potentially leading to an increase in ransomware attacks against transportation ICS.

Another emerging threat is the increasing use of ransomware specifically targeting ICS12. This trend poses a severe risk as it can disrupt essential services and cause catastrophic consequences12. There has been an increase in ICS-centric malware in recent years, especially following the Russo-Ukrainian war10.

## TTPs Used by Threat Actors Targeting Transportation ICS

Threat actors employ various TTPs to target transportation ICS, including:

- Phishing: A common tactic used to deliver malware or steal credentials. Attackers often craft sophisticated phishing emails that impersonate trusted entities or use social engineering techniques to trick victims into clicking malicious links or opening infected attachments13. For example, a campaign targeting transportation and logistics organizations in North America involved compromising email accounts and injecting malicious content into existing conversations13. The attackers impersonated software typically used for transport and fleet operations management, such as Samsara, AMB Logistic, and Astra TMS, to deliver malware like Arechclient2, DanaBot, Lumma Stealer, NetSupport, and StealC14.
    
- Exploiting vulnerabilities: Threat actors exploit known vulnerabilities in ICS software and hardware to gain access to systems and networks1. Outdated software, poor password security, and the use of default credentials increase vulnerability to these attacks1. Securing the software supply chain is crucial, as attackers often target vulnerabilities in commonly used software to compromise multiple organizations14.
    
- Malware: Various malware families are used to target transportation ICS, including info stealers, backdoors, and ransomware14. These malware can disrupt operations, steal data, and provide attackers with persistent access to systems14.
    
- Reconnaissance: Before launching attacks, threat actors conduct extensive reconnaissance to gather information about their targets15. This includes identifying vulnerable systems, mapping network architecture, and understanding operational processes15.
    
- Brute force attacks: Attackers use brute force techniques to guess passwords and gain unauthorized access to systems16.
    
- ClickFix: This social engineering technique tricks victims into copying and running malicious PowerShell scripts by convincing them it will "fix a technical problem"17.
    

## OSINT Sources for Threat Intelligence on Transportation ICS

OSINT plays a crucial role in gathering threat intelligence on transportation ICS. Various sources provide valuable information, including:

- Security websites and blogs: Websites like SecurityWeek, SANS Institute, and Dark Reading publish articles and reports on cybersecurity threats, vulnerabilities, and attack trends4.
    
- Government agencies: Organizations like CISA and the DNI release advisories, reports, and threat assessments on cyber threats to critical infrastructure, including transportation systems1.
    
- Industry reports: Cybersecurity companies like Dragos and Kaspersky publish research reports and threat intelligence on ICS threats and vulnerabilities4.
    
- Open-source threat intelligence platforms: Platforms like SpiderFoot and TheHarvester can be used to gather information about threat actors, malware, and vulnerabilities from various online sources18.
    
- Social media: Social media platforms can provide insights into threat actor activity, discussions, and trends19.
    

## Analysis of Trends and Patterns

Analyzing the information gathered from various sources reveals several key trends and patterns in the threat landscape targeting transportation ICS:

- Increasing use of ransomware: Ransomware attacks are becoming more prevalent, with threat actors specifically targeting ICS to disrupt operations and extort ransoms. The rise of RaaS models further contributes to this trend by lowering the barrier to entry for cybercriminals.
    
- Targeting of specific vulnerabilities: Threat actors exploit known vulnerabilities in ICS software and hardware, highlighting the importance of timely software updates, strong password security, and secure configuration practices.
    
- Sophisticated phishing techniques: Attackers employ sophisticated social engineering techniques and impersonation tactics to deceive employees in the transportation sector and gain access to sensitive information or deliver malware.
    
- Convergence of IT and OT networks: The increasing convergence of IT and OT networks expands the attack surface for threat actors, requiring organizations to adopt a more holistic and integrated approach to cybersecurity.
    

## Conclusion

The threat to transportation ICS is real and growing. Emerging threat actors, evolving TTPs, and the increasing sophistication of attacks require a proactive and vigilant approach to cybersecurity. The evolving threat landscape, characterized by the increasing use of ransomware, the targeting of specific vulnerabilities, and sophisticated phishing techniques, presents unique challenges for the transportation industry. Organizations in this sector must prioritize a multi-layered security approach that combines strong cybersecurity measures with proactive threat intelligence gathering and incident response planning. This includes:

- Implement strong cybersecurity measures: This includes multifactor authentication, strong passwords, regular software updates, network segmentation, and secure configuration practices.
    
- Monitor networks and systems for suspicious activity: Employing intrusion detection and prevention systems and security information and event management (SIEM) tools can help identify and respond to threats.
    
- Gather and analyze threat intelligence: Utilize OSINT and other sources to stay informed about emerging threats, vulnerabilities, and attack trends.
    
- Develop incident response plans: Prepare for potential cyberattacks by developing and regularly testing incident response plans.
    
- Collaborate with industry partners and government agencies: Share information and best practices to improve overall cybersecurity posture.
    

By taking these steps, transportation organizations can strengthen their defenses and mitigate the risk of cyberattacks against their critical ICS infrastructure.

#### Works cited

1. Recent Cyber Attacks on US Infrastructure Underscore Vulnerability of Critical US Systems, November 2023–April 2024, accessed December 27, 2024, [https://www.dni.gov/files/CTIIC/documents/products/Recent_Cyber_Attacks_on_US_Infrastructure_Underscore_Vulnerability_of_Critical_US_Systems-June2024.pdf](https://www.dni.gov/files/CTIIC/documents/products/Recent_Cyber_Attacks_on_US_Infrastructure_Underscore_Vulnerability_of_Critical_US_Systems-June2024.pdf)

2. 14 recent cyber attacks on the transport & logistics sector - Wisdiam, accessed December 27, 2024, [https://wisdiam.com/publications/recent-cyber-attacks-transport-logistics-sector/](https://wisdiam.com/publications/recent-cyber-attacks-transport-logistics-sector/)

3. Q1 2024 – a brief overview of the main incidents in industrial cybersecurity, accessed December 27, 2024, [https://ics-cert.kaspersky.com/publications/reports/2024/06/03/q1-2024-a-brief-overview-of-the-main-incidents-in-industrial-cybersecurity/](https://ics-cert.kaspersky.com/publications/reports/2024/06/03/q1-2024-a-brief-overview-of-the-main-incidents-in-industrial-cybersecurity/)

4. What's the Scoop on FrostyGoop: The Latest ICS Malware and ICS Controls Considerations, accessed December 27, 2024, [https://www.sans.org/blog/whats-the-scoop-on-frostygoop-the-latest-ics-malware-and-ics-controls-considerations/](https://www.sans.org/blog/whats-the-scoop-on-frostygoop-the-latest-ics-malware-and-ics-controls-considerations/)

5. Collecting In the Dark: Tropic Trooper Targets Transportation and Government - Trend Micro, accessed December 27, 2024, [https://www.trendmicro.com/en_us/research/21/l/collecting-in-the-dark-tropic-trooper-targets-transportation-and-government-organizations.html](https://www.trendmicro.com/en_us/research/21/l/collecting-in-the-dark-tropic-trooper-targets-transportation-and-government-organizations.html)

6. Protecting Critical Infrastructure: Defending Against Threats to OT/ICS Systems, accessed December 27, 2024, [https://www.criticalstart.com/protecting-critical-infrastructure-defending-against-threats-to-ot-ics-systems/](https://www.criticalstart.com/protecting-critical-infrastructure-defending-against-threats-to-ot-ics-systems/)

7. Feds Warn on Russian Actors Targeting Critical Infrastructure - Dark Reading, accessed December 27, 2024, [https://www.darkreading.com/ics-ot-security/feds-warn-russian-actors-targeting-critical-infrastructure](https://www.darkreading.com/ics-ot-security/feds-warn-russian-actors-targeting-critical-infrastructure)

8. Russian Military Cyber Actors Target US and Global Critical Infrastructure - CISA, accessed December 27, 2024, [https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-249a](https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-249a)

9. Cybersecurity in Transportation | Risks and Challenges - Darktrace, accessed December 27, 2024, [https://darktrace.com/cyber-ai-glossary/cybersecurity-in-transportation](https://darktrace.com/cyber-ai-glossary/cybersecurity-in-transportation)

10. Over 145,000 Industrial Control Systems Across 175 Countries Found Exposed Online, accessed December 27, 2024, [https://thehackernews.com/2024/11/over-145000-industrial-control-systems.html](https://thehackernews.com/2024/11/over-145000-industrial-control-systems.html)

11. Ransomhub Group Strikes Industrial Control Systems (ICS) - The Cyber Express, accessed December 27, 2024, [https://thecyberexpress.com/ransomhub-group-strikes-ics/](https://thecyberexpress.com/ransomhub-group-strikes-ics/)

12. ICS OT Security: Current Threats and Solutions, accessed December 27, 2024, [https://www.ssh.com/academy/operational-technology/ics-ot-security-current-threats-and-solutions](https://www.ssh.com/academy/operational-technology/ics-ot-security-current-threats-and-solutions)

13. Transport, Logistics Orgs Hit by Stealthy Phishing Gambit - Dark Reading, accessed December 27, 2024, [https://www.darkreading.com/threat-intelligence/transport-logistics-stealthy-phishing](https://www.darkreading.com/threat-intelligence/transport-logistics-stealthy-phishing)

14. US Transportation and Logistics Firms Targeted With Infostealers, Backdoors, accessed December 27, 2024, [https://www.securityweek.com/us-transportation-and-logistics-firms-targeted-with-infostealers-backdoors/](https://www.securityweek.com/us-transportation-and-logistics-firms-targeted-with-infostealers-backdoors/)

15. PRC State-Sponsored Actors Compromise and Maintain Persistent Access to U.S. Critical Infrastructure | CISA, accessed December 27, 2024, [https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-038a](https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-038a)

16. IRGC-Affiliated Cyber Actors Exploit PLCs in Multiple Sectors ... - CISA, accessed December 27, 2024, [https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-335a](https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-335a)

17. APT and financial attacks on industrial organizations in Q3 2024 | Kaspersky ICS CERT, accessed December 27, 2024, [https://ics-cert.kaspersky.com/publications/reports/2024/12/26/apt-and-financial-attackson-industrial-organizationsin-q3-2024/](https://ics-cert.kaspersky.com/publications/reports/2024/12/26/apt-and-financial-attackson-industrial-organizationsin-q3-2024/)

18. 10 Best OSINT Research Tools for Threat Intelligence - Kapeed - Medium, accessed December 27, 2024, [https://kapeedaryal.medium.com/10-best-osint-research-tools-for-threat-intelligence-ef05d68cc9fd](https://kapeedaryal.medium.com/10-best-osint-research-tools-for-threat-intelligence-ef05d68cc9fd)

19. What is OSINT (Open-Source Intelligence?) - SANS Institute, accessed December 27, 2024, [https://www.sans.org/blog/what-is-open-source-intelligence/](https://www.sans.org/blog/what-is-open-source-intelligence/)

**