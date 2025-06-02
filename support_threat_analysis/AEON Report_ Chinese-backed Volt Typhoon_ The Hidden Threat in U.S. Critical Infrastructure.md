\# Chinese-backed Volt Typhoon: The Hidden Threat in U.S. Critical Infrastructure

This report examines Volt Typhoon, a sophisticated Chinese state-sponsored threat actor that has strategically pre-positioned itself within U.S. critical infrastructure networks. Since its discovery in 2023, this adversary has employed stealthy living-off-the-land techniques to maintain persistent access to communications, energy, transportation, and water systems. By analyzing Volt Typhoon's tactics, victimology, and potential impact, this report provides critical insights into defending against a threat designed not just for espionage, but potentially for disruption during geopolitical crises.

\#\# Discovery and Initial Reports of Volt Typhoon

\*\*Volt Typhoon is a state-sponsored threat known for covertly pre-positioning within US critical infrastructure networks using living-off-the-land tactics.\*\* Initial detection came from Microsoft in May 2023, which uncovered stealthy operations targeting key infrastructure sectors. Subsequent investigations by CISA, NSA, and FBI confirmed that this threat actor had compromised IT networks in sectors such as communications, energy, transportation, and water across the continental United States and territories like Guam.

The threat actor exploits vulnerabilities in end-of-life SOHO devices—routers, firewalls, and VPN hardware—to gain initial access. Once inside a network, they use native administrative tools (LOLBins), abuse valid credentials, and conduct hands-on keyboard activity to maintain persistence without generating typical malware signatures. For example, Microsoft’s analysis highlighted the use of PowerShell and command-line tools to dump LSASS memory and create domain controller installation media. This behavior is atypical for standard espionage, as the focus is on pre-positioning for potential future disruptive attacks should a major crisis arise between the US and the People’s Republic of China.

Key technical methods used by Volt Typhoon include:

\- Exploiting unpatched, publicly exposed network devices    
\- Utilizing living-off-the-land tools to avoid detection    
\- Maintaining long-term undiscovered access to enable lateral movement toward operational technology systems

Such tactics underscore the strategic intent to not immediately exfiltrate data but to position the actor for potential sabotage. This report highlights that while attribution to the PRC remains based on observed tactics and patterns, the persistent and adaptive nature of Volt Typhoon marks it as a significant risk to critical infrastructure in the event of escalating geopolitical tensions.

\#\#\# Sources  
\- Volt Typhoon targets US critical infrastructure with living-off-the-land techniques | Microsoft Security Blog, May 24, 2023 : https://www.microsoft.com/en-us/security/blog/2023/05/24/volt-typhoon-targets-us-critical-infrastructure-with-living-off-the-land-techniques/  
\- PRC State-Sponsored Cyber Threat | CISA : https://www.cisa.gov/topics/cyber-threats-and-advisories/nation-state-cyber-actors/china  
\- U.S. Government Disrupts Botnet People’s Republic of China Used to Conceal Hacking of Critical Infrastructure | DOI, Jan 31, 2024 : https://www.justice.gov/archives/opa/pr/us-government-disrupts-botnet-peoples-republic-china-used-conceal-hacking-critical

\#\# Volt Typhoon Infiltration and Persistence Methods

\*\*Volt Typhoon employs highly sophisticated, stealthy techniques to gain and maintain long-term access to target systems.\*\* The adversary begins with thorough reconnaissance, using open-source tools to gather intelligence on network architecture, security controls, and key personnel. They identify vulnerable public-facing devices, such as Fortinet FortiGuard appliances, and exploit known or zero-day vulnerabilities to gain initial access. Stolen valid credentials play a significant role in their entry strategy, granting them immediate footholds within critical infrastructure.

For execution, Volt Typhoon relies on native operating system tools—often referred to as living-off-the-land (LOTL) techniques—to blend malicious commands with legitimate activity. They use command-line utilities like PowerShell, WMIC, and netsh to execute payloads, collect system data, and pivot within the network without triggering standard detection systems. Persistence is maintained by deploying web shells, scheduled tasks, and reusing compromised administrations so that access remains undetected over extended periods.

Privilege escalation is achieved by exploiting insecurely stored credentials and vulnerabilities in operating system components, allowing the group to extract critical files such as the Active Directory database through volume shadow copies. Lateral movement is conducted using remote access tools and valid credentials, enabling deep network exploration and discovery. Data collection occurs through systematic aggregation, followed by compression and encryption of sensitive information for exfiltration.

Key phases of their operation include:  
\- Reconnaissance    
\- Initial Access    
\- Execution & Persistence    
\- Privilege Escalation    
\- Lateral Movement    
\- Data Collection  

An observed case involves exploiting vulnerabilities on Fortinet devices to infiltrate systems and then leveraging LOTL tactics to maintain stealthy control.

\#\#\# Sources  
\- Volt Typhoon targets US critical infrastructure with living-off-the-land techniques, May 24, 2023 : https://www.microsoft.com/en-us/security/blog/2023/05/24/volt-typhoon-targets-us-critical-infrastructure-with-living-off-the-land-techniques/  
\- PRC State-Sponsored Actors Compromise and Maintain Persistent Access to U.S. Critical Infrastructure, Feb 07, 2024 : https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-038a

\#\# Examination of Sectors and Organizational Impact of Volt Typhoon Activity

\*\*Critical infrastructure sectors in the United States face uniquely targeted and persistent cyber threats from Volt Typhoon.\*\* This threat actor, believed to be state-sponsored, has systematically exploited vulnerabilities in IT and OT environments since mid-2021. The group utilizes stealthy, living-off-the-land techniques to infiltrate networks and maintain prolonged undetected access, aiming to gather intelligence and potentially disrupt critical communications.

Volt Typhoon’s operations have notably impacted sectors such as communications, manufacturing, energy, transportation, construction, and education. A detailed case study involves critical infrastructure in Guam, where the group was observed embedding malware into systems that support military communications. This not only raises concerns regarding espionage but also underscores the potential for cascading disruption during geopolitical crises.

Key aspects of their attack methodology include exploiting insecure public-facing devices, using valid credentials for lateral movement, and employing command-line utilities to execute exploratory and credential-dumping tasks. The actor’s ability to proxy traffic through compromised SOHO equipment further complicates detection. To summarize, affected organizations are advised to implement strict patch management, enforce multi-factor authentication, and monitor for anomalous process behaviors and network logins.

A practical list of targeted sectors includes:  
\- Communications and information technology    
\- Energy and utilities    
\- Transportation and logistical networks    
\- Construction and maritime services  

Robust detection, incident response planning, and cross-sector collaboration are essential to mitigate the broad and evolving impacts of Volt Typhoon’s activities.

\#\#\# Sources  
\- Volt Typhoon targets US critical infrastructure with living-off-the-land techniques, Microsoft Security Blog, May 24, 2023 : https://www.microsoft.com/en-us/security/blog/2023/05/24/volt-typhoon-targets-us-critical-infrastructure-with-living-off-the-land-techniques/  
\- Securing U.S. Infrastructure Amid Volt Typhoon Threat, Georgetown SCS, May 24, 2023 : https://scs.georgetown.edu/news-and-events/article/9453/securing-us-infrastructure-amid-volt-typhoon-threat  
\- PRC State-Sponsored Actors Compromise and Maintain Persistent Access to U.S. Critical Infrastructure, CISA, Feb 07, 2024 : https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-038a  
\- What Is Volt Typhoon? A Cybersecurity Expert Explains The Chinese Hackers Targeting US Critical Infrastructure, UMBC, Apr 01, 2024 : https://umbc.edu/stories/what-is-volt-typhoon-a-cybersecurity-expert-explains-the-chinese-hackers-targeting-us-critical-infrastructure/

\#\# Counter-Narrative Analysis: Volt Typhoon Attribution

\*\*Chinese sources assert that attributing Volt Typhoon as a state-sponsored actor is based on ambiguous analysis and politically motivated narratives.\*\* Chinese technical teams argue that the observed malicious samples do not exhibit the sophisticated hallmarks of state-backed operations but instead bear strong similarities to cybercrime group tactics. Their analyses point out that the indicators of compromise and “living off the land” behaviors are common among financially motivated criminals. In one case study, Chinese researchers demonstrated that behavioral patterns in sample breaches aligned more with established cybercrime rings than with coordinated state-sponsored intrusion efforts.

Chinese reports offer several key points challenging the prevailing U.S. narrative:    
\- \*\*Sample Behavior:\*\* Investigations reveal that the operational methods and execution techniques mirror those used by criminal groups rather than a nation’s intelligence apparatus.    
\- \*\*Evidence Gaps:\*\* The U.S. advisories and associated reports often lack detailed source-tracing and rigorous attribution protocols, leading to premature conclusions.    
\- \*\*Political Motivation:\*\* The counter-narrative suggests that the heightened emphasis on Volt Typhoon may serve U.S. political and budgetary interests by justifying increased cybersecurity investments and diverting attention from domestic issues.

This counter-position not only questions the technical rigor of attribution but also highlights the strategic use of cyber threat narratives in international politics. By dissecting the evidence through a technical lens, Chinese experts encourage re-examination of attribution practices and caution against conflating cyber espionage with prepositioned disruptive capabilities.

\#\#\# Sources    
\- US hypes up 'Volt Typhoon' false narrative to smear China, 2024-04-15 : https://global.chinadaily.com.cn/a/202404/15/WS661c956fa31082fc043c2023.html    
\- China’s Influence Ops | Twisting Tales of Volt Typhoon at Home and Abroad, 2024 : https://www.sentinelone.com/labs/chinas-influence-ops-twisting-tales-of-volt-typhoon-at-home-and-abroad/    
\- Volt Typhoon II: A Secret Disinformation Campaign, 2024-07-08 : https://www.cverc.org/head/zhaiyao/futetaifengerEN.pdf    
\- A Tale of Two Typhoons: Properly Diagnosing Chinese Cyber Threats, 2025-02 : https://warontherocks.com/2025/02/a-tale-of-two-typhoons-properly-diagnosing-chinese-cyber-threats/

\#\# Recommendations and Strategies

\*\*Layered defenses built on timely patch management, strong multi-factor authentication, segregation of critical networks, and rigorously tested incident response plans are essential to counter advanced threats like Volt Typhoon.\*\* Organizations must prioritize patching vulnerabilities on internet-facing systems, particularly for devices such as routers and VPN appliances that are frequently exploited. For example, one reported incident involved a Fortinet firewall vulnerability that was mitigated by accelerating patch deployment and isolating the affected asset through network segmentation.

Regular application of phishing-resistant MFA impedes unauthorized credential use and lateral movement. Comprehensive logging and centralized monitoring further facilitate early detection of anomalous activities associated with living-off-the-land techniques. By correlating logs from endpoints, network devices, and critical IT assets, defenders can rapidly identify suspicious behaviors such as LSASS dumping or unusual remote desktop sessions.

A short list of key defensive measures includes:  
\- \*\*Timely patch management:\*\* Prioritize updates for internet-facing systems and legacy devices.  
\- \*\*Phishing-resistant MFA:\*\* Enforce MFA using hardware security keys or advanced authentication methods.  
\- \*\*Network segmentation:\*\* Isolate IT and OT networks to confine potential breaches.  
\- \*\*Centralized logging and monitoring:\*\* Enable detailed and centralized logging for rapid incident detection.  
\- \*\*Regular incident response exercises:\*\* Test incident response plans using realistic OT scenarios to validate readiness.

Integrating these practices creates multiple choke points that delay or thwart adversaries, reducing operational risk and maintaining continuity of critical infrastructure services.

\#\#\# Sources  
\- Volt Typhoon Explained: Living Off the Land Tactics for Cyber Espionage, December 23, 2024 : https://www.picussecurity.com/resource/blog/volt-typhoon-living-off-the-land-cyber-espionage    
\- PRC State-Sponsored Actors Compromise and Maintain Persistent Access to U.S. Critical Infrastructure, February 07, 2024 : https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-038a    
\- Volt Typhoon: Cybersecurity Risks and Strategies for Financial Institutions, September 30, 2024 : https://conetrix.com/blog/volt-typhoon-cybersecurity-risks-and-strategies-for-financial-institutions

\#\# Conclusion

Volt Typhoon represents a sophisticated threat actor with apparent ties to the People's Republic of China, strategically pre-positioning within U.S. critical infrastructure networks. Their operations are characterized by stealthy living-off-the-land techniques that leverage legitimate administrative tools, minimizing malware signatures and enabling prolonged undetected access. While attribution remains contested by Chinese sources, the technical evidence points to a coordinated campaign targeting communications, energy, transportation, and water systems with potential for future disruptive operations during geopolitical crises.

Effective protection against these threats requires:  
\- Prioritized patching of internet-facing systems and SOHO devices  
\- Implementation of phishing-resistant multi-factor authentication  
\- Network segmentation between IT and OT environments  
\- Enhanced logging and monitoring for early detection  
\- Regular testing of incident response capabilities

Organizations must recognize that these persistent advanced threats require a defense-in-depth approach with cross-sector collaboration to protect national critical infrastructure.