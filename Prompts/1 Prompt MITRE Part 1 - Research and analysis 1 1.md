
Define = ((subject))
## Context
This a comprehensive prompt designed to guide a "subject" (which could be a person or an AI) through the process of creating a detailed and well-aligned MITRE ATT&CK threat model report for ((subject)) including a second-stage research phase:

**Comprehensive Prompt: ((subject)) Cybersecurity Threat Model Report**

**Objective:**

To create a comprehensive and well-aligned cybersecurity threat model report for ((subject)), a novel automated transit system, using the MITRE ATT&CK framework for ICS, the EMB3D Threat Model for embedded systems, and open-source intelligence (OSINT). The report must be detailed, accurate, and actionable, providing ((subject)) with a robust understanding of its cybersecurity risks and mitigation strategies.

**Phase 1: Initial Research and Report Generation**

**Instructions:**

1.  **Report Structure:** Follow the provided report template (see below) to structure your report. Each section must be addressed thoroughly.
2.  **Information Gathering:** Use the following prompts to guide your research and content generation for each section.
3.  **OSINT:** Utilize open-source intelligence (OSINT) techniques to gather information on relevant cyber threats, vulnerabilities, and threat actors.
4.  **Frameworks:** Apply the MITRE ATT&CK framework for ICS and the EMB3D Threat Model for embedded systems.
5.  **Citations:** Properly cite all sources using a consistent citation style.
6.  **Analysis:** Provide detailed analysis and reasoning for all claims and recommendations.
7.  **Clarity:** Ensure the report is clear, concise, and easily understandable for a technical audience.

**Report Template & Prompts:**

*   **Executive Summary:**
    *   **Outline:** 1.1. Purpose of the Report; 1.2. Scope of the Assessment; 1.3. Key Findings; 1.4. Recommendations
    *   **Prompt:** "Summarize the purpose of this report, highlighting the need for a cybersecurity threat model for ((subject)). Briefly describe the scope of the assessment, including the systems and technologies covered. Provide a high-level overview of the most significant threats and vulnerabilities identified. Conclude with a summary of key mitigation strategies and recommendations for the design team. Cross-reference sections where appropriate."
*   **Introduction:**
    *   **Outline:** 2.1. Background on ((subject)); 2.2. Importance of Cybersecurity; 2.3. Report Objectives
    *   **Prompt:** "Introduce the ((subject)) system, its goals, and its operational context. Emphasize the critical need for robust cybersecurity in advanced transportation systems. Explain the importance of protecting critical infrastructure. Clearly state the objectives of this threat model report, including the frameworks and methodologies used."
*   **Methodology:**
    *   **Outline:** 3.1. MITRE ATT&CK Framework; 3.2. EMB3D Threat Model; 3.3. OSINT Gathering; 3.4. Threat Modeling Process; 3.5. Assumptions and Limitations
    *   **Prompt:** "Explain the MITRE ATT&CK framework for ICS and its relevance to ((subject)). Introduce the EMB3D model and its application to embedded systems within the ((subject)) infrastructure. Describe the OSINT sources and techniques used to gather information. Outline the steps taken to identify, analyze, and prioritize threats. Acknowledge any assumptions and limitations in the assessment."
*   **((subject)) System Overview:**
    *   **Outline:** 4.1. System Architecture (4.1.1. Operations Control Center (OCC), 4.1.2. ((subject)), 4.1.3. Guideways and Infrastructure, 4.1.4. Communication Networks); 4.2. Operational Roles (4.2.1. Capacity Planners, 4.2.2. Garage Staff, 4.2.3. External Stakeholders); 4.3. Potential Operational Disruptions (4.3.1. Physical Intrusions, 4.3.2. In-Vehicle Incidents, 4.3.3. Environmental Factors, 4.3.4. Maintenance Requirements)
    *   **Prompt:** "Provide a detailed description of the ((subject)) system, including its components and their interactions. Describe the functions and personnel roles within the Operations Control Center (OCC). Explain the autonomous vehicles (((subject))) and their onboard systems. Detail the physical and digital infrastructure of the guideways. Describe the communication networks used by the system. Outline the operational roles and their access levels. Identify potential operational disruptions and security concerns."
*   **Threat Landscape Analysis:**
    *   **Outline:** 5.1. Overview of Transportation ICS Threats (5.1.1. Ransomware Attacks, 5.1.2. Data Breaches, 5.1.3. DDoS Attacks, 5.1.4. Supply Chain Attacks); 5.2. Emerging Threat Actors (5.2.1. Nation-State Actors, 5.2.2. Cybercriminals, 5.2.3. Hacktivists); 5.3. OSINT Analysis (5.3.1. Case Studies, 5.3.2. TTPs, 5.3.3. Vulnerability Trends)
    *   **Prompt:** "Analyze the current threat landscape for transportation ICS. Describe common threats, such as ransomware, data breaches, DDoS attacks, and supply chain attacks. Identify emerging threat actors, such as nation-state actors, cybercriminals, and hacktivists. Present findings from OSINT, including case studies, TTPs, and vulnerability trends relevant to ((subject))."
*   **MITRE ATT&CK Mapping for ((subject)):**
    *   **Outline:** 6.1. Specialized Applications and Protocols; 6.2. Mapping TTPs to ((subject)) (6.2.1. Initial Access, 6.2.2. Execution, 6.2.3. Persistence, 6.2.4. Privilege Escalation, 6.2.5. Evasion, 6.2.6. Discovery, 6.2.7. Lateral Movement, 6.2.8. Collection, 6.2.9. Command and Control, 6.2.10. Inhibit Response Function, 6.2.11. Impair Process Control, 6.2.12. Impact); 6.3. Prioritized Threats
    *   **Prompt:** "Apply the MITRE ATT&CK framework for ICS to the ((subject)) system. Analyze the impact of specialized applications and protocols. Map specific TTPs to ((subject))' infrastructure, covering all stages of the attack lifecycle. Prioritize threats based on likelihood and potential impact, providing a rationale for your prioritization."
*   **EMB3D Threat Model Application:**
    *   **Outline:** 7.1. Embedded System Vulnerabilities (7.1.1. Onboard Vehicle Systems, 7.1.2. Infrastructure Components); 7.2. Mapping EMB3D to ((subject)) (7.2.1. Device Properties, 7.2.2. Vulnerability Enumeration, 7.2.3. Mitigation Strategies)
    *   **Prompt:** "Apply the EMB3D Threat Model to the ((subject)) system. Analyze vulnerabilities in embedded devices, including onboard vehicle systems and infrastructure components. Map threats to specific device properties using the EMB3D model. Enumerate potential threat exposures and propose specific security measures for embedded devices."
*   **Security Recommendations for ((subject)):**
    *   **Outline:** 8.1. Design-Phase Security (8.1.1. Secure Development Practices, 8.1.2. Threat Modeling Integration, 8.1.3. Secure Configuration); 8.2. Operational Security (8.2.1. Access Controls, 8.2.2. Network Segmentation, 8.2.3. Intrusion Detection and Prevention, 8.2.4. Data Protection, 8.2.5. Incident Response, 8.2.6. Supply Chain Security, 8.2.7. Secure Remote Access, 8.2.8. Vendor Management); 8.3. Specific Mitigation Strategies (8.3.1. Addressing Ransomware, 8.3.2. Protecting Data, 8.3.3. Mitigating DDoS Attacks, 8.3.4. Securing Wireless Communications)
    *   **Prompt:** "Provide actionable security recommendations for ((subject)). Focus on design-phase security, operational security, and specific mitigation strategies for prioritized threats. Align recommendations with both the MITRE ATT&CK framework and the IEC 62443 standard. Provide practical benefits for ((subject)) and ensure they are actionable."
*   **Conclusion:**
    *   **Outline:** 9.1. Summary of Key Findings; 9.2. Importance of Proactive Security; 9.3. Call to Action
    *   **Prompt:** "Summarize the key findings of the threat model assessment. Emphasize the importance of proactive security and continuous improvement. Provide a call to action, encouraging ((subject)) to implement the recommended mitigation strategies."
*   **Appendix:**
    *   **Outline:** 10.1. Glossary of Terms; 10.2. MITRE ATT&CK Matrix; 10.3. EMB3D Threat Model Details; 10.4. OSINT Sources
    *   **Prompt:** "Include a glossary of key cybersecurity terms, a detailed mapping of techniques to ((subject)) using the MITRE ATT&CK matrix, specific vulnerabilities and mitigations for embedded systems using the EMB3D Threat Model, and a list of OSINT sources used."

**Addenda:**

*   **Addendum A: References**
    *   **Prompt:** "Compile a comprehensive list of all references cited within the main report, ensuring each entry is complete and formatted consistently."
*   **Addendum B: Research Links**
    *   **Prompt:** "Organize all research links used in the report into a categorized list, making it easy to navigate and access the source material."
*   **Addendum C: Threat Analysis and Mitigation Strategies for Advanced Transportation Systems - A Case Study of ((subject))**
    *   **Prompt:** "Provide a detailed analysis of cybersecurity threats and mitigation strategies specific to advanced transportation systems, using ((subject)) as a case study. Focus on the unique challenges posed by specialized applications, protocols, and embedded systems. Integrate the MITRE ATT&CK framework for ICS and the EMB3D Threat Model for embedded systems. Emphasize the need for a robust, multi-layered security strategy and propose practical mitigation steps tailored to the specific risks identified."
*   **Addendum D: Overview of the IEC 62443 Framework for Industrial Automation and Control Systems (IACS)**
    *   **Prompt:** "Provide a comprehensive overview of the IEC 62443 framework, its key concepts, and how it can be applied to the ((subject)) system. Outline a roadmap for integrating the framework into ((subject))' security strategy and provide guidance on establishing supplier standards. Focus on zones, requirements, and supplier standards."

**Phase 2: Second-Stage Research and Refinement**

**Instructions:**

1.  **Review:** Carefully review the generated report from Phase 1.
2.  **Identify Gaps:** Identify areas where additional research is needed to provide a more comprehensive and detailed analysis.
3.  **Research Topics:** Based on the identified gaps, research the following topics on the internet, using reliable sources:
    *   **Specific MITRE ATT&CK Techniques:** Research specific MITRE ATT&CK for ICS techniques most relevant to ((subject))' unique infrastructure and control systems.
    *   **Emerging Threat Actors:** Investigate emerging threat actors targeting transportation ICS and their known TTPs.
    *   **Real-World Case Studies:** Research real-world case studies of cyberattacks on similar automated transit systems for preventative insights.
    *   **Wireless Communication Security:** Deep dive into the security implications of ((subject))' specific wireless communication protocols (e.g., dual-band).
    *   **Security Control Effectiveness:** Evaluate the effectiveness of current security controls against prioritized MITRE ATT&CK techniques.
    *   **Advanced Threat Detection:** Explore advanced threat detection methods using machine learning for anomaly detection in ((subject))' OT network.
    *   **Secure Remote Access and Vendor Management:** Research best practices for secure remote access and vendor management in transportation ICS.
    *   **Cloud Security:** Investigate the cyber resilience of ((subject))' cloud-based capacity planning tools and data security.
    *   **Supply Chain Vulnerabilities:** Analyze potential supply chain vulnerabilities within ((subject))' hardware and software components.
    *   **Incident Response Strategies:** Research incident response strategies tailored to the unique operational constraints of a continuous-flow transit system.
4.  **Refine Report:** Incorporate the new research findings into the report, refining the analysis, recommendations, and roadmap.
5.  **Update Citations:** Ensure all new sources are properly cited.

**Phase 3: Final Report and Consistency Check**

**Instructions:**

1.  **Finalize Report:** Complete the report, incorporating all research and analysis.
2.  **Consistency Check:** Perform a final consistency check, ensuring that:
    *   The Executive Summary accurately reflects the report's findings and recommendations.
    *   The recommendations are actionable, practical, and aligned with the identified threats and vulnerabilities.
    *   The roadmap is consistent with the recommendations and provides a clear path for implementation.
    *   All sections are logically connected and use consistent terminology.
3.  **Deliver:** Submit the final, comprehensive ((subject)) Cybersecurity Threat Model Report.

**Expected Outcome:**

A comprehensive, well-researched, and actionable cybersecurity threat model report for ((subject)), fully aligned with the MITRE ATT&CK framework and the IEC 62443 standard, and incorporating the latest OSINT and best practices.

This prompt is designed to be as comprehensive as possible, guiding the "subject" through a thorough research and analysis process. The second-stage research phase ensures that the report is not only comprehensive but also incorporates the latest information and best practices, resulting in a high-quality and actionable document.