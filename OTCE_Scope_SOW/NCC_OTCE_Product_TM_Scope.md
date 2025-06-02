**Product Threat Model Scoping Sheet**

---

Client Name  		  
Product Name:		  
Product Division:	  
Client Contact: 	  
NCC Contact:   	  
Date Completed:   
Op OD: 		 

---

**Scoping Outcome**

1. **Product Name:**		  
2. **Product Division:**		  
3. **Category of product** (simple/moderate/complex) see *Table 1.2 LOE Product Complexity*  
4. **Product Description** (pull from **“***Product Threat Model Questionnaire”*  
5. **Is Safety Critical?**  
6. **Level of Documentation provided:**  
7. **Estimated LOE** (simple/moderate/complex) see *Table 1.3 Level of Effort*  
8. **Project Management** (PRODUCT01469)  
   * Simple: .5 Days  
   * Moderate:  1 Day  
   * Complex: 2-3 Days

**Total Days \=**   
*(Estimated LOE \+ Project Management)* 

**Project Manager Expectations**  
Coordinate stakeholder meetings for workshops. See *Table 1.1 Summary Table: CSET Threat Modeling Workflow and Table 1.3 Level of Effort Table.*

**Staffing Notes**

* **No Onsite work required**  
* Onboarding process **required, must be staffed by OTCE**  
* Required certifications; **OTCE Sr Rating**  
* OT program staffed by OT Rated Resources : Contact Jim Mckenney for staffing

---

**LOE Determination**

**Product information:** See attached *Product Threat Model Questionnaire completed by product owner*

**Notes on LOE Determination**

* **Simple**: Standalone products, no remote management, low criticality, few stakeholders.  
* **Moderate**: Products with network/cloud integration, moderate criticality, or regulatory requirements.  
* **Complex**: Safety-critical, highly integrated, or multi-zone products requiring full IEC 62443 alignment and in-depth risk analysis.

**Additional Factors That May Affect LOE**

* Availability and quality of documentation  
* Number of product variants or configurations  
* Stakeholder availability for workshops/interviews  
* Need for technical testing or validation

**Notes: Key Factors for Tailoring LOE by Complexity**

* **System Architecture:** Simple products have fewer components and interactions; complex products have multiple zones, trust boundaries, and integrations  
* **Data Sensitivity:** Products handling sensitive or regulated data require deeper analysis and more stakeholder engagement  
* **Connectivity:** Networked or cloud-connected products introduce more attack vectors, increasing LOE  
* **Criticality and Security Level:** Products with higher safety, operational, or compliance impact (e.g., IEC 62443 SL-3/4) require more rigorous threat modeling and documentation.  
* **Stakeholder Involvement:** More complex products involve more teams and require additional workshops and reviews  
* **Documentation and Reporting:** Complex models need more detailed diagrams, risk matrices, and mitigation plans

**Table 1.1 Summary Table: CSET Threat Modeling Workflow**

| Step | CSET Feature/Action |
| :---- | :---- |
| **Define Scope & Criticality** | Diagram builder, zone/conduit definition, SAL/SL-T selection |
| **Collect System Info** | System questionnaires, diagram import/creation |
| **Select Standards** | Standards selection wizard |
| **Identify Threats** | Guided threat/vulnerability questionnaires |
| **Analyze Risks** | Automated scoring, risk analysis reports |
| **Develop Mitigations** | Mitigation tracking, reporting |

**Table 1.2 LOE Product Complexity**

| Complexity | Description | LOE (Days) | Scope/Activities |
| :---- | :---- | :---- | :---- |
| **Simple** | Single function, minimal interfaces, low criticality | 1–3 | Basic asset/threat identification, simple DFD, single workshop, short report |
| **Moderate** | Multi-function, networked, moderate data sensitivity, some compliance | 3–5 | Multiple workshops, detailed DFD, STRIDE/PASTA analysis, risk matrix, standard mitigation documentation |
| **Complex** | Integrated systems, high criticality, multiple zones/interfaces, regulatory focus | 6-10 | Extensive stakeholder sessions, full STRIDE/PASTA, comprehensive risk/impact analysis, SL-T mapping, full report |

**Table 1.3 Level of Effort Table**

| Complexity | Workshops | Stakeholder Interviews | DFD/Architecture | Threat Enumeration | Risk Matrix | Mitigation Plan | Reporting |
| :---- | :---- | :---- | :---- | :---- | :---- | :---- | :---- |
| **Simple** | 1 | 1–2 | High-level | Major threats | Basic | Standard | Summary |
| **Moderate** | 2–3 | 2–4 | Detailed | STRIDE/PASTA | Detailed | Prioritized | Full |
| **Complex** | 4+ | 4+ | Comprehensive | Full STRIDE/PASTA | In-depth | SL-T aligned | Extensive |

**NCC Group OTCE Approach to Product Threat Modeling**

NCC Group uses the  Cyber Security Evaluation Tool (CSET), developed by CISA, to support threat modeling for equipment by following a structured, step-by-step process that aligns with industry standards and best practices. 

**CSET** provides a repeatable, standards-based approach to threat modeling for equipment, supporting both technical and organizational decision-making throughout the cybersecurity lifecycle

**1\. Define Scope and Criticality**

* **Identify the equipment or system under review** (e.g., fire prevention devices).  
  **Determine the criticality** of each component by assessing the potential consequences of compromise, which helps set the Security Assurance Level (SAL) or Security Level Target (SL-T) as recommended by IEC 62443

* **Document zones and conduits**: Use CSET’s interface to define cybersecurity zones, critical components, and network communication paths by dragging and dropping icons to build a network diagram[8](https://www.zengrc.com/blog/what-you-should-know-about-the-new-cyber-security-evaluation-tool-model/).

**2\. Collect System Information**

* **Gather detailed information** about hardware, software, network interfaces, and data flows relevant to the equipment[1](https://github.com/cisagov/cset)

* **Import or create network diagrams**: CSET allows you to import existing diagrams (e.g., from MS Visio) or create new ones to visualize your system architecture and connectivity

**3\. Select and Apply Standards**

* **Choose relevant cybersecurity standards** (such as IEC 62443, NIST, or others) within CSET to guide the evaluation and threat modeling process

* **Tailor the assessment** based on the chosen standard and the criticality/SAL of the equipment[8](https://www.zengrc.com/blog/what-you-should-know-about-the-new-cyber-security-evaluation-tool-model/).

**4\. Identify Threats and Vulnerabilities**

* **Use CSET’s guided questionnaires** to systematically identify threats and vulnerabilities related to your equipment, including physical, network, and software attack vectors

* **Leverage CSET’s built-in threat libraries** and checklists to ensure comprehensive coverage of common and sector-specific threats

**5\. Analyze and Prioritize Risks**

* **CSET provides scoring and reporting tools** to help you assess the likelihood and potential impact of identified threats, supporting risk prioritization and mitigation planning

* **Review the generated reports** to identify gaps in security controls and areas requiring additional protection.

**6\. Develop and Track Mitigations**

* **Document recommended mitigations** for each identified threat or vulnerability using CSET’s reporting features

---

**Product Threat Model Scoping Questionnaire**

Questionnaire tailored for equipment manufacturers incorporating criticality and IEC 62443 Security Level Target (SL-T) considerations.

**Instructions**

* Please answer all applicable questions as thoroughly as possible.  
* Attach relevant documentation or diagrams where available.  
* Indicate if any information is unavailable or estimated.  
* Attach product information sheet

---

Client Name  		  
Product Name:		  
Product Division:	  
Client Contact: 	  
NCC Contact:   	  
Date Completed: 	  
Opp ID:  	 

---

1\. Product (Equipment) Overview

* Product Name and Model(s):

* Brief Description and Intended Use:

* Primary Functions and Capabilities:

* Deployment Environments (e.g., industrial, commercial, residential):

* Product Lifecycle Stages (design, manufacturing, deployment, maintenance, decommissioning):

---

2\. System Architecture & Connectivity

* What are the main hardware components?

* What operating systems and firmware are used?

* What software applications or embedded code are present?

* What network interfaces/protocols are supported (Ethernet, Wi-Fi, Bluetooth, serial, etc.)?

* Does the product connect to external systems (e.g., cloud, SCADA, mobile apps)?

* Are remote management or update features present?

* What data flows in/out of the product?

---

3\. Asset Identification

* What data does the product store, process, or transmit?

* Are there sensitive or regulated data types (PII, operational data, safety logs)?

* What are the key assets (e.g., control logic, configuration files, cryptographic keys)?

* Are there any third-party components or dependencies?

---

4\. Threat Landscape

* What are the known or anticipated threat actors (insiders, external hackers, competitors)?

* What are potential attack vectors (network, physical, supply chain, wireless)?

* Has the product or similar products experienced incidents or vulnerabilities in the past?

* Are there known threats specific to the product’s environment or industry?

---

5\. Security Controls (Current State)

* What authentication and authorization mechanisms are implemented?

* Is data encrypted at rest and/or in transit?

* Are there logging and monitoring capabilities?

* Are software/firmware updates signed and validated?

* What physical security measures are in place?

* Are there intrusion detection or anomaly detection capabilities?

* How is secure boot or firmware integrity ensured?

---

6\. Criticality & Consequence Assessment (IEC 62443 Alignment)

* What is the role of the product in safety, operational continuity, or regulatory compliance?

* What are the potential consequences of compromise (safety, environmental, financial, reputational)?

* How is criticality assessed and documented?

* Which zones/conduits does the product belong to (if part of a larger system)?

* What Security Level Target (SL-T) is assigned to the product or its zones (SL-1 to SL-4)?

* What rationale supports the SL-T assignment (e.g., consequence analysis, risk assessment)?

* Are there compliance requirements (IEC 62443, NIST, UL, etc.)?

---

7\. Stakeholder & Process Information

* Who are the key stakeholders (engineering, operations, IT, safety, compliance)?

* Who is responsible for security decisions and risk acceptance?

* What is the process for reporting and managing vulnerabilities?

* Are there documented procedures for incident response and recovery?

* Are there plans for regular review and update of the threat model?

---

8\. Documentation & Supporting Materials

* Are architecture diagrams, data flow diagrams, and network schematics available?

* Is there a Bill of Materials (BOM) for hardware/software components?

* Are security policies, procedures, and previous assessments available?

---

9\. Additional Considerations

* Are there unique features or constraints (real-time requirements, legacy protocols, resource limitations)?

* Are there user or operator training requirements?

* Are there supply chain or third-party risks to be considered?

* Are there planned product updates or changes in the near future?

---

