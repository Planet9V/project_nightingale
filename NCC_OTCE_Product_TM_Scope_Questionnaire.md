  
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

