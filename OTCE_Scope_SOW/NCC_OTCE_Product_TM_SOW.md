This Statement of Work (“**SOW**”) is issued pursuant to Master Services Agreement (“**Agreement**”), by and between NCC Group Security Services, Inc. (“**NCC Group**”) **CLIENT** (“**Client**”) and is effective as of the date last signed below by both Parties.  Terms not otherwise defined in this SOW shall have the meanings as defined in the Agreement.  In the event of any conflict between the terms of this SOW and the Agreement, the terms in this SOW shall govern. The term of this SOW (“Term”) is for a fixed period of 2 years following the \[date on which all Parties have signed this SOW (“SOW Date”)\].

1. **Description of NCC Group Project Deliverables:** For each Product Threat Modeling engagement performed under this SOW, NCC Group will prepare and present reports utilizing the CISA Cyber Security Evaluation Tool (CSET) methodology, including:

**Executive Reporting**

* **Executive Summary Report:** High-level overview discussing engagement scope, methodology, key findings, and overall risk posture related to the assessed product(s)  
* **Strategic Recommendations:** Analysis of product security posture, conformance to applicable standards, and integration considerations  
* **Priority Action Items:** Critical security gaps, architectural vulnerabilities, and immediate remediation recommendations based on threat analysis

**Product Threat Model Assessment Reporting**

* **Threat Model Summary Report:** Comprehensive overview of the threat modeling process, including system context, identified threats, mitigations, and residual risks  
* **Data Flow Diagrams (DFDs):** Visual representation of the product system showing processes, data stores, data flows, trust boundaries, and security zones  
* **Threat Enumeration Table:** Auto-generated list of threats per STRIDE category (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege), mapped to DFD elements

**Risk Assessment and Analysis Reporting**

* **Threat Traceability Matrix:** Shows how each identified threat links to specific system components, risk ratings, and corresponding mitigations  
* **Component-Based Risk Analysis:** Assessment of individual product components with required controls based on Security Assurance Level (SAL) and criticality ratings for Confidentiality, Integrity, and Availability  
* **Risk Heat Map:** Visual representation of threat distribution by likelihood and impact  
* **Mitigation Coverage Report:** Summary of addressed versus unaddressed threats, supporting remediation planning

**Compliance Framework Assessment**  
Based on product requirements and criticality, assessment against one or more of the following frameworks:

* IEC 62443 (Industrial Automation and Control Systems Security) \- Primary framework for OT/IoT products  
  * NIST Cybersecurity Framework (CSF) 2.0  
  * CIS Controls Version 8  
  * CISA Cross-Sector Cybersecurity Performance Goals (CPG)  
  * NIST SP 800-82 (Guide to Industrial Control Systems Security)  
  * ISO/IEC 27001/27002  
  * Additional sector-specific frameworks as applicable

**Security Assurance Level (SAL) Assessment**

* **Criticality Assessment:** Evaluation of Confidentiality, Integrity, and Availability requirements  
* **Security Level Target (SL-T) Analysis:** For IEC 62443 assessments, determination of appropriate security levels (SL-1 through SL-4)  
* **Zone and Conduit Analysis:** Security architecture assessment with trust boundary identification (for complex products or deployments only))

**Technical Documentation:**

* **System Architecture Analysis:** Assessment of hardware, software, network interfaces, and data flows  
* **Attack Surface Analysis:** Identification of potential attack vectors including network, physical, and supply chain risks  
* **Security Controls Gap Analysis:** Current state versus required controls based on selected framework(s)

**Product Threat Model Trending and Version Management: (OPTIONAL)**

* **Baseline Threat Model Database:** Establishment of initial threat model profile with all identified threats, controls, and assurance levels  
* **Version-to-Version Differential Analysis:** Comparative assessment showing changes in threat landscape, control implementations, and risk posture between product versions   
* **Trend Analysis Reporting:** Historical view of security improvements, new threats, and remediation effectiveness over time  
* **Asset Correlation Database:** Integration of threat model findings with Software Bill of Materials (SBOM) data for comprehensive asset tracking  
* **Security Target Level Progression:** Tracking of IEC 62443 Security Level Target (SL-T) achievement and improvements across versions  
* **Technical Validation Correlation:** Linking threat model assurance levels to actual technical validation results (SAST findings, penetration testing, vulnerability assessments)

**Gap Analysis and Prioritization: (OPTIONAL)**

* **Remediation Effectiveness Tracking:** Analysis of control implementation success and threat mitigation over time  
* **Priority Gap Identification:** Automated identification of critical security gaps based on trend analysis and assurance level requirements  
* **Investment ROI Analysis:** Assessment of security investment effectiveness based on threat reduction and compliance improvement trends

**Appendices (As Applicable):**

* **CSET Tool Outputs:** Raw assessment data, questionnaire responses, and framework compliance scores  
* **Workshop Session Summaries:** Key findings from stakeholder interviews and technical sessions  
* **Reference Materials:** Supporting documentation and industry best practices

2. **Description of NCC Group Project schedule:** NCC Group will perform Product Threat Modeling Projects at the request of Client. This Statement of Work is intended to cover multiple Projects and to simplify the process of quickly beginning work as needed by the Client. A written request (email will suffice) from a client representative is an offer to engage NCC Group for a particular Project against this SOW (subject to NCC Group's acceptance). All requests for Projects made by Client are subject to acceptance in writing by NCC Group (email will suffice) once NCC Group has assessed the request. Project timelines and specific start/end dates will be mutually agreed upon for each requested engagement.

3. **Description of Activities**:   
   

NCC Group will perform the following activities using the CISA CSET methodology and structured threat modeling approach:

* **Activity 1 \-- Product Scoping and Complexity Assessment:**

Conduct initial product assessment using NCC Group's *Product Threat Model Scoping Questionnaire* to determine product complexity and effort requirements per the following framework:

**Available Standards and Compliance Frameworks:**  
Based on product requirements and criticality, assessment will be conducted against one or more of the following frameworks available in CSET:

	**Table 1.1 Available Standards/Frameworks**

| Framework Category | Available Standards |
| :---- | :---- |
| **Industrial/OT Security** | IEC 62443 (Primary for OT/IoT products), ISA-62443-4-1, High Level Critical Infrastructure Assessment |
| **General Cybersecurity** | NIST Cybersecurity Framework (CSF) 2.0, CIS Controls Version 8, CISA Cross-Sector Cybersecurity Performance Goals (CPG) |
| **Government/Federal** | NIST SP 800-82 (Industrial Control Systems), NIST SP 800-171, NIST SP 800-53, FISMA |
| **Sector-Specific** | TSA Pipeline Security Guidelines, FAA Portable Electronic Devices, Healthcare 405(d) |
| **Infrastructure** | NERC CIP (Energy), American Water Works Association, CFATS Risk-Based Performance Standards |
| **International** | ISO/IEC 27001/27002, Cybersecurity Maturity Model Certification (CMMC) 2.0 |
| **Risk Assessment** | CISA Ransomware Readiness Assessment (RRA), CISA External Dependencies Management (EDM) |

**Table 1.2 CSET Threat Modeling Workflow**

| Step | CSET Feature/Action |
| :---- | :---- |
| **1 Define Scope & Criticality** | Diagram builder, zone/conduit definition, SAL/SL-T selection |
| **2 Collect System Info** | System questionnaires, diagram import/creation |
| **3 Select Standards** | Standards selection wizard |
| **4 Identify Threats** | Guided threat/vulnerability questionnaires |
| **5 Analyze Risks** | Automated scoring, risk analysis reports |
| **6 Reporting** | Reporting |

**Table 1.3 Estimated Level of Effort Product Complexity**

| Complexity | Description | LOE (Days) | Scope/Activities |
| :---- | :---- | :---- | :---- |
| **Simple** | Single function, minimal interfaces, low criticality | 1-3 | Basic asset/threat identification, simple DFD, single workshop, short report |
| **Moderate** | Multi-function, networked, moderate data sensitivity, some compliance | 3-5 | Multiple workshops, detailed DFD, STRIDE/PASTA analysis, risk matrix, standard mitigation documentation |
| **Complex** | Integrated systems, high criticality, multiple zones/interfaces, regulatory focus | 6-10 | Extensive stakeholder sessions, full STRIDE/PASTA, comprehensive risk/impact analysis, SL-T mapping, full report |

**Table 1.4 Estimated Level of Effort Table – Workshop and Interviews**

| Complexity | Work shops | Stakeholder Interviews | DFD/ Architecture | Threat Enumeration | Risk Matrix | Mitigation  Plan | Reporting |
| :---- | :---- | :---- | :---- | :---- | :---- | :---- | :---- |
| **Simple** | 1 | 1-2 | High-level | Major threats | Basic | Standard | Summary |
| **Moderate** | 2-3 | 2-4 | Detailed | STRIDE/PASTA | Detailed | Prioritized | Full |
| **Complex** | 4+ | 4+ | Comprehensive | Full STRIDE/PASTA | In-depth | SL-T aligned | Extensive |

* **Activity 2 \-- System Information Collection and Documentation:**

Gather detailed product information through structured questionnaires and collect supporting documentation per CSET methodology requirements.

* **Activity 3 \-- CSET-Based Threat Modeling Workshops:**

Conduct structured workshops based on product complexity as defined in Tables 1.2 and 1.3 above:

* Create/import Data Flow Diagrams (DFDs) in CSET tool  
* Define security zones, conduits, and trust boundaries  
* Conduct guided threat identification using STRIDE methodology  
* Map threats to system components and data flows  
* Assess current mitigation status and residual risks

* **Activity 4 \-- Framework Compliance Assessment:**

Configure CSET tool with selected compliance framework(s) and complete framework-specific questionnaires and requirements assessment.

* **Activity 5 \-- Risk Analysis and Prioritization:**

Utilize CSET's automated scoring and risk analysis capabilities to create threat traceability matrix, risk heat maps, and prioritization analysis.

* **Activity 6 \-- Product Threat Model Database and Trending Analysis: (Optional)**

Establish comprehensive database of threat model components and implement systematic tracking of threat model evolution across product versions with SBOM correlation.

* **Activity 7 \-- Security Architecture and Controls Analysi**

Analyze component-based security requirements, map required controls to Security Assurance Levels, and evaluate zone and conduit security implementations (for complex products or implementations)

* **Activity 8 \-- Trend Analysis and Gap Prioritization (Optional)**

Generate historical trend analysis reports and utilize trending data to identify critical security gaps and optimal remediation sequences.

* **Activity 9 \-- Report Generation and Delivery**

Generate comprehensive threat model reports using CSET export capabilities with executive summaries and technical findings per complexity requirements and chosen target assessment framework

* **Activity 10 \-- Project Management**

Standard NCC Group project management oversight and coordination with workshop scheduling and stakeholder coordination per complexity requirements.

4.  **Description of in Scope Product Systems**

Product threat modeling scope will be defined for each engagement and may include:

| System Category | Examples | Typical Complexity |
| :---- | :---- | :---- |
| **Industrial Control Systems** | PLCs, SCADA systems, HMIs | Moderate to Complex |
| **IoT/Edge Devices** | Sensors, gateways, controllers | Simple to Moderate |
| **Critical Infrastructure** | Power systems, water treatment | Complex |
| **Building Automation** | HVAC, access control, fire safety | Simple to Moderate |
| **Medical Devices** | Patient monitoring, diagnostic equipment | Moderate to Complex |
| **Transportation Systems** | Vehicle controllers, traffic management | Complex |
| **Fire Suppression systems** | Sensors, Audibles, Visuals, access control | Moderate to Complex |

*Specific target products will be defined in individual project requests*

5. **Program Management Services:** 

**Program Delivery**  
NCC will work with client to define the project plan during the pre-engagement period, which occurs after the SOW is signed. The actual project plan will consider NCC scheduling, client schedules and resource availability, including testing windows to set a Kickoff date, Engagement period (defined activities) and Engagement Closure (Reporting and Readout) date.

**Program Management Services:**   
NCC will work with client to define the project plan during the pre-engagement period, which occurs after the SOW is signed. The actual project plan will consider NCC scheduling, client schedules and resource availability, including testing windows to set a Kickoff date, Engagement period (defined activities) and Engagement Closure (Reporting and Readout) date.

**Description of Client Responsibilities**: NCC Group has used this information in establishing the project schedule and Fees for this project. In the event an item identified below does not occur in the manner or time frame shown, such circumstance shall constitute a change that may require an adjustment to the schedule and/or Fee. In connection with the services performed by NCC Group under this SOW, the Client will provide NCC Group with:

**Project Management Responsibilities:**

* Prompt and accurate responses to NCC Group Program Manager requests  
* Single point of contact with knowledge of target products and organization  
* Clear escalation path should primary contact become unavailable  
* Timely internal communication with relevant personnel regarding scheduled services

**Technical Responsibilities:**

* Access to product documentation (specifications, architecture diagrams, security assessments)  
* Availability of key stakeholders for workshops and interviews:   
  * Product owners and managers  
  * Development team members  
  * Security and compliance personnel  
  * Operations and maintenance staff  
* Provision of product information including:   
  * System architecture and component details  
  * Network diagrams and connectivity information  
  * Current security control implementations  
  * Known vulnerabilities or security incidents  
  * Regulatory and compliance requirements

**Documentation and Access:**

* Product specifications and technical documentation  
* Architecture diagrams, data flow diagrams, network schematics  
* Bill of Materials (BOM) for hardware/software components  
* Software Bill of Materials (SBOM) data for component tracking and correlation  
* Security policies, procedures, and previous assessments  
* Historical threat model data and previous version assessments (if available)  
* Previous technical validation results (SAST, penetration testing, vulnerability assessments)  
* Access to product development and operations personnel  
* Access to product version control and change management systems  
* Confirmation that assessment activities comply with organizational policies  
    
5. **Fees and Invoicing:** Client will pay to NCC Group the fees listed below and the actual travel and living expenses incurred, up to a maximum of the expense estimate below (“Fees”). Although NCC Group will only invoice for actual expenses incurred up to the expense estimate, Client will ensure that any PO value includes the full expense estimate to avoid any invoicing issues.  All fixed priced Services will be invoiced upon completion of each milestone as listed below.

| Activity | Fee |
| :---- | :---- |
| Activity 1 \-- Product Scoping and Complexity Assessment | \[TBD based on product complexity\] |
| Activity 2 \-- System Information Collection |  |
| Activity 3 \-- CSET-Based Threat Modeling Workshops |  |
| Activity 4 \-- Framework Compliance Assessment |  |
| Activity 5 \-- Risk Analysis and Prioritization |  |
| Activity 6 \-- Product Threat Model Database and Trending *(Optional)* |  |
| Activity 7 \-- Security Architecture Analysis |  |
| Activity 8 \-- Trend Analysis and Gap Prioritization *(Optional)* |  |
| Activity 9 \-- Report Generation and Delivery |  |
| Activity 10 \-- Project Management |  |
| Subtotal | \[X Days × Day Rate\] |
| Expenses (Estimate \- Actuals Invoiced): | *(Assumed Remote \- TBD if travel required)* |
| **PROJECT TOTAL (Estimate):** |  |

**Level of Effort (Scoping) on a Per Product basis impacted by**

**Complexity**

* **Simple Products:** 1-3 days effort (initial assessment or “re-test”)  
* **Moderate Products:** 3-5 days effort (initial assessment or “re-test”)  
* **Complex Products:** 6-10 days effort (initial assessment or “re-test”)  
* **Optional Trending Analysis:** 1-2 days additional effort for differential analysis and trend reporting

**Multi-Version Engagement Pricing:**

* **Initial Baseline Threat Model:** Full complexity-based pricing as above  
* **Version Update Assessments:** 30-50% of initial effort depending on scope of product changes  
* **Optional Annual Trend Analysis:** 1-2 days effort for comprehensive historical analysis  
* **Database Maintenance and Updates:** Included in version update assessments

**Optional Services:**  
**Trending Package** \- Available for products with multiple versions, releases, or after remediation cycles requiring re-assessment:

* Version-to-version comparative analysis (can align to the SBOM Vulnerability Tracking & Alerting  
* Historical trend reporting  
* Security improvement tracking  
* Gap closure measurement

*Note: Final pricing will be determined based on product complexity assessment, selected compliance framework(s), and scope of trending analysis required. Multi-version engagements receive discounted pricing for subsequent assessments*

| Payment Structure:  |   |   |   |   |
| ----- | :---: | :---: | ----- | ----- |
| **Milestone 1:**  | Signature by both Parties of this SOW | Payment: Upon receipt of invoice | $   |  |
| **Milestone 2:** | Delivery or products   | Payment: Upon Receipt of invoice | $  |  |
|  |  |  |   |   |
|  **Payment Information:**  |   |   |   |   |
| Purchase Order Number:  |   |   | Payment Terms:   | 30 days |

Unless otherwise provided for in this SOW, all Fees are for Services performed during the normal, daytime, business hours of the location at which they are performed (which shall be determined by NCC Group in its reasonable opinion) (“Normal Business Hours”). Any Services that Client requests to be performed outside of Normal Business Hours following mutual agreement of the SOW will result in an automatic increase in the Fees at a rate of 1.5 x daily rate stipulated in this SOW, or, if no daily rate is stipulated in this SOW, an additional daily fee of a minimum of $1,000 per day will be charged.

Where the Services includes a re-test, Client must schedule the retest, and the re-test must be completed, within three (3) months of completion of the initial test. In the event any such re-test does not take place within this timeframe, Client will be required to enter into a separate statement of work outlining the fees, time and deliverables needed to complete the re-test. Client will not be entitled to any refund of prepaid Fees for a re-test not completed within three (3) months of completion of the initial test

6. **Cancellation Policy:** 

Upon mutual agreement of a start date for Services (“**Start Date**”), NCC Group will immediately start to allocate resources and facilities and commit to third party expenditure to fulfil its contractual commitments. Client may, on written notice, re-schedule or cancel the Services but if it does so, Client agrees to pay NCC Group a proportion of the Fees under the relevant SOW (“**Cancellation Fees**”) as compensation (and not as a penalty) to reflect the losses which NCC Group will incur as a result of such cancellation or re-scheduling, as follows:  
(i)	cancellation request 8-21 days before the Start Date: 50% of the Fees will be payable;  
(ii)	re-schedule request 8-14 days before the Start Date: 50% of the Fees will be payable;  
(iii)	cancellation or rescheduling request within 7 days of the Start Date: 100% of the Fees will be payable.

Cancellation Fees will be paid within thirty (30) days of approval of the cancellation or rescheduling request.   The Parties have computed, estimated, and agreed upon the Cancellation Fees as an attempt to make a reasonable forecast of probable actual loss because of the difficulty of estimating with exactness the damages which will result.  
Where NCC Group permits a rescheduling of the Services, Client will pay the full Fees for the Services as rescheduled in addition to any Cancellation Fees specified above (Cancellation Fees will not be credited against the full Fees). Client will also be responsible for all non-refundable expenses which have been incurred prior to cancellation or rescheduling.

E**xport Control**

Client to confirm whether any material or information NCC Group consultants will come into contact with during this engagement will be subject to export control laws or regulations:

Yes  ☐ No ☒

7. **Special Terms:**   
   1. Client agrees to fully co-operate with NCC Group in its efforts to comply with applicable immigration rules and regulations. Such co-operation includes, without limitation, allowing NCC Group to post documents at any Client location(s) where an NCC Group employee is assigned.   
   2. NCC Group will not be required to travel to such countries: (i) listed as “Advise against all travel” or “Advise against all but essential travel” (or any equivalent advisories) by the US Department of State, World Health Organization (WHO), Centers for Disease Control and Prevention or any similar organization; and/or (ii) where travel is restricted in accordance with NCC Group’s internal policies or at NCC Group’s reasonable discretion. Where NCC Group is unable to travel due to these circumstances, it shall constitute a force majeure event.

   

   Where NCC Group is able to perform the Services, or part of them, remotely, the Client and NCC Group agree to discuss and implement any reasonable adjustments to the Services to enable the Services to be delivered remotely. For the avoidance of doubt, the agreed Fees for the Services shall be payable by the Client where the Services are delivered remotely in accordance with this paragraph.

   

8. **Address for Performance of the Services:** 

| Designated Address  |  |
| :---- | :---- |

9. **Contact Information:**

| CLIENT |  |
| :---- | :---- |
| Primary Contact |  |
| Address |  |
| Phone |  |
| Email |  |
| Accounts Payable Contact |  |
| Phone |  |
| Email |  |

| INVOICING ADDRESS |  |
| :---- | :---- |

| NCC Group |  |
| :---- | :---- |
| Name |  |
| Address | 11 E Adams St Ste 400, Chicago, IL 60603 |
| Phone | 551.208.8785 |
| Fax | 415-974-6339 |
| Email | william.filosa@nccgroup.com |

**AGREED:**

| CLIENT.: |  |  | NCC GROUP SECURITY SERVICES, INC. |  |  |
| :---- | :---- | :---- | :---- | :---- | ----- |
| Signature by: |  |  | Signature by: |  |  |
| Printed Name: |  |  | Printed Name: |  |  |
| Title: |  |  | Title: |  |  |
| Date: |  |  | Date: |  |  |

