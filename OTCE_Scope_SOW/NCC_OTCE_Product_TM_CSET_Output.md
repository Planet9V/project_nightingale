**Product Threat Model CSET Tool (CISA)**

---

**CSET Threat Modeling Reporting – Example Outputs**

**1\. Threat Model Summary Report**

**Purpose:**  
Presents a high-level overview of the threat modeling process, including system context, identified threats, mitigations, and residual risks.

**Sample Sections:**

* **System Overview:**  
  *Description of the system, boundaries, and critical assets as entered in CSET.*

* **Data Flow Diagram (DFD):**  
  *Visual representation of the system, showing processes, data stores, data flows, and trust boundaries.*

* **Threat Enumeration Table:**  
  *Auto-generated list of threats per STRIDE category, mapped to DFD elements.*

| DFD Element | STRIDE Category | Threat Description | Severity | Mitigation Implemented | Residual Risk |
| :---- | :---- | :---- | :---- | :---- | :---- |
| **Remote Interface** | Spoofing | Attacker impersonates admin | High | MFA enabled | Low |
| **Data Store** | Tampering | Malicious firmware update | High | Signed updates | Medium |
| **Sensor Data Flow** | Information Disc. | Data intercepted in transit | Medium | TLS encryption | Low |

---

**2\. Threat Traceability Matrix**

**Purpose:**  
Shows how each identified threat is linked to a specific system component, its risk rating, and the corresponding mitigation.

**Sample Output:**

| Threat ID | System Component | Threat Description | Risk Rating | Mitigation Status | Comments |
| :---- | :---- | :---- | :---- | :---- | :---- |
| **T-001** | Controller | Unauthorized command | High | Mitigated | Access control in place |
| **T-002** | Network Link | Eavesdropping | Medium | Partially Mitigated | Encryption pending |

---

**3\. Mitigation Coverage Report**

**Purpose:**  
Summarizes which threats have been addressed and which remain, supporting remediation planning.

**Sample Output:**

| Threat Category | Total Threats | Mitigated | Not Mitigated | Partial |
| :---- | :---- | :---- | :---- | :---- |
| **Spoofing** | 5 | 4 | 1 | 0 |
| **Tampering** | 8 | 5 | 3 | 0 |
| **Repudiation** | 3 | 2 | 0 | 1 |

---

**4\. Risk Heat Map**

**Purpose:**  
Visualizes the distribution of threats by likelihood and impact, as assessed in the tool.

**Sample Output:**

text

High Impact

|■■■■■

|

|■■■

|

|■

\+-----------------

  Low Likelihood      High Likelihood

---

**5\. Exportable Reports**

* **PDF/Word/Excel Exports:**  
  All the above tables, diagrams, and summaries can be exported for sharing with stakeholders.

* **Appendices:**  
  Includes full DFDs, threat lists, mitigation details, and supporting documentation.

---

**What Makes CSET Threat Modeling Reporting Unique**

* **Automated STRIDE Mapping:**  
  CSET generates threats based on your DFD and system context, reducing manual effort.

* **Traceability:**  
  Every threat is mapped to a component, data flow, and mitigation status.

* **Actionable Outputs:**  
  Reports are structured for both technical and management audiences, supporting remediation and compliance.

