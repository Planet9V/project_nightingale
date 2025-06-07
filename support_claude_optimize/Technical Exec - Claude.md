# **Executive \- All Aplications**

## **Waylay Acquisition Security Analysis**

**Prepared for**: Vertiv Security Leadership  
 **Date**: May 13, 2025

## **EXECUTIVE SUMMARY**

\<artifact id="executive-summary" /\>

## **INTERACTIVE DASHBOARD**

The interactive dashboard below provides a visual summary of key security findings:

\<artifact id="security-dashboard" /\>

## **1\. DETAILED TECHNICAL FINDINGS**

This assessment evaluates security vulnerabilities across Waylay's three main application suites. Our analysis reveals **8 Critical** and **18 High** severity vulnerabilities that present significant technical risks requiring remediation as part of the integration plan.

## **2\. APPLICATION SECURITY BREAKDOWN**

### **2.1 Waylay Core Platform**

**Security Posture**: HIGH RISK

**Critical Vulnerabilities**:

* **Remote Code Execution via HTMLUnit** (CVE-2023-26119)

  * **Technical Details**: Allows remote code execution via XSTL when browsing attacker-controlled webpages  
  * **CVSS Score**: 9.8 (Critical)  
  * **Exploitability**: Network-based attack with low complexity, requires no privileges  
  * **Affected Components**: WaylayEngine, resources, etl, alarm-service  
  * **Threat Intelligence**: Similar vulnerability class to those observed in critical infrastructure breaches

* **Prototype Pollution** (CVE-2022-37601)

  * **Technical Details**: Vulnerability in function parseQuery in webpack loader-utils  
  * **CVSS Score**: 7.5 (High)  
  * **Exploitability**: 90th percentile for likelihood of exploitation  
  * **Affected Component**: housekeeper  
  * **Threat Intelligence**: Prototype pollution vulnerabilities commonly exploited for initial access

### **2.2 Waylay AI Suite**

**Security Posture**: MODERATE-HIGH RISK

**Critical Vulnerabilities**:

* **Server-Side Template Injection** (CVE-2022-29078)

  * **Technical Details**: Template injection in ejs settings\[view options\]\[outputFunctionName\]  
  * **Attack Vector**: Server-side injection leading to OS command execution  
  * **Affected Component**: ai-console  
  * **Threat Intelligence**: Template injection vulnerabilities tracked in CISA's advisory database  
* **Algorithm Confusion in Python-Jose** (CVE-2024-33663)

  * **Technical Details**: Cryptographic bypass with OpenSSH ECDSA keys  
  * **CVSS Score**: Ranges from 6.5 to 9.3  
  * **Affected Component**: byoml  
  * **Threat Intelligence**: Recent proof-of-concept exploits published online

**Positive Finding**: The ai-studio-client component has no detected vulnerabilities.

### **2.3 Waylay SalesForce Integration**

**Security Posture**: HIGH RISK

**Critical Vulnerabilities**:

* **Server-Side Template Injection** (CVE-2022-29078)  
  * **Technical Details**: Same as in AI Suite \- template injection in ejs  
  * **Attack Vector**: OS command execution via template compilation  
  * **Affected Component**: SalesForceApp  
  * **Threat Intelligence**: Actively exploited in similar business applications

**High-Severity Vulnerabilities**:

* **Path Traversal** (CVE-2024-12905)  
* **Multiple ReDoS Vulnerabilities** (CVE-2021-3807, CVE-2022-3517)  
* **Server-Side Request Forgery** (CVE-2025-27152)

## **3\. TECHNICAL RISK ASSESSMENT**

### **3.1 Code Quality Assessment**

The Waylay codebase exhibits **mixed security maturity**:

* **Strengths**:

  * 58% of repositories have no identified vulnerabilities  
  * Several modern components (AI suite) show better security posture  
* **Weaknesses**:

  * Critical security vulnerabilities in core components  
  * Outdated dependencies with known vulnerabilities  
  * Inconsistent security practices across different components  
  * Multiple instances of the same vulnerability suggest inadequate dependency management

### **3.2 Exploitation Risk Analysis**

The most critical vulnerabilities in the Waylay suite align with current threat actor tactics:

1. **Remote Code Execution in Core Platform**:

   * **Technical Severity**: Critical (CVSS 9.8)  
   * **Attack Complexity**: Low  
   * **Privileges Required**: None  
   * **User Interaction**: None  
   * **Threat Intelligence**: Similar RCE vulnerabilities are primary targets for both ransomware groups and APT actors. The Network attack vector and low complexity make this vulnerability particularly attractive to attackers.  
2. **Server-Side Template Injection**:

   * **Technical Severity**: Critical  
   * **Attack Pattern**: Injecting malicious templates to achieve code execution  
   * **Threat Intelligence**: According to CISA, template injection vulnerabilities remain one of the top initial access vectors. The ejs vulnerability (CVE-2022-29078) has appeared in multiple security advisories.  
3. **Algorithm Confusion in Cryptographic Components**:

   * **Technical Severity**: Critical  
   * **Attack Pattern**: Exploiting algorithm mismatch to bypass cryptographic controls  
   * **Threat Intelligence**: While more complex to exploit, nation-state actors are known to target cryptographic bypass vulnerabilities, particularly in systems processing sensitive data.

### **3.3 Vulnerability Context in Current Threat Landscape**

Current threat intelligence indicates these vulnerability classes are actively exploited:

* **RCE Vulnerabilities**: Used by threat actors including Lazarus Group, APT41, and multiple ransomware affiliates as initial access vectors.

* **Template Injection**: Increasingly targeted in web applications processing sensitive data. Similar vulnerabilities were exploited in multiple data breaches over the past 18 months.

* **Prototype Pollution**: Emerging as a common attack vector in JavaScript applications, with multiple threat actors incorporating these exploits into their toolkits.

## **4\. TECHNICAL REMEDIATION PLAN**

### **4.1 Immediate Technical Actions**

1. **Patch Critical RCE Vulnerabilities**:

   * Update net.sourceforge.htmlunit:htmlunit to version 3.0.0 across all affected repositories  
   * Technical complexity: Low  
   * Required testing: Component functionality verification, integration testing  
2. **Remediate Template Injection Vulnerabilities**:

   * Update ejs to version 3.1.7 in both ai-console and SalesForceApp  
   * Technical complexity: Low  
   * Required testing: Template functionality validation  
3. **Address Cryptographic Vulnerabilities**:

   * Update python-jose to version 3.4.0 in the byoml component  
   * Technical complexity: Medium (cryptographic verification needed)  
   * Required testing: Authentication flow validation, cryptographic function testing  
4. **Technical Monitoring Enhancement**:

   * Implement HTTP traffic monitoring for affected components  
   * Deploy web application firewall rules to detect exploitation attempts  
   * Technical complexity: Medium

### **4.2 Integration Security Controls**

1. **Network Isolation**:

   * Implement network segmentation for vulnerable components  
   * Use application-level proxies with enhanced logging for critical interfaces  
   * Technical complexity: Medium  
2. **Continuous Vulnerability Scanning**:

   * Implement dependency scanning in CI/CD pipelines  
   * Conduct periodic SAST/DAST scans on application code  
   * Technical complexity: Low  
3. **Secure Integration Testing**:

   * Perform security-focused integration testing  
   * Conduct penetration testing before production deployment  
   * Technical complexity: High

## **5\. SECURITY MATURITY EVALUATION**

Compared to industry benchmarks for similar-sized technology companies:

| Security Aspect | Waylay Status | Industry Average | Gap Analysis |
| ----- | ----- | ----- | ----- |
| Vulnerability-free Repositories | 58% | 50-60% | Within normal range |
| Critical Vulnerabilities | 8 | 5-10 | Within expected range |
| Dependency Management | Poor | Fair to Good | Below average |
| Security Integration | Limited evidence | Typically present | Significant gap |
| Secure SDLC | Limited evidence | Increasingly common | Significant gap |

The Waylay codebase appears to have **typical vulnerabilities for its technology stack and maturity** but lacks evidence of systematic security processes that would be expected in a more mature organization.

## **6\. CONCLUSION AND RECOMMENDATIONS**

The security assessment of Waylay's application suite reveals significant but common technical vulnerabilities that require remediation. These vulnerabilities are technically manageable but represent material security risk if not addressed.

### **Technical Recommendations:**

1. **Implement a Comprehensive Remediation Plan**:

   * Prioritize critical vulnerabilities affecting network-exposed components  
   * Address security-design weaknesses through technical architecture review  
   * Establish secure development practices across all development teams  
2. **Enhance Security Testing**:

   * Conduct penetration testing on all application components  
   * Implement automated security testing in development pipelines  
   * Perform source code security review of critical components  
3. **Technical Integration Strategy**:

   * Develop a phased integration approach  
   * Maintain network separation until critical vulnerabilities are addressed  
   * Implement enhanced monitoring during the integration period

The Waylay technology stack presents manageable security risks comparable to other acquisitions at similar maturity levels. With proper technical remediation and an appropriate integration security plan, these risks can be effectively mitigated to support a successful acquisition.

