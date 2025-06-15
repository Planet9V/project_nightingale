# Prospect Research Encyclopedia System
## Comprehensive Coverage Without Overengineering

**Purpose**: Maintain exhaustive, current intelligence on all 75 prospects as the foundational knowledge layer for Project Nightingale.

---

## 🎯 Design Philosophy

1. **Comprehensive**: Every prospect gets full coverage
2. **Current**: Monthly refresh cycle for all prospects
3. **Consistent**: Same depth and structure for everyone
4. **Simple**: One tool, one process, one format

---

## 📋 Standard Research Template

Every prospect file follows this exhaustive structure:

```markdown
---
company: [Full Legal Name]
last_refreshed: [YYYY-MM-DD]
research_gaps: [List areas needing data]
---

# [Company Name] - Comprehensive Intelligence Profile

## 1. Corporate Overview
### Basic Information
- Legal Name & DBAs:
- Founded:
- Headquarters:
- Stock Symbol:
- Website:
- Industry Classifications (NAICS/SIC):

### Corporate Structure
- Parent/Subsidiary Relationships:
- Business Units/Divisions:
- M&A History (last 5 years):
- Joint Ventures/Partnerships:

### Financial Profile
- Annual Revenue (3-year trend):
- EBITDA/Profit Margins:
- Market Cap:
- Credit Rating:
- Major Investors:

### Geographic Footprint
- Manufacturing Locations:
- Operations Centers:
- Data Centers:
- Remote Sites:
- Employee Distribution:

## 2. Leadership & Governance
### Executive Team
- CEO:
  - Background:
  - Tenure:
  - Previous Roles:
  - Public Statements on Security/Technology:
  
- CFO:
  [Same structure]
  
- CIO/CTO:
  [Same structure]
  
- CISO/CSO:
  [Same structure]
  
- COO:
  [Same structure]

### Board of Directors
- Chairman:
- Security/Risk Committee Members:
- Technology Committee Members:

### Key Middle Management
- VP Engineering:
- Director of IT:
- Security Operations Manager:
- Procurement Lead:

## 3. Technology Infrastructure
### IT Environment
- ERP System:
- CRM Platform:
- Email/Collaboration:
- Cloud Providers:
- Data Center Strategy:

### OT/ICS Environment
- SCADA Systems:
- Industrial Protocols:
- Control System Vendors:
- Connected Equipment:
- Remote Access Methods:

### Digital Footprint
- Main Domains:
- Subdomains Identified:
- Technology Stack (BuiltWith/Wappalyzer):
- Mobile Apps:
- API Endpoints:

### Security Tools/Vendors
- Known Security Vendors:
- Managed Security Providers:
- Compliance Certifications:
- Security Frameworks Used:

## 4. Business Operations
### Core Business Lines
- Primary Products/Services:
- Revenue by Segment:
- Key Customers:
- Supply Chain Dependencies:

### Strategic Initiatives
- Digital Transformation Projects:
- Sustainability Programs:
- Innovation Labs/R&D:
- Announced Investments:

### Operational Metrics
- Production Capacity:
- Utilization Rates:
- Quality Metrics:
- Safety Record:

## 5. Risk & Compliance
### Regulatory Environment
- Primary Regulators:
- Compliance Requirements:
- Recent Violations/Fines:
- Pending Regulations:

### Security Incidents
- Public Breaches (last 5 years):
- Ransomware Attacks:
- Disclosed Vulnerabilities:
- Near-misses Reported:

### Insurance & Risk
- Cyber Insurance Coverage:
- Risk Management Structure:
- Business Continuity Plans:
- Crisis Management Team:

## 6. Market Position
### Competitive Landscape
- Main Competitors:
- Market Share:
- Competitive Advantages:
- Strategic Threats:

### Industry Trends
- Sector Challenges:
- Technology Adoption:
- M&A Activity:
- Regulatory Changes:

### Analyst Coverage
- Industry Rankings:
- Analyst Reports:
- Credit Ratings:
- ESG Scores:

## 7. Cultural & Organizational
### Corporate Culture
- Stated Values:
- Employee Reviews (Glassdoor):
- DEI Initiatives:
- Community Involvement:

### Communication Style
- PR Approach:
- Executive Visibility:
- Social Media Presence:
- Crisis Communications:

### Decision Making
- Procurement Process:
- Budget Cycles:
- Approval Hierarchies:
- Innovation Appetite:

## 8. Intelligence Gaps & Notes
### Information Needed
- [List specific gaps]

### Research Notes
- [Contradictions found]
- [Unverified information]
- [Follow-up required]

### Sources Consulted
- Company Website
- SEC Filings
- News Articles
- Industry Reports
- LinkedIn Profiles
- [Other sources with dates]
```

---

## 🔄 Simple Refresh Process

### Refresh Cycle (All 75 Prospects)

**Phase 1**: Companies A-D
**Phase 2**: Companies E-J  
**Phase 3**: Companies K-P
**Phase 4**: Companies Q-Z

### Research Routine

```bash
#!/bin/bash
# research_routine.sh - Simple research routine

TODAY=$(date +%Y-%m-%d)
PROSPECTS=("Company_A" "Company_B" "Company_C")

for COMPANY in "${PROSPECTS[@]}"; do
    echo "=== Researching $COMPANY ==="
    
    # 1. Open existing file
    code "prospect_research/${COMPANY}_Prospect_Intelligence.md"
    
    # 2. Run searches (opens in browser)
    open "https://www.google.com/search?q=\"${COMPANY}\"+cybersecurity+news&tbs=qdr:m"
    open "https://www.linkedin.com/company/${COMPANY}/people/"
    open "https://www.sec.gov/edgar/search/?q=${COMPANY}"
    open "https://github.com/search?q=${COMPANY}"
    
    # 3. Update file header
    sed -i '' "s/last_refreshed:.*/last_refreshed: $TODAY/" \
        "prospect_research/${COMPANY}_Prospect_Intelligence.md"
    
    echo "Complete manual update, then press Enter"
    read
done

# 4. Commit updates
git add prospect_research/*.md
git commit -m "Monthly refresh: $TODAY"
```

### Research Checklist (Per Company)

**Quick Scan:**
- [ ] Google News (recent)
- [ ] LinkedIn leadership changes
- [ ] Latest SEC filing (if public)
- [ ] Check company newsroom

**Deep Dive (if changes found):**
- [ ] Update executive profiles
- [ ] New technology announcements
- [ ] M&A activity
- [ ] Security incidents
- [ ] Regulatory filings
- [ ] Vendor announcements

**Fill Gaps (as needed):**
- [ ] Missing executive profiles
- [ ] Unknown technology stack
- [ ] Unclear OT environment
- [ ] No financial data

---

## 📊 Quality Tracking

### Simple Progress Tracker

```markdown
# Research Status

| Company | Last Refresh | Completeness | Gaps | Priority |
|---------|--------------|--------------|------|----------|
| AES Corporation | 2025-06-14 | 85% | CISO profile | High |
| Boeing | 2025-06-01 | 95% | None | Medium |
| Consumers Energy | 2025-05-15 | 70% | OT details | High |
| Duke Energy | 2025-06-10 | 90% | Board info | Low |
...
```

### Progress Metrics

Track only what matters:
- Prospects refreshed: X/75
- Average completeness: X%
- High-priority gaps: X
- New intelligence found: X items

---

## 🚀 Implementation Steps

### Phase 1: Setup
1. Create research schedule for 75 prospects
2. Build template file
3. Set up research routine script
4. Create progress tracker

### Phase 2: Pilot
1. Research first batch of companies using template
2. Identify common information sources
3. Refine search queries
4. Optimize process

### Phase 3: Full Implementation
1. Complete all 75 prospects
2. Document reliable sources
3. Create source bookmark set
4. Establish sustainable rhythm

### Phase 4: Maintenance
1. Regular prospect refresh cycles
2. Periodic progress review
3. Gap analysis and filling
4. Process improvement iterations

---

## 🔧 Tools Required

**Essential (Free):**
- Text editor (VS Code)
- Web browser
- Git for version control

**Helpful (Paid):**
- LinkedIn Sales Navigator (executive tracking)
- BuiltWith Pro (technology stack)
- D&B Hoovers (financial data)

**NOT Required:**
- AI enrichment platforms
- Complex databases
- Automation scripts
- Quality scoring systems

---

## 💡 Key Success Factors

1. **Consistency Over Perfection**
   - Better to have 80% on all prospects than 100% on some

2. **Recent Over Complete**
   - Recently updated 70% complete beats outdated 100% complete

3. **Gaps Are OK**
   - Document what you don't know for focused follow-up

4. **Human Intelligence**
   - No AI can replace human judgment on what matters

5. **Sustainable Pace**
   - Set reasonable time limits per prospect

---

## 📈 Expected Outcomes

After full implementation:
- All 75 prospects documented comprehensively
- Regular refresh rhythm established  
- Average 85% completeness across all prospects
- Clear gap identification for targeted research
- Sustainable effort level maintained

This becomes your authoritative knowledge base that feeds:
- Account Manager Playbooks
- Executive Briefings
- Threat Intelligence Mapping
- Sales Battle Cards
- Strategic Planning

**Simple. Comprehensive. Sustainable.**