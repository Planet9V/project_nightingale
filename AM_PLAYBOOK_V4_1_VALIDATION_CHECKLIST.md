# AM Playbook v4.1 Validation Checklist
## Quality Assurance Protocol for Enhanced Playbooks

**Purpose**: Systematic validation of all v4.1 AM playbooks to ensure template compliance and data quality  
**Estimated Time**: 30 minutes per playbook  

---

## 🔍 VALIDATION PROTOCOL

### For Each V4.1 Playbook, Check:

#### **1. TEMPLATE STRUCTURE COMPLIANCE**

**Partnership Overview Section**
- [ ] Jim McKenney contact information present
- [ ] Clark Richter (Dragos) mentioned
- [ ] Tri-partner solution explained
- [ ] Mission statement included
- [ ] NO placeholder text like [DRAGOS AM NAME]

**Enhanced Intelligence Capabilities**
- [ ] Enhanced Concierge Reports explained
- [ ] OSINT Intelligence Collection described
- [ ] EAB Selection Process outlined
- [ ] Specific to this AM's prospects

**5-Step OT-First Process**
- [ ] All 5 steps clearly documented
- [ ] Success metrics included
- [ ] Operational focus emphasized
- [ ] Process flow complete

---

#### **2. PROSPECT COVERAGE VALIDATION**

**Complete Prospect List**
```bash
# Extract from CSV to verify:
# All prospects where NCC_Account_Manager = "[AM Name]" 
# AND GTM_Status = "Original"
```

- [ ] Every assigned prospect has a profile section
- [ ] No missing prospects
- [ ] Account IDs match CSV exactly
- [ ] No placeholder profiles

**Quick Reference Table**
- [ ] Table exists with all prospects
- [ ] Primary decision makers listed
- [ ] Campaign themes assigned (Ransomware/M&A only)
- [ ] Appendix references included

---

#### **3. CONTACT INFORMATION QUALITY**

**Executive Contacts**
- [ ] Actual names (not "CIO Name")
- [ ] Real titles from research
- [ ] Email addresses where available
- [ ] "Contact unavailable - requires research" only when truly missing

**Contact Completeness Score**
- [ ] Primary Decision Maker: ____%
- [ ] Technical Influencer: ____%
- [ ] Financial Stakeholder: ____%
- [ ] Overall: ____% (Target: 95%+)

---

#### **4. CONTENT QUALITY CHECKS**

**No Placeholder Content**
Search for these red flags:
- [ ] No "[CONTINUE...]" text
- [ ] No "[PLACEHOLDER]" text
- [ ] No "[AM NAME]" variables
- [ ] No "[SECTOR]" variables
- [ ] No "..." indicating incomplete sections

**Appendix System**
- [ ] All appendix files referenced
- [ ] Correct naming: Appendix_[ID]_[Company].md
- [ ] Links formatted properly
- [ ] Appendix count matches prospect count

---

#### **5. ENHANCEMENT ELEMENTS**

**Intelligence Integration**
- [ ] OSINT findings mentioned for prospects
- [ ] EAB selections documented
- [ ] Enhanced Concierge Report status noted
- [ ] Threat intelligence integrated appropriately

**Email Templates**
- [ ] Initial outreach template present
- [ ] Industry-specific customization
- [ ] All 5 templates included
- [ ] Professional tone throughout

**Objection Handling**
- [ ] All 4 standard objections covered
- [ ] Industry-specific responses
- [ ] Value-focused messaging
- [ ] No fear-based language

---

## 📊 VALIDATION SCORING MATRIX

| Section | Weight | Score | Notes |
|---------|--------|-------|-------|
| Template Structure | 20% | ___/20 | |
| Prospect Coverage | 25% | ___/25 | |
| Contact Quality | 25% | ___/25 | |
| Content Quality | 20% | ___/20 | |
| Enhancements | 10% | ___/10 | |
| **TOTAL** | 100% | ___/100 | |

**Grading Scale**:
- A+ (95-100): Ready for use
- A (90-94): Minor updates needed
- B (80-89): Moderate updates required
- C (70-79): Significant work needed
- D (<70): Major non-compliance

---

## 🔧 COMMON ISSUES & FIXES

### **Issue 1: Placeholder Contact Information**
**Finding**: "[CIO Name]" or "[Email]" in profiles
**Fix**: 
1. Check `/prospect_research/prospect_research_[company].md`
2. Use WebSearch: "[Company] CIO email 2024"
3. Try mcp__tavily__tavily-search for LinkedIn
4. Document as "unavailable" only if not found

### **Issue 2: Missing Quick Reference Table**
**Finding**: No summary table in Section 3
**Fix**: Create table with all prospects:
```markdown
| Company | Primary DM | Tech Lead | Theme | Appendix |
|---------|------------|-----------|--------|----------|
| [Actual data from research files and CSV] |
```

### **Issue 3: Generic Email Templates**
**Finding**: Templates say "[INDUSTRY]" or "[SECTOR]"
**Fix**: Customize for specific industry:
- Oil & Gas: drilling, pipeline, refinery focus
- Chemical: CFATS, process safety emphasis
- Manufacturing: production, quality, efficiency

### **Issue 4: Incomplete Prospect Profiles**
**Finding**: "Continue with remaining prospects..."
**Fix**: Create full profile for EVERY assigned prospect

---

## 📝 VALIDATION TRACKING

### **AM Playbook Validation Status**

| Account Manager | Playbook Version | Validation Date | Score | Status |
|----------------|------------------|-----------------|-------|---------|
| Jim Vranicar | V4.1 Complete | _____ | ___/100 | _____ |
| Jeb Carter | V4.1 Official | _____ | ___/100 | _____ |
| William Filosa | V4.1 Official | _____ | ___/100 | _____ |
| Matthew Donahue | V4.1 Official | _____ | ___/100 | _____ |
| Steve Thompson | V4.1 Official | _____ | ___/100 | _____ |
| Daniel Paszkiewicz | V4.1 Official | _____ | ___/100 | _____ |
| Sarah Sobolewski | V4.1 Official | _____ | ___/100 | _____ |
| Wayne Margolin | V4.1 Official | _____ | ___/100 | _____ |
| Dani LaCerra | V4.1 Official | _____ | ___/100 | _____ |
| Nate Russo | V4.1 Official | _____ | ___/100 | _____ |

---

## ✅ FINAL VALIDATION SIGN-OFF

**Validator Name**: _________________________  
**Validation Date**: _________________________  
**Overall Assessment**: ______________________  

**Recommendations**:
1. _________________________________________
2. _________________________________________
3. _________________________________________

**Ready for Production Use**: YES / NO

---

*This validation checklist ensures all v4.1 AM playbooks meet Project Nightingale quality standards and template requirements before production use.*