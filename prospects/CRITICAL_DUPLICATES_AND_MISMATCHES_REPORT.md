# CRITICAL: Duplicate Account IDs and Folder Mismatches Report
## Project Nightingale - Data Integrity Issues
### Date: June 9, 2025

**⚠️ URGENT ATTENTION REQUIRED**: Multiple prospects are using duplicate or generic account IDs that need immediate correction to prevent data corruption and reporting errors.

---

## 1. DUPLICATE ACCOUNT IDS (9 Sets of Duplicates)

### A-012345 (GENERIC ID - 2 folders)
```
❌ A-012345_AES_Corporation
❌ A-012345_NXP_Semiconductors
```
**Issue**: Generic test ID used for 2 different companies
**CSV Match**: A-031305 should be AES Corporation

### A-033248 (REAL ID - 2 folders) 
```
✓ A-033248_Pacific_Gas_and_Electric (Correct - matches CSV)
❌ A-033248_Portland_General_Electric (Wrong - should be different ID)
```
**Issue**: Same ID used for 2 different utilities
**CSV Match**: Portland General Electric should be A-033248 per CSV

### A-075450 (REAL ID - 2 folders)
```
✓ A-075450_Southern_California_Edison (Correct - matches CSV)
❌ A-075450_Southern_California_Edison_Company (Duplicate folder)
```
**Issue**: Same company with 2 slightly different folder names

### A-112386 (REAL ID - 2 folders)
```
✓ A-112386_BMW (Correct - matches CSV)
❌ A-112386_BMW_Group_North_America (Duplicate/subsidiary)
```
**Issue**: Parent and subsidiary using same ID

### A-234567 (GENERIC ID - 3 folders) ⚠️ WORST CASE
```
❌ A-234567_BMW
❌ A-234567_Boeing  
❌ A-234567_Casper_Sleep
```
**Issue**: Generic test ID used for 3 completely different companies
**CSV Matches**: BMW is A-112386, Boeing is A-018814, Casper Sleep is A-107329

### A-345678 (GENERIC ID - 3 folders) ⚠️ WORST CASE
```
❌ A-345678_Analog_Devices
❌ A-345678_McDonalds_Corporation
❌ A-345678_VDL_Group
```
**Issue**: Generic test ID used for 3 completely different companies
**CSV Matches**: Analog Devices is A-020312, McDonald's is A-129751, VDL is A-EMEA-20003

### A-456789 (GENERIC ID - 2 folders)
```
❌ A-456789_Applied_Materials
❌ A-456789_General_Electric_Haier
```
**Issue**: Generic test ID used for 2 different companies
**CSV Matches**: Applied Materials is A-019866, GE Haier is A-072258

### A-567890 (GENERIC ID - 2 folders)
```
❌ A-567890_Crestron_Electronics
❌ A-567890_San_Francisco_International_Airport
```
**Issue**: Generic test ID used for 2 different companies
**CSV Matches**: Crestron is A-078866, SFO Airport is A-110670

### A-678901 (GENERIC ID - 2 folders)
```
❌ A-678901_Maher_Terminals
❌ A-678901_Spellman_High_Voltage
```
**Issue**: Generic test ID used for 2 different companies
**CSV Matches**: Maher Terminals is A-122766, Spellman is A-014671

---

## 2. FOLDERS NOT IN MASTER CSV (26 Total)

### Generic Test IDs (Already Listed Above)
These are the duplicate generic IDs that don't belong:
- A-012345 (except the real NXP which should be A-EMEA-20002)
- A-234567 (all 3 folders)
- A-345678 (all 3 folders) 
- A-456789 (both folders)
- A-567890 (both folders)
- A-678901 (both folders)
- A-123456 (generic)
- A-156789 (generic)
- A-789012 (generic)
- A-890123 (generic)
- A-901234 (generic)

### Potentially Legitimate IDs Not in CSV
These appear to be real account IDs but aren't in the master CSV:
```
A-031007_PGE_Pacific_Gas_Electric
A-031019_Portland_General_Electric
A-031084_Eversource_Energy
A-031125_CenterPoint_Energy
A-034695_Exelon_Corporation
A-045678_National_Fuel_Gas_Distribution
A-045892_Ontario_Power_Generation
A-067823_Pepco_Holdings
A-067890_Iroquois_Gas_Transmission
A-078945_Johnson_Controls
A-087654_Evergy_Inc
A-088972_Vermont_Electric_Power
A-089134_National_Fuel_Gas_Distribution
A-098765_Pacificorp
A-150024_International_Paper_Company
```

**Note**: Some of these companies ARE in the CSV but with different IDs, suggesting these are old/incorrect folders.

---

## 3. CORRECT ID MAPPING FROM CSV

Here are the CORRECT account IDs from the master CSV for commonly confused companies:

### Energy/Utilities
- **AES Corporation**: A-031305 (NOT A-012345)
- **CenterPoint Energy**: A-109140 (NOT A-031125)
- **Eversource Energy**: A-094599 (NOT A-031084)
- **National Fuel Gas**: A-135830 (NOT A-045678 or A-089134)
- **Ontario Power Generation**: A-092681 (NOT A-045892)
- **Pacificorp**: A-052457 (NOT A-098765)
- **PG&E (Pacific Gas and Electric)**: A-037323 (NOT A-031007)
- **Portland General Electric**: A-033248 (NOT A-031019)
- **Vermont Electric Power**: A-122495 (NOT A-088972)

### Manufacturing/Industrial
- **Analog Devices**: A-020312 (NOT A-345678)
- **Applied Materials**: A-019866 (NOT A-456789)
- **Boeing**: A-018814 (NOT A-234567)
- **BMW**: A-112386 (NOT A-234567)
- **Crestron Electronics**: A-078866 (NOT A-567890)
- **General Electric (Haier)**: A-072258 (NOT A-456789)
- **Johnson Controls**: A-029867 (NOT A-078945)
- **Spellman High Voltage**: A-014671 (NOT A-678901)

### Other
- **Casper Sleep**: A-107329 (NOT A-234567)
- **International Paper**: A-035329 (NOT A-150024)
- **Maher Terminals**: A-122766 (NOT A-678901)
- **McDonald's Corporation**: A-129751 (NOT A-345678)
- **San Francisco Airport**: A-110670 (NOT A-567890)

### EMEA (Currently Missing)
- **NXP**: A-EMEA-20002 (folder missing, NOT A-012345)
- **VDL**: A-EMEA-20003 (folder missing, NOT A-345678)

---

## 4. RECOMMENDED ACTIONS

### IMMEDIATE ACTIONS REQUIRED:

1. **Archive All Generic ID Folders**:
   - Move all A-123456, A-234567, A-345678, A-456789, A-567890, A-678901, A-789012, A-890123, A-901234 folders to an archive
   - These contain test data or incorrectly labeled production data

2. **Rename Folders to Correct IDs**:
   - Carefully map content from generic folders to correct account IDs
   - Verify company names match before moving content

3. **Consolidate Duplicates**:
   - Merge A-075450 Southern California Edison folders
   - Merge A-112386 BMW folders (if both needed)
   - Fix A-033248 confusion between PG&E and Portland General

4. **Create Missing EMEA Folders**:
   - A-EMEA-20002_NXP_Semiconductors
   - A-EMEA-20003_VDL_Group

5. **Delete or Archive Non-CSV Folders**:
   - Review the 15 potentially legitimate IDs not in CSV
   - Determine if they're old versions or test data
   - Archive if historical, delete if test data

---

## 5. DATA INTEGRITY RISK ASSESSMENT

### HIGH RISK Issues:
- **Generic IDs**: 11 companies using generic test IDs (A-234567, etc.)
- **Wrong IDs**: ~15 companies potentially using incorrect account IDs
- **Missing Folders**: 2 EMEA prospects have no folders

### MEDIUM RISK Issues:
- **Duplicate Folders**: Same company with multiple folders
- **Naming Variations**: Inconsistent folder naming (Company vs Company_Corporation)

### Impact if Not Fixed:
- Reports will show incorrect data
- Artifacts may be in wrong folders
- Account managers won't find their prospects
- Automated processes will fail
- Billing/tracking will be incorrect

---

**URGENT**: This cleanup should be done BEFORE generating more artifacts to avoid perpetuating the confusion.

**Created**: June 9, 2025  
**Priority**: CRITICAL - Fix before proceeding with artifact generation