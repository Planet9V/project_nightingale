#!/usr/bin/env python3
"""
add_metadata.py - Add YAML frontmatter metadata to all prospect files
Enables searchability, categorization, and quality tracking
"""

import os
import re
from pathlib import Path
from datetime import datetime
import yaml

# Sector mappings based on company names
SECTOR_MAPPINGS = {
    'Energy': ['Duke', 'Exelon', 'PG&E', 'Edison', 'Constellation', 'CenterPoint', 
               'NRG', 'AES', 'Consumers', 'Evergy', 'Eversource', 'Portland_General',
               'Puget_Sound', 'Archaea', 'Caithness', 'Range_Resources', 'Westlake',
               'Halliburton', 'ExxonMobile', 'Iroquois_Gas'],
    'Manufacturing': ['Boeing', 'GE', 'BMW', 'Ford', 'John_Deere', 'International_Paper',
                      'US_Steel', 'United_Steel', 'Applied_Materials', 'Analog_Devices',
                      'Spellman', 'ASML', 'NXP', 'VDL', 'TATA_Steel', 'Johnson_Controls'],
    'Transportation': ['Norfolk_Southern', 'WMATA', 'Maher_Terminals', 'Port_of_Long_Beach',
                       'Port_of_San_Francisco', 'San_Francisco_Airport'],
    'Food': ['McDonalds', 'PepsiCo', 'US_Sugar', 'Land_O_Lakes', 'Perdue_Farms',
             'Friesland_Campina', 'Enza_Zaden'],
    'Utilities': ['American_Water', 'Ontario_Power', 'Vermont_Electric', 'Pepco',
                  'Pacific_Gas', 'PacifiCorp', 'National_Fuel_Gas'],
    'Other': ['CasperSleep', 'Costco', 'Crestron', 'Veson', 'AeroDefense',
              'Redaptive', 'Kamo', 'Neara', 'Hyfluence', 'Axpo', 'Engie']
}

# Theme mappings based on patterns
THEME_MAPPINGS = {
    'ITC': ['convergence', 'IT/OT', 'integration', 'connected'],
    'MA': ['merger', 'acquisition', 'consolidation'],
    'RANSOMWARE': ['ransomware', 'crypto', 'encryption'],
    'SCA': ['supply chain', 'vendor', 'third party'],
}

def determine_sector(company_name):
    """Determine sector based on company name"""
    for sector, companies in SECTOR_MAPPINGS.items():
        for company in companies:
            if company.lower() in company_name.lower():
                return sector
    return 'Other'

def determine_theme(content):
    """Determine theme based on content analysis"""
    content_lower = content.lower()
    
    for theme, keywords in THEME_MAPPINGS.items():
        for keyword in keywords:
            if keyword in content_lower:
                return theme
    
    return 'GENERAL'

def extract_financial_data(content):
    """Extract revenue and employee count from content"""
    revenue = None
    employees = None
    
    # Revenue patterns
    revenue_patterns = [
        r'\$(\d+(?:\.\d+)?)\s*billion\s*(?:in\s*)?(?:revenue|sales)',
        r'revenue[:\s]+\$(\d+(?:\.\d+)?)\s*billion',
        r'annual\s*revenue[:\s]+\$(\d+(?:\.\d+)?)\s*B',
    ]
    
    for pattern in revenue_patterns:
        match = re.search(pattern, content, re.IGNORECASE)
        if match:
            revenue = f"${match.group(1)} billion"
            break
    
    # Employee patterns
    employee_patterns = [
        r'(\d+,?\d*)\+?\s*employees',
        r'employees[:\s]+(\d+,?\d*)',
        r'workforce\s*of\s*(\d+,?\d*)',
    ]
    
    for pattern in employee_patterns:
        match = re.search(pattern, content, re.IGNORECASE)
        if match:
            employees = match.group(1).replace(',', '')
            break
    
    return revenue, employees

def extract_ticker(content):
    """Extract stock ticker from content"""
    ticker_patterns = [
        r'NYSE:\s*([A-Z]+)',
        r'NASDAQ:\s*([A-Z]+)',
        r'\(([A-Z]{1,5})\)',
        r'ticker:\s*([A-Z]+)',
    ]
    
    for pattern in ticker_patterns:
        match = re.search(pattern, content)
        if match:
            return match.group(1)
    
    return None

def calculate_intelligence_score(content, has_metadata=False):
    """Calculate intelligence completeness score"""
    score = 0
    
    # Base score for having content
    if len(content) > 1000:
        score += 20
    
    # Check for key sections
    sections = [
        'Executive Summary', 'Company Overview', 'Leadership',
        'Technical Infrastructure', 'Cybersecurity', 'Opportunities',
        'Financial', 'Competitive', 'Strategic'
    ]
    
    for section in sections:
        if section.lower() in content.lower():
            score += 5
    
    # Metadata bonus
    if has_metadata:
        score += 10
    
    # Length bonus
    if len(content) > 10000:
        score += 10
    elif len(content) > 5000:
        score += 5
    
    # Recent data bonus (look for 2024/2025 dates)
    if '2025' in content:
        score += 10
    elif '2024' in content:
        score += 5
    
    return min(score, 100)

def add_metadata_to_file(filepath):
    """Add or update metadata in a prospect file"""
    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Extract company name from filename
    filename = Path(filepath).stem
    company_name = filename.replace('_Prospect_Intelligence', '').replace('_', ' ')
    
    # Check if metadata already exists
    has_metadata = content.startswith('---\n')
    
    if has_metadata:
        # Extract existing metadata
        _, frontmatter, body = content.split('---\n', 2)
        metadata = yaml.safe_load(frontmatter)
    else:
        body = content
        metadata = {}
    
    # Update or create metadata
    if 'prospect' not in metadata:
        metadata['prospect'] = company_name
    
    # Auto-determine fields
    metadata['ticker'] = metadata.get('ticker') or extract_ticker(body)
    metadata['sector'] = metadata.get('sector') or determine_sector(filename)
    metadata['theme'] = metadata.get('theme') or determine_theme(body)
    metadata['priority'] = metadata.get('priority') or 'B'  # Default priority
    
    # Extract financial data
    revenue, employees = extract_financial_data(body)
    metadata['revenue'] = metadata.get('revenue') or revenue
    metadata['employees'] = metadata.get('employees') or employees
    
    # Update metadata
    metadata['last_updated'] = datetime.now().strftime('%Y-%m-%d')
    metadata['intelligence_score'] = calculate_intelligence_score(body, True)
    metadata['data_sources'] = metadata.get('data_sources', ['manual_research'])
    
    # Rebuild file with metadata
    yaml_str = yaml.dump(metadata, default_flow_style=False, sort_keys=False)
    new_content = f"---\n{yaml_str}---\n\n{body}"
    
    # Write back
    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(new_content)
    
    return metadata

def main():
    """Main execution"""
    print("📊 Adding Metadata to Prospect Files")
    print("====================================\n")
    
    # Get the prospect_research directory
    script_dir = Path(__file__).parent
    prospect_dir = script_dir.parent
    
    # Process all markdown files
    files_processed = 0
    metadata_summary = []
    
    for file in prospect_dir.glob('*_Prospect_Intelligence.md'):
        try:
            print(f"Processing: {file.name}...", end='')
            metadata = add_metadata_to_file(file)
            files_processed += 1
            metadata_summary.append({
                'file': file.name,
                'sector': metadata.get('sector'),
                'score': metadata.get('intelligence_score'),
                'priority': metadata.get('priority')
            })
            print(" ✓")
        except Exception as e:
            print(f" ❌ Error: {e}")
    
    print(f"\n✅ Complete! Processed {files_processed} files")
    
    # Generate summary report
    if metadata_summary:
        report_file = script_dir / "metadata_summary.md"
        with open(report_file, 'w') as f:
            f.write("# Metadata Enhancement Summary\n\n")
            f.write("| Company | Sector | Score | Priority |\n")
            f.write("|---------|--------|-------|----------|\n")
            
            for item in sorted(metadata_summary, key=lambda x: x['score'], reverse=True):
                f.write(f"| {item['file'].replace('_Prospect_Intelligence.md', '')} | ")
                f.write(f"{item['sector']} | {item['score']} | {item['priority']} |\n")
        
        print(f"📝 Summary report saved to: {report_file}")

if __name__ == "__main__":
    main()