#!/usr/bin/env python3
"""
standardize_naming.py - Fix inconsistent file naming in prospect_research folder
Converts all files to format: COMPANY_NAME_Prospect_Intelligence.md
"""

import os
import re
from pathlib import Path

def clean_company_name(filename):
    """Extract and clean company name from various formats"""
    # Remove file extension
    name = filename.replace('.md', '')
    
    # Remove common prefixes
    prefixes = ['prospect_research_', 'prospect_resarch_', 'Caithness Energy_', 'consumers_energy']
    for prefix in prefixes:
        if name.startswith(prefix):
            name = name[len(prefix):]
    
    # Handle special cases
    replacements = {
        'GTM Strategy_': '',
        'GTM Technical Analysis_': '',
        '_part2': '',
        '_Part_2': '',
        'prospect_vulnerability_intel_': '',
    }
    
    for old, new in replacements.items():
        name = name.replace(old, new)
    
    # Convert underscores to spaces for proper casing
    name = name.replace('_', ' ')
    
    # Proper case
    name = ' '.join(word.capitalize() for word in name.split())
    
    # Special company name corrections
    corrections = {
        'Ge': 'GE',
        'Bmw': 'BMW',
        'Pge': 'PG&E',
        'Nrg': 'NRG',
        'Vdl': 'VDL',
        'Nxp': 'NXP',
        'Tata': 'TATA',
        'Wmata': 'WMATA',
        'Us ': 'US ',
        'Asml': 'ASML',
    }
    
    for old, new in corrections.items():
        name = name.replace(old, new)
    
    # Convert back to underscore format
    name = name.replace(' ', '_')
    
    return name

def standardize_files(directory):
    """Standardize all markdown files in the directory"""
    path = Path(directory)
    changes = []
    
    for file in path.glob('*.md'):
        # Skip already processed files and special files
        if '_Prospect_Intelligence.md' in str(file) or file.name.startswith('PROSPECT_'):
            continue
            
        old_name = file.name
        company = clean_company_name(old_name)
        new_name = f"{company}_Prospect_Intelligence.md"
        
        if old_name != new_name:
            new_path = file.parent / new_name
            
            # Check for duplicates
            if new_path.exists():
                print(f"⚠️  Duplicate detected: {old_name} -> {new_name}")
                # Add suffix for duplicate
                counter = 2
                while new_path.exists():
                    new_name = f"{company}_Prospect_Intelligence_{counter}.md"
                    new_path = file.parent / new_name
                    counter += 1
            
            file.rename(new_path)
            changes.append((old_name, new_name))
            print(f"✓ Renamed: {old_name} -> {new_name}")
    
    return changes

def main():
    """Main execution"""
    print("🔧 Prospect Research File Standardization")
    print("=========================================\n")
    
    # Get the prospect_research directory
    script_dir = Path(__file__).parent
    prospect_dir = script_dir.parent
    
    print(f"📁 Processing directory: {prospect_dir}")
    print(f"📊 Files found: {len(list(prospect_dir.glob('*.md')))}\n")
    
    # Perform standardization
    changes = standardize_files(prospect_dir)
    
    print(f"\n✅ Complete! Renamed {len(changes)} files")
    
    # Save change log
    if changes:
        log_file = script_dir / "naming_changes.log"
        with open(log_file, 'w') as f:
            f.write("File Naming Standardization Log\n")
            f.write("==============================\n\n")
            for old, new in changes:
                f.write(f"{old} -> {new}\n")
        print(f"📝 Change log saved to: {log_file}")

if __name__ == "__main__":
    main()