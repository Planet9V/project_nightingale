#!/usr/bin/env python3
"""
gap_analysis.py - Identify missing information across all prospects
Simple, practical gap tracking without overengineering
"""

import os
import re
from pathlib import Path
from datetime import datetime, timedelta
import yaml

class ProspectGapAnalyzer:
    """Analyze prospect files for missing critical information"""
    
    def __init__(self, research_dir='.'):
        self.research_dir = Path(research_dir)
        self.critical_fields = {
            'Executive Info': [
                'CEO:',
                'CFO:', 
                'CIO/CTO:',
                'CISO/CSO:'
            ],
            'Company Basics': [
                'Annual Revenue',
                'Employee',
                'Headquarters:',
                'Founded:'
            ],
            'Technology': [
                'ERP System:',
                'Cloud Provider',
                'SCADA System',
                'Security Vendor'
            ],
            'Risk & Compliance': [
                'Security Incident',
                'Compliance Requirement',
                'Regulatory',
                'Insurance'
            ]
        }
        
    def analyze_file(self, filepath):
        """Analyze a single prospect file for gaps"""
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Parse metadata
        metadata = {}
        if content.startswith('---'):
            try:
                _, fm, _ = content.split('---', 2)
                metadata = yaml.safe_load(fm) or {}
            except:
                pass
        
        # Get company name
        company = metadata.get('company', filepath.stem.replace('_', ' '))
        
        # Check last refresh
        last_refreshed = metadata.get('last_refreshed', 'Unknown')
        if last_refreshed != 'Unknown':
            try:
                refresh_date = datetime.strptime(last_refreshed, '%Y-%m-%d')
                days_old = (datetime.now() - refresh_date).days
            except:
                days_old = 999
        else:
            days_old = 999
        
        # Find gaps
        gaps = {}
        for category, fields in self.critical_fields.items():
            missing = []
            for field in fields:
                # Simple check - is the field mentioned and has content after it?
                pattern = f'{field}.*?([A-Za-z0-9])'
                if not re.search(pattern, content, re.IGNORECASE):
                    missing.append(field.rstrip(':'))
            if missing:
                gaps[category] = missing
        
        # Calculate completeness
        total_fields = sum(len(fields) for fields in self.critical_fields.values())
        missing_count = sum(len(missing) for missing in gaps.values())
        completeness = int(((total_fields - missing_count) / total_fields) * 100)
        
        return {
            'company': company,
            'last_refreshed': last_refreshed,
            'days_old': days_old,
            'completeness': completeness,
            'gaps': gaps,
            'file': filepath.name
        }
    
    def analyze_all_prospects(self):
        """Analyze all prospect files in directory"""
        results = []
        
        for file in self.research_dir.glob('*_Prospect_Intelligence.md'):
            try:
                analysis = self.analyze_file(file)
                results.append(analysis)
            except Exception as e:
                print(f"Error analyzing {file}: {e}")
        
        return sorted(results, key=lambda x: x['completeness'])
    
    def generate_report(self, results):
        """Generate gap analysis report"""
        report = []
        report.append("# Prospect Research Gap Analysis")
        report.append(f"\nGenerated: {datetime.now().strftime('%Y-%m-%d %H:%M')}")
        report.append(f"Total Prospects: {len(results)}")
        
        # Summary statistics
        avg_completeness = sum(r['completeness'] for r in results) / len(results)
        stale_count = sum(1 for r in results if r['days_old'] > 30)
        critical_gaps = sum(1 for r in results if r['completeness'] < 70)
        
        report.append(f"\n## Summary")
        report.append(f"- Average Completeness: {avg_completeness:.1f}%")
        report.append(f"- Stale Profiles (>30 days): {stale_count}")
        report.append(f"- Critical Gaps (<70% complete): {critical_gaps}")
        
        # Prospects needing immediate attention
        report.append(f"\n## 🚨 Immediate Attention Required")
        report.append("\n| Company | Completeness | Last Refresh | Age (days) | Critical Gaps |")
        report.append("|---------|--------------|--------------|------------|---------------|")
        
        for r in results[:10]:  # Top 10 worst
            if r['completeness'] < 70 or r['days_old'] > 60:
                gap_summary = ', '.join(f"{k}({len(v)})" for k, v in r['gaps'].items())
                report.append(f"| {r['company'][:30]} | {r['completeness']}% | {r['last_refreshed']} | {r['days_old']} | {gap_summary} |")
        
        # Gap frequency analysis
        gap_frequency = {}
        for r in results:
            for category, fields in r['gaps'].items():
                for field in fields:
                    gap_frequency[field] = gap_frequency.get(field, 0) + 1
        
        report.append(f"\n## 📊 Most Common Gaps")
        report.append("\n| Information Type | Missing Count | % of Prospects |")
        report.append("|------------------|---------------|----------------|")
        
        for gap, count in sorted(gap_frequency.items(), key=lambda x: x[1], reverse=True)[:10]:
            percentage = (count / len(results)) * 100
            report.append(f"| {gap} | {count} | {percentage:.1f}% |")
        
        # Completeness distribution
        report.append(f"\n## 📈 Completeness Distribution")
        report.append("\n| Range | Count | Prospects |")
        report.append("|-------|-------|-----------|")
        
        ranges = [(90, 100), (80, 89), (70, 79), (60, 69), (0, 59)]
        for low, high in ranges:
            in_range = [r for r in results if low <= r['completeness'] <= high]
            if in_range:
                companies = ', '.join(r['company'][:20] for r in in_range[:3])
                if len(in_range) > 3:
                    companies += f" (+{len(in_range)-3} more)"
                report.append(f"| {low}-{high}% | {len(in_range)} | {companies} |")
        
        # Action items
        report.append(f"\n## 🎯 Recommended Actions")
        report.append("\n1. **Immediate**: Refresh all prospects >60 days old")
        report.append("2. **This Week**: Fill executive information gaps (most common)")
        report.append("3. **This Month**: Complete all <70% profiles to minimum standard")
        report.append("4. **Ongoing**: Maintain 30-day refresh cycle")
        
        return '\n'.join(report)

def main():
    """Run gap analysis"""
    print("🔍 Running Prospect Research Gap Analysis...")
    
    # Initialize analyzer
    analyzer = ProspectGapAnalyzer('../')
    
    # Analyze all prospects
    results = analyzer.analyze_all_prospects()
    
    if not results:
        print("❌ No prospect files found!")
        return
    
    # Generate report
    report = analyzer.generate_report(results)
    
    # Save report
    report_file = Path('../GAP_ANALYSIS_REPORT.md')
    with open(report_file, 'w') as f:
        f.write(report)
    
    print(f"✅ Analysis complete! Found {len(results)} prospects")
    print(f"📄 Report saved to: {report_file}")
    
    # Print summary to console
    avg_completeness = sum(r['completeness'] for r in results) / len(results)
    print(f"\n📊 Summary:")
    print(f"   Average Completeness: {avg_completeness:.1f}%")
    print(f"   Least Complete: {results[0]['company']} ({results[0]['completeness']}%)")
    print(f"   Most Complete: {results[-1]['company']} ({results[-1]['completeness']}%)")

if __name__ == "__main__":
    main()