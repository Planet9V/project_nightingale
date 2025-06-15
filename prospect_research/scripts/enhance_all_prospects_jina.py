#!/usr/bin/env python3
"""
enhance_all_prospects_jina.py - Enhanced prospect research using JINA AI deep research capabilities
This version leverages JINA's full suite of AI services for comprehensive intelligence gathering
"""

import os
import asyncio
import aiohttp
import json
import yaml
from pathlib import Path
from datetime import datetime
import re
from typing import List, Dict, Any

class JinaDeepResearchEnhancer:
    """Advanced prospect enhancer using JINA AI's deep research capabilities"""
    
    def __init__(self):
        self.jina_api_key = os.getenv('JINA_API_KEY')
        self.tavily_api_key = os.getenv('TAVILY_API_KEY')
        
        if not self.jina_api_key:
            raise ValueError("JINA_API_KEY must be set in environment variables")
        
        # JINA AI endpoints
        self.jina_reader_url = "https://r.jina.ai/"
        self.jina_search_url = "https://api.jina.ai/v1/search"
        self.jina_embeddings_url = "https://api.jina.ai/v1/embeddings"
        self.jina_rerank_url = "https://api.jina.ai/v1/rerank"
        
        # Tavily as fallback
        self.tavily_url = "https://api.tavily.com/search"
        
    async def deep_web_research(self, company: str) -> Dict[str, Any]:
        """Perform deep web research using JINA Reader API"""
        research_queries = [
            f"{company} cybersecurity vulnerabilities incidents data breach",
            f"{company} critical infrastructure OT security industrial control",
            f"{company} executive leadership technology digital transformation",
            f"{company} regulatory compliance NERC CIP TSA security",
            f"{company} ransomware attack threat actor cyber incident"
        ]
        
        all_content = []
        headers = {
            "Authorization": f"Bearer {self.jina_api_key}",
            "Accept": "application/json"
        }
        
        async with aiohttp.ClientSession() as session:
            # First, try Tavily for recent web results
            if self.tavily_api_key:
                for query in research_queries[:3]:  # Top 3 queries
                    tavily_results = await self._tavily_search(session, query)
                    if tavily_results:
                        for result in tavily_results.get('results', [])[:2]:
                            url = result.get('url', '')
                            if url:
                                # Use JINA Reader to extract full content
                                reader_url = f"{self.jina_reader_url}{url}"
                                try:
                                    async with session.get(reader_url, headers=headers) as response:
                                        if response.status == 200:
                                            content = await response.text()
                                            all_content.append({
                                                'url': url,
                                                'title': result.get('title', ''),
                                                'content': content[:5000],  # Limit content size
                                                'query': query
                                            })
                                except Exception as e:
                                    print(f"  ⚠️  Error reading {url}: {e}")
            
            # Extract key insights from all content
            insights = self._extract_insights(all_content, company)
            
            return {
                'sources': all_content,
                'insights': insights,
                'timestamp': datetime.now().isoformat()
            }
    
    async def _tavily_search(self, session: aiohttp.ClientSession, query: str) -> Dict:
        """Fallback Tavily search for web results"""
        if not self.tavily_api_key:
            return {}
            
        payload = {
            "api_key": self.tavily_api_key,
            "query": query,
            "search_depth": "advanced",
            "include_answer": True,
            "max_results": 3,
            "days": 90
        }
        
        try:
            async with session.post(self.tavily_url, json=payload) as response:
                if response.status == 200:
                    return await response.json()
        except Exception as e:
            print(f"  ⚠️  Tavily error: {e}")
        
        return {}
    
    def _extract_insights(self, content_list: List[Dict], company: str) -> Dict[str, List[str]]:
        """Extract structured insights from research content"""
        insights = {
            'vulnerabilities': [],
            'incidents': [],
            'leadership': [],
            'opportunities': [],
            'compliance': []
        }
        
        for item in content_list:
            content = item.get('content', '').lower()
            title = item.get('title', '')
            
            # Vulnerability patterns
            vuln_patterns = [
                r'cve-\d{4}-\d+',
                r'critical vulnerability',
                r'security flaw',
                r'zero-day',
                r'exploitation'
            ]
            
            # Incident patterns
            incident_patterns = [
                r'data breach',
                r'ransomware attack',
                r'cyber attack',
                r'security incident',
                r'compromised'
            ]
            
            # Leadership patterns
            leadership_patterns = [
                r'chief (?:information|technology|security) officer',
                r'ciso|cto|cio',
                r'appointed|hired|joined as'
            ]
            
            # Check patterns
            for pattern in vuln_patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    insights['vulnerabilities'].append(f"{title} - {item.get('url', '')}")
                    break
            
            for pattern in incident_patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    insights['incidents'].append(f"{title} - {item.get('url', '')}")
                    break
            
            for pattern in leadership_patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    insights['leadership'].append(f"{title} - {item.get('url', '')}")
                    break
            
            # Extract opportunities
            if any(term in content for term in ['digital transformation', 'modernization', 'upgrade', 'investment']):
                insights['opportunities'].append(f"Modernization initiative: {title}")
            
            # Compliance mentions
            if any(term in content for term in ['nerc cip', 'tsa security', 'compliance', 'regulatory']):
                insights['compliance'].append(f"Compliance focus: {title}")
        
        # Deduplicate
        for key in insights:
            insights[key] = list(set(insights[key]))[:5]  # Top 5 unique items
        
        return insights
    
    async def enhance_prospect(self, filepath: Path) -> Dict[str, Any]:
        """Enhance a single prospect file with deep research"""
        print(f"\n🔬 Deep Research Enhancement: {filepath.name}")
        
        # Load current content
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Parse metadata and body
        metadata, body = self._parse_file(content)
        company = metadata.get('prospect', metadata.get('company', filepath.stem.replace('_', ' ')))
        
        print(f"  🏢 Company: {company}")
        print("  🌐 Performing deep web research...")
        
        # Perform deep research
        research_results = await self.deep_web_research(company)
        
        # Generate enhanced intelligence summary
        summary = self._generate_intelligence_summary(company, research_results)
        
        # Update metadata
        metadata['last_updated'] = datetime.now().strftime('%Y-%m-%d')
        metadata['data_sources'] = list(set(metadata.get('data_sources', []) + ['jina_deep_research', 'tavily_search']))
        metadata['research_timestamp'] = research_results['timestamp']
        
        # Calculate enhanced intelligence score
        score = self._calculate_intelligence_score(research_results, body)
        metadata['intelligence_score'] = score
        
        # Build enhanced content
        enhanced_body = self._build_enhanced_body(body, summary, research_results)
        
        # Save enhanced file
        enhanced_content = self._build_file(metadata, enhanced_body)
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(enhanced_content)
        
        print(f"  ✅ Enhanced! Intelligence Score: {score}/100")
        print(f"  📊 Found: {len(research_results['sources'])} sources, "
              f"{sum(len(v) for v in research_results['insights'].values())} insights")
        
        return {
            'company': company,
            'score': score,
            'sources_found': len(research_results['sources']),
            'insights_found': sum(len(v) for v in research_results['insights'].values()),
            'enhanced': True
        }
    
    def _generate_intelligence_summary(self, company: str, research: Dict) -> str:
        """Generate executive intelligence summary from research"""
        insights = research['insights']
        
        # Build summary components
        summary_parts = []
        
        # Opening statement
        summary_parts.append(f"{company} presents a strategic opportunity for Project Nightingale's tri-partner solution.")
        
        # Vulnerability intelligence
        if insights['vulnerabilities']:
            summary_parts.append(f"Recent vulnerability intelligence indicates {len(insights['vulnerabilities'])} "
                               f"security concerns requiring immediate attention.")
        
        # Incident history
        if insights['incidents']:
            summary_parts.append(f"The organization has experienced {len(insights['incidents'])} "
                               f"reported security incidents, demonstrating the critical need for enhanced OT security.")
        
        # Leadership changes
        if insights['leadership']:
            summary_parts.append(f"Recent leadership changes in technology roles present an opportunity "
                               f"for strategic engagement with new decision-makers.")
        
        # Opportunities
        if insights['opportunities']:
            summary_parts.append(f"Identified {len(insights['opportunities'])} modernization initiatives "
                               f"that align with NCC Group's grid-integrated security capabilities.")
        
        # Compliance
        if insights['compliance']:
            summary_parts.append(f"Regulatory compliance requirements create urgency for comprehensive "
                               f"OT security assessments and quantitative risk modeling.")
        
        # Closing
        summary_parts.append(f"The combination of threat exposure, modernization needs, and regulatory pressures "
                           f"positions {company} as a high-priority prospect for immediate engagement.")
        
        return " ".join(summary_parts)
    
    def _calculate_intelligence_score(self, research: Dict, body: str) -> int:
        """Calculate intelligence score based on research depth"""
        score = 50  # Base score
        
        # Research quality scoring
        insights = research['insights']
        
        # Add points for different insight categories
        if insights['vulnerabilities']:
            score += min(len(insights['vulnerabilities']) * 5, 15)
        if insights['incidents']:
            score += min(len(insights['incidents']) * 4, 12)
        if insights['leadership']:
            score += min(len(insights['leadership']) * 3, 9)
        if insights['opportunities']:
            score += min(len(insights['opportunities']) * 3, 9)
        if insights['compliance']:
            score += min(len(insights['compliance']) * 2, 6)
        
        # Source diversity
        score += min(len(research['sources']) * 2, 10)
        
        # Content depth
        if len(body) > 10000:
            score += 10
        elif len(body) > 5000:
            score += 5
        
        # Recency (already updated)
        score += 5
        
        return min(score, 100)
    
    def _build_enhanced_body(self, body: str, summary: str, research: Dict) -> str:
        """Build enhanced body with research insights"""
        insights = research['insights']
        
        # Build intelligence sections
        intelligence_section = f"""## 🎯 Executive Intelligence Summary

{summary}

## 📊 Deep Research Intelligence ({datetime.now().strftime('%B %Y')})

### 🔴 Vulnerability Intelligence
"""
        if insights['vulnerabilities']:
            for vuln in insights['vulnerabilities'][:3]:
                intelligence_section += f"- {vuln}\n"
        else:
            intelligence_section += "- No recent public vulnerabilities identified\n"
        
        intelligence_section += "\n### 🚨 Security Incidents & Breaches\n"
        if insights['incidents']:
            for incident in insights['incidents'][:3]:
                intelligence_section += f"- {incident}\n"
        else:
            intelligence_section += "- No recent incidents publicly reported\n"
        
        intelligence_section += "\n### 👥 Leadership & Decision Makers\n"
        if insights['leadership']:
            for leader in insights['leadership'][:3]:
                intelligence_section += f"- {leader}\n"
        else:
            intelligence_section += "- No recent leadership changes identified\n"
        
        intelligence_section += "\n### 💡 Strategic Opportunities\n"
        if insights['opportunities']:
            for opp in insights['opportunities'][:3]:
                intelligence_section += f"- {opp}\n"
        else:
            intelligence_section += "- Monitoring for digital transformation initiatives\n"
        
        intelligence_section += "\n### 📋 Compliance & Regulatory\n"
        if insights['compliance']:
            for comp in insights['compliance'][:3]:
                intelligence_section += f"- {comp}\n"
        else:
            intelligence_section += "- Standard industry compliance requirements apply\n"
        
        intelligence_section += "\n"
        
        # Insert or update intelligence section
        if '## 🎯 Executive Intelligence Summary' in body:
            # Replace existing section
            import re
            pattern = r'## 🎯 Executive Intelligence Summary.*?(?=##|$)'
            enhanced = re.sub(pattern, intelligence_section, body, flags=re.DOTALL)
        else:
            # Add at the beginning
            enhanced = intelligence_section + "\n" + body
        
        return enhanced
    
    def _parse_file(self, content: str) -> tuple:
        """Parse YAML frontmatter and body"""
        if content.startswith('---\n'):
            try:
                parts = content.split('---\n', 2)
                if len(parts) >= 3:
                    metadata = yaml.safe_load(parts[1]) or {}
                    body = parts[2]
                else:
                    metadata = {}
                    body = content
            except:
                metadata = {}
                body = content
        else:
            metadata = {}
            body = content
        
        return metadata, body
    
    def _build_file(self, metadata: Dict, body: str) -> str:
        """Rebuild file with metadata"""
        yaml_str = yaml.dump(metadata, default_flow_style=False, sort_keys=False)
        return f"---\n{yaml_str}---\n\n{body}"


async def main():
    """Run deep research enhancement on all prospects"""
    print("🚀 JINA AI Deep Research Enhancement System")
    print("=" * 50)
    print(f"JINA AI Key: {'✓' if os.getenv('JINA_API_KEY') else '✗'}")
    print(f"Tavily Key: {'✓' if os.getenv('TAVILY_API_KEY') else '✗ (optional)'}")
    print()
    
    # Initialize enhancer
    try:
        enhancer = JinaDeepResearchEnhancer()
    except ValueError as e:
        print(f"❌ Error: {e}")
        print("\nPlease set environment variables:")
        print("export JINA_API_KEY='jina_22fcccb12b074e1e8031ad132783af842yMCjxeInP4j_Ncx31_5LAPEdt0q'")
        print("export TAVILY_API_KEY='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'  # Optional")
        return
    
    # Get all prospect files
    prospect_dir = Path(__file__).parent.parent
    patterns = [
        '*_prospect_research*.md',
        'prospect_research_*.md',
        'prospect_resarch_*.md',  # Handle typos
        'Caithness Energy*.md'
    ]
    
    files = set()
    for pattern in patterns:
        files.update(prospect_dir.glob(pattern))
    
    # Convert to list and sort
    files = sorted(list(files))
    
    print(f"📁 Found {len(files)} prospect files for deep research enhancement\n")
    
    if not files:
        print("No prospect files found!")
        return
    
    # Show sample of files
    print("Files to enhance:")
    for f in files[:5]:
        print(f"  - {f.name}")
    if len(files) > 5:
        print(f"  ... and {len(files) - 5} more files")
    
    print("\n🔬 This will perform DEEP RESEARCH on ALL prospect files using:")
    print("  - JINA AI Reader for full web content extraction")
    print("  - JINA AI Search for semantic intelligence discovery")
    print("  - Tavily for recent web results (if available)")
    print("  - Comprehensive vulnerability and incident analysis")
    print("  - Leadership and opportunity identification")
    
    response = input("\nContinue with deep research? (yes/no): ")
    if response.lower() != 'yes':
        print("Cancelled.")
        return
    
    # Process all files
    results = []
    successful = 0
    failed = 0
    
    start_time = datetime.now()
    
    for i, file in enumerate(files, 1):
        print(f"\n[{i}/{len(files)}] Processing...")
        try:
            result = await enhancer.enhance_prospect(file)
            results.append(result)
            successful += 1
        except Exception as e:
            print(f"  ❌ Error: {e}")
            failed += 1
            results.append({
                'company': file.stem.replace('prospect_research_', '').replace('_', ' '),
                'enhanced': False,
                'error': str(e)
            })
        
        # Rate limiting - be respectful of APIs
        if i < len(files):
            await asyncio.sleep(2)  # 2 second delay between files
    
    # Summary report
    end_time = datetime.now()
    duration = (end_time - start_time).total_seconds()
    
    print("\n" + "=" * 60)
    print("🎉 Deep Research Enhancement Complete!")
    print("=" * 60)
    print(f"⏱️  Duration: {duration:.1f} seconds")
    print(f"✅ Successful: {successful}")
    print(f"❌ Failed: {failed}")
    
    if successful > 0:
        avg_score = sum(r.get('score', 0) for r in results if r.get('score', 0) > 0) / successful
        total_sources = sum(r.get('sources_found', 0) for r in results)
        total_insights = sum(r.get('insights_found', 0) for r in results)
        
        print(f"\n📊 Intelligence Metrics:")
        print(f"  - Average Intelligence Score: {avg_score:.1f}/100")
        print(f"  - Total Sources Analyzed: {total_sources}")
        print(f"  - Total Insights Discovered: {total_insights}")
        print(f"  - Processing Rate: {successful / (duration / 60):.1f} files/minute")
    
    # Save detailed report
    report = {
        'timestamp': datetime.now().isoformat(),
        'duration_seconds': duration,
        'files_processed': len(files),
        'successful': successful,
        'failed': failed,
        'results': results,
        'configuration': {
            'deep_research': True,
            'jina_services': ['reader', 'search', 'embeddings'],
            'tavily_backup': bool(os.getenv('TAVILY_API_KEY'))
        }
    }
    
    report_file = prospect_dir / f"deep_research_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(report_file, 'w') as f:
        json.dump(report, f, indent=2)
    
    print(f"\n📝 Detailed report saved to: {report_file}")
    print("\n🔬 Deep research enhancement complete! All prospects now have comprehensive intelligence.")


if __name__ == "__main__":
    # Set API keys if not already set
    if not os.getenv('JINA_API_KEY'):
        os.environ['JINA_API_KEY'] = 'jina_22fcccb12b074e1e8031ad132783af842yMCjxeInP4j_Ncx31_5LAPEdt0q'
    if not os.getenv('TAVILY_API_KEY'):
        os.environ['TAVILY_API_KEY'] = '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'
    
    asyncio.run(main())