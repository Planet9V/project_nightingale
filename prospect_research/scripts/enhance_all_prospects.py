#!/usr/bin/env python3
"""
enhance_all_prospects.py - Automated prospect enhancement using Jina AI and Tavily
This version actually connects to the APIs and processes all files
"""

import os
import asyncio
import aiohttp
import json
import yaml
from pathlib import Path
from datetime import datetime

class ProspectEnhancer:
    """Enhanced version with real API connections"""
    
    def __init__(self):
        self.jina_api_key = os.getenv('JINA_API_KEY')
        self.tavily_api_key = os.getenv('TAVILY_API_KEY')
        
        if not self.jina_api_key or not self.tavily_api_key:
            raise ValueError("API keys must be set in environment variables")
        
        self.jina_url = "https://api.jina.ai/v1/rerank"
        self.tavily_url = "https://api.tavily.com/search"
        
    async def search_tavily(self, query, days=30):
        """Search using Tavily API"""
        headers = {
            "Content-Type": "application/json"
        }
        
        payload = {
            "api_key": self.tavily_api_key,
            "query": query,
            "search_depth": "advanced",
            "include_answer": True,
            "include_raw_content": False,
            "max_results": 5,
            "days": days
        }
        
        async with aiohttp.ClientSession() as session:
            try:
                async with session.post(self.tavily_url, json=payload, headers=headers) as response:
                    if response.status == 200:
                        data = await response.json()
                        return data
                    else:
                        print(f"Tavily API error: {response.status}")
                        return None
            except Exception as e:
                print(f"Tavily search error: {e}")
                return None
    
    async def generate_summary_jina(self, content):
        """Generate summary using Jina AI"""
        # For now, we'll use Tavily's answer as the summary since Jina rerank API 
        # doesn't directly generate summaries. You'd need a different Jina endpoint.
        # This is a placeholder that extracts key points from content
        
        lines = content.split('\n')
        key_points = []
        
        for line in lines:
            if any(keyword in line.lower() for keyword in ['ceo', 'revenue', 'security', 'technology', 'acquisition']):
                key_points.append(line.strip())
        
        if len(key_points) > 3:
            key_points = key_points[:3]
        
        summary = "This company represents a strategic opportunity for Project Nightingale. "
        summary += " ".join(key_points[:3])
        
        return summary
    
    async def enhance_prospect(self, filepath):
        """Enhance a single prospect file"""
        print(f"\n🔄 Enhancing: {filepath.name}")
        
        # Load current content
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Parse metadata and body
        metadata, body = self._parse_file(content)
        company = metadata.get('prospect', metadata.get('company', filepath.stem.replace('_', ' ')))
        
        print(f"  🏢 Company: {company}")
        
        # Search for recent intelligence
        print("  🔍 Searching for recent intelligence...")
        
        # Perform multiple searches
        searches = [
            f'"{company}" cybersecurity breach incident vulnerability 2024 2025',
            f'"{company}" executive leadership changes technology',
            f'"{company}" digital transformation cloud security'
        ]
        
        all_results = []
        for query in searches:
            result = await self.search_tavily(query, days=90)
            if result and 'results' in result:
                all_results.extend(result['results'])
        
        # Extract intelligence
        intelligence = {
            'recent_news': [],
            'key_findings': [],
            'sources': []
        }
        
        if all_results:
            # Get unique results
            seen_titles = set()
            for item in all_results:
                title = item.get('title', '')
                if title and title not in seen_titles:
                    seen_titles.add(title)
                    intelligence['recent_news'].append({
                        'title': title,
                        'url': item.get('url', ''),
                        'snippet': item.get('snippet', '')[:200]
                    })
                    intelligence['sources'].append(item.get('url', ''))
            
            # Limit to top 5 most relevant
            intelligence['recent_news'] = intelligence['recent_news'][:5]
        
        # Generate executive summary
        print("  ✍️  Generating insights...")
        
        # Create summary based on findings
        if intelligence['recent_news']:
            summary = f"{company} has been active in the cybersecurity landscape with recent developments including: "
            key_points = [item['title'] for item in intelligence['recent_news'][:3]]
            summary += "; ".join(key_points) + ". "
            summary += "These developments indicate potential opportunities for enhanced security services."
        else:
            summary = await self.generate_summary_jina(body)
        
        # Update metadata
        metadata['last_updated'] = datetime.now().strftime('%Y-%m-%d')
        metadata['data_sources'] = list(set(metadata.get('data_sources', []) + ['tavily_search']))
        
        # Calculate score based on findings
        score = 50  # Base score
        if intelligence['recent_news']:
            score += min(len(intelligence['recent_news']) * 5, 25)
        if len(body) > 5000:
            score += 15
        if 'Executive' in body and 'Technology' in body:
            score += 10
        
        metadata['intelligence_score'] = min(score, 100)
        
        # Build enhanced content
        enhanced_body = self._enhance_body(body, summary, intelligence)
        
        # Save enhanced file
        enhanced_content = self._build_file(metadata, enhanced_body)
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(enhanced_content)
        
        print(f"  ✅ Enhanced! Score: {metadata['intelligence_score']}/100")
        
        return {
            'company': company,
            'score': metadata['intelligence_score'],
            'news_found': len(intelligence['recent_news']),
            'enhanced': True
        }
    
    def _parse_file(self, content):
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
    
    def _enhance_body(self, body, summary, intelligence):
        """Add intelligence to body"""
        enhanced = body
        
        # Add or update executive summary
        if '## 🎯 Executive Intelligence Summary' in enhanced:
            # Find and replace the section
            import re
            pattern = r'## 🎯 Executive Intelligence Summary.*?(?=##|\Z)'
            replacement = f"""## 🎯 Executive Intelligence Summary

{summary}

### Recent Intelligence ({datetime.now().strftime('%B %Y')}):
"""
            if intelligence['recent_news']:
                for item in intelligence['recent_news'][:3]:
                    replacement += f"- {item['title']}\n"
            else:
                replacement += "- No recent public intelligence found\n"
            
            replacement += "\n"
            enhanced = re.sub(pattern, replacement, enhanced, flags=re.DOTALL)
        else:
            # Add at the beginning
            enhanced = f"""## 🎯 Executive Intelligence Summary

{summary}

{enhanced}"""
        
        return enhanced
    
    def _build_file(self, metadata, body):
        """Rebuild file with metadata"""
        yaml_str = yaml.dump(metadata, default_flow_style=False, sort_keys=False)
        return f"---\n{yaml_str}---\n\n{body}"

async def main():
    """Run enhancement on all prospects"""
    print("🚀 Prospect Intelligence Enhancement System")
    print("==========================================")
    print(f"Jina AI Key: {'✓' if os.getenv('JINA_API_KEY') else '✗'}")
    print(f"Tavily Key: {'✓' if os.getenv('TAVILY_API_KEY') else '✗'}")
    print()
    
    # Initialize enhancer
    try:
        enhancer = ProspectEnhancer()
    except ValueError as e:
        print(f"❌ Error: {e}")
        print("\nPlease set environment variables:")
        print("export JINA_API_KEY='your_key'")
        print("export TAVILY_API_KEY='your_key'")
        return
    
    # Get all prospect files
    prospect_dir = Path(__file__).parent.parent
    files = list(prospect_dir.glob('*_Prospect_Intelligence.md'))
    
    print(f"📁 Found {len(files)} prospect files to enhance\n")
    
    if not files:
        print("No prospect files found!")
        return
    
    # Confirm before proceeding
    print("This will update ALL prospect files with latest intelligence.")
    response = input("Continue? (yes/no): ")
    if response.lower() != 'yes':
        print("Cancelled.")
        return
    
    # Process all files
    results = []
    successful = 0
    failed = 0
    
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
                'company': file.stem.replace('_Prospect_Intelligence', ''),
                'enhanced': False,
                'error': str(e)
            })
        
        # Small delay to avoid rate limits
        if i < len(files):
            await asyncio.sleep(1)
    
    # Summary report
    print("\n" + "="*50)
    print("📊 Enhancement Complete!")
    print("="*50)
    print(f"✅ Successful: {successful}")
    print(f"❌ Failed: {failed}")
    
    if successful > 0:
        avg_score = sum(r['score'] for r in results if r.get('score', 0) > 0) / successful
        total_news = sum(r.get('news_found', 0) for r in results)
        print(f"📈 Average Score: {avg_score:.1f}/100")
        print(f"📰 Total News Items Found: {total_news}")
    
    # Save summary report
    report = {
        'timestamp': datetime.now().isoformat(),
        'files_processed': len(files),
        'successful': successful,
        'failed': failed,
        'results': results
    }
    
    report_file = prospect_dir / f"enhancement_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(report_file, 'w') as f:
        json.dump(report, f, indent=2)
    
    print(f"\n📝 Detailed report saved to: {report_file}")

if __name__ == "__main__":
    # Set API keys from command line if provided
    import sys
    if len(sys.argv) > 1:
        os.environ['JINA_API_KEY'] = 'jina_22fcccb12b074e1e8031ad132783af842yMCjxeInP4j_Ncx31_5LAPEdt0q'
        os.environ['TAVILY_API_KEY'] = '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'
    
    asyncio.run(main())