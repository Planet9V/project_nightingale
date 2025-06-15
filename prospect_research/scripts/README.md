# Prospect Intelligence Enhancement Scripts

## 🔧 Available Scripts

### 1. `standardize_naming.py`
Fixes inconsistent file naming across all prospect files.
- Converts to format: `Company_Name_Prospect_Intelligence.md`
- Handles duplicates automatically
- Creates change log

### 2. `add_metadata.py`
Adds YAML frontmatter metadata to enable searching and categorization.
- Auto-detects sector and theme
- Extracts financial data
- Calculates quality scores

### 3. `populate_empty_files.py`
Generates initial content for empty prospect files.
- Uses standard template
- Sets up proper structure
- Prepares for enhancement

### 4. `enhance_prospect.py`
AI-powered intelligence enhancement using JINA and Tavily.
- Gathers web intelligence
- Checks vulnerabilities
- Generates executive summaries
- Identifies opportunities

## 🚀 Quick Start

```bash
# Run all scripts in sequence
python standardize_naming.py
python add_metadata.py
python populate_empty_files.py

# For full enhancement (requires API keys)
export JINA_API_KEY="your_key"
export TAVILY_API_KEY="your_key"
python enhance_prospect.py
```

## 📋 Requirements

- Python 3.8+
- PyYAML (`pip install pyyaml`)
- API keys for JINA and Tavily (for enhancement)

## 📊 Output Files

- `naming_changes.log` - Record of all file renames
- `metadata_summary.md` - Overview of all prospects
- `enhancement_report_*.json` - Detailed enhancement results

## 🔄 Automation

For weekly updates, add to cron:
```bash
0 0 * * 1 cd /path/to/scripts && python enhance_prospect.py
```

Or use GitHub Actions (see main proposal for workflow).