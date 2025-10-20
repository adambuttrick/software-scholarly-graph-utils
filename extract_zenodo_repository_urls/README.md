# Extract Zenodo Repository URLs

Extracts repository URLs (GitHub, GitLab, Bitbucket, etc.) and basic metadata from Zenodo DataCite data file/JSONL records.


## Usage

```bash
# Basic CSV output to stdout
python extract_zenodo_repository_urls.py -i input.jsonl

# Write to file
python extract_zenodo_repository_urls.py -i input.jsonl.gz -o output.csv

# JSON output format
python extract_zenodo_repository_urls.py -i input.jsonl -f json -o output.json

# Keep .git suffixes
python extract_zenodo_repository_urls.py -i input.jsonl --include-git-suffix

# Verbose mode
python extract_zenodo_repository_urls.py -i input.jsonl --verbose
```

## Output

CSV columns:
- `container_doi`: Zenodo container DOI
- `repository_url`: Canonicalized repository URL
- `citation_count`: Citation count
- `citations_over_time`: JSON array of citation history
- `citation_relationships`: JSON array of citation relationships
- `version_dois`: Semicolon-separated version DOIs

## Supported Repositories

- GitHub
- GitLab
- Bitbucket
- SourceForge
- Codeberg
- Sourcehut (git.sr.ht)
- Gitee
- Generic .git URLs
