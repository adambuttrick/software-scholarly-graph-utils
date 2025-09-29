# Extract Repo Links

Extract software repository URLs from markdown files and generate JSON summaries.

## Usage

```bash
python extract_repo_links.py -i INPUT_DIR -o OUTPUT_PATH [options]
```

## Arguments

- `-i, --input_dir`: Directory containing markdown files to search (required)
- `-o, --output_path`: Path for JSON output file or directory (required)
- `-e, --extensions`: File extensions to search (default: .md .markdown)
- `-r, --recursive`: Search subdirectories recursively
- `--hosts`: Repository hostnames to match (default: GitHub, GitLab, Bitbucket, etc.)

## Output

JSON file with repository URLs, occurrence counts, and context from markdown files.