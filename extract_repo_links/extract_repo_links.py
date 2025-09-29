import re
import json
import argparse
from pathlib import Path
from collections import defaultdict
from urllib.parse import urlparse, urlunparse
from typing import Dict, Iterable, Iterator, List, Sequence, Tuple, cast


URL_PATTERN = re.compile(
    r"https?\s*:\s*/\s*/[^\s<>\[\]\)\}\"']+", re.IGNORECASE)
CONTINUATION_CHUNK = re.compile(r"\s+((?:\\[^\s]|[A-Za-z0-9/_\-.~%#=&?+])+)")
ALLOWED_EXTENSION_STARTS = set("/?#=&._~%+")

DEFAULT_REPO_HOSTS = {
    "github.com",
    "gitlab.com",
    "bitbucket.org",
    "sourceforge.net",
    "codeberg.org",
    "gitea.com",
    "savannah.gnu.org",
    "savannah.nongnu.org",
    "gitee.com",
    "git.sr.ht",
    "hg.sr.ht",
    "sr.ht",
    "pagure.io",
    "heptapod.net",
}

GIT_STYLE_HOSTS = {
    "github.com",
    "gitlab.com",
    "bitbucket.org",
    "codeberg.org",
    "gitea.com",
    "sourceforge.net",
    "savannah.gnu.org",
    "savannah.nongnu.org",
    "gitee.com",
    "git.sr.ht",
    "hg.sr.ht",
    "sr.ht",
    "pagure.io",
    "heptapod.net",
}

NON_SUBDOMAIN_HOSTS = {
    "github.com",
    "gitlab.com",
    "bitbucket.org",
    "codeberg.org",
    "gitea.com",
    "gitee.com",
    "git.sr.ht",
    "hg.sr.ht",
    "sr.ht",
    "pagure.io",
    "heptapod.net",
}


def parse_arguments():
    parser = argparse.ArgumentParser(
        description="Locate software repository URLs in markdown files and emit JSON summaries.",)
    parser.add_argument("-i", "--input_dir", type=Path, required=True,
                        help="Directory containing markdown files to search.",)
    parser.add_argument("-o", "--output_path", type=Path, required=True,
                        help="Path for the aggregated JSON output (file or directory).",)
    parser.add_argument("-e", "--extensions", nargs="+", default=(".md", ".markdown"),
                        help="File extensions to include in the search (default: .md .markdown).",)
    parser.add_argument("-r", "--recursive", action="store_true",
                        help="Recursively search for markdown files.",)
    parser.add_argument("--hosts", nargs="+", default=sorted(DEFAULT_REPO_HOSTS),
                        help="Repository hostnames to flag. Matches include subdomains.")
    return parser


def clean_url(raw: str) -> str:
    trimmed = raw.strip()
    trimmed = trimmed.rstrip(".,);:'\"\\")
    collapsed = "".join(trimmed.split())
    collapsed = collapsed.rstrip(".,);:'\"\\")
    collapsed = re.sub(r"\\([^\s])", r"\1", collapsed)
    lower = collapsed.lower()
    if lower.startswith("http://"):
        return "http://" + collapsed[7:]
    if lower.startswith("https://"):
        return "https://" + collapsed[8:]
    return collapsed


def should_extend_url(prev_char: str, next_char: str, host: str) -> bool:
    if not prev_char or not next_char:
        return False
    if not (next_char.isalnum() or next_char in ALLOWED_EXTENSION_STARTS):
        return False
    git_style_host = host in GIT_STYLE_HOSTS
    if prev_char == '.' and next_char.isdigit():
        return True
    if git_style_host and prev_char in "/?=&-_:#%+":
        return True
    if not git_style_host and prev_char in "?&#%+=":
        return True

    return False


def extract_raw_url(text: str, match: re.Match[str]) -> str:
    start, end = match.span()
    portion = text[start:end]
    stripped = portion.rstrip()
    prev_char = stripped[-1] if stripped else ''
    condensed = ''.join(portion.split())
    if condensed:
        try:
            host = normalize_host(urlparse(condensed).netloc)
        except ValueError:
            host = ''
    else:
        host = ''
    cursor = end
    while cursor < len(text):
        continuation = CONTINUATION_CHUNK.match(text, cursor)
        if not continuation:
            break
        chunk = continuation.group(1)
        next_char = chunk[0]
        if not should_extend_url(prev_char, next_char, host):
            break
        portion += continuation.group(0)
        cursor += len(continuation.group(0))
        prev_char = chunk[-1]

    return portion


def canonicalize_repo_path(host: str, path: str) -> str:
    parts = [segment for segment in path.split('/') if segment]
    if host in GIT_STYLE_HOSTS and len(parts) >= 2:
        return "/" + "/".join(parts[:2])
    if host in {"launchpad.net"} and len(parts) >= 2:
        return "/" + "/".join(parts[:2])

    return path


def sanitize_path(path: str) -> str:
    if not path:
        return "/"
    segments = [segment for segment in path.split('/') if segment]
    cleaned = [seg for seg in segments if any(ch.isalnum() for ch in seg)]
    if not cleaned:
        return "/"

    return "/" + "/".join(cleaned)


def canonicalize_repo_url(parsed_url) -> str:
    host = normalize_host(parsed_url.netloc)
    path = canonicalize_repo_path(host, parsed_url.path)
    path = sanitize_path(path)
    segments = [segment for segment in path.split('/') if segment]
    if host in GIT_STYLE_HOSTS and len(segments) < 2:
        return ""
    scheme = (parsed_url.scheme or "").lower()
    if scheme not in {"http", "https"}:
        scheme = "https"
    if host in DEFAULT_REPO_HOSTS or scheme == "https":
        scheme = "https"
    if not scheme:
        scheme = "https"
    cleaned = parsed_url._replace(
        scheme=scheme,
        netloc=host,
        path=path,
        params="",
        query="",
        fragment="",
    )

    return urlunparse(cleaned)


def normalize_host(host: str) -> str:
    host = host.lower()
    if host.startswith("www."):
        host = host[4:]

    return host


def host_matches_allowed(host: str, allowed: str) -> bool:
    allowed = allowed.lower()
    if allowed in NON_SUBDOMAIN_HOSTS:
        return host == allowed

    return host == allowed or host.endswith(f".{allowed}")


def is_repo_host(host: str, allowed_hosts: Sequence[str]) -> bool:
    host = normalize_host(host)
    for allowed in allowed_hosts:
        if host_matches_allowed(host, allowed):
            return True

    return False


def extract_context(block: str, match_start: int) -> str:
    left_boundary = block.rfind("\n\n", 0, match_start)
    right_boundary = block.find("\n\n", match_start)
    start = left_boundary + 2 if left_boundary != -1 else 0
    end = right_boundary if right_boundary != -1 else len(block)

    return block[start:end].strip()


def iter_markdown_files(root: Path, extensions: Iterable[str], recursive: bool) -> Iterator[Path]:
    normalized_exts = {ext.lower() if ext.startswith('.') else f'.{ext.lower()}' for ext in extensions}
    if recursive:
        iterator = root.rglob("*")
    else:
        iterator = root.glob("*")
    for path in iterator:
        if path.is_file() and path.suffix.lower() in normalized_exts:
            yield path


def find_repository_links(text: str, allowed_hosts: Sequence[str]) -> List[dict]:
    matches = []
    for match in URL_PATTERN.finditer(text):
        raw_url = clean_url(extract_raw_url(text, match))
        if not raw_url or '://' not in raw_url:
            continue
        parsed = urlparse(raw_url)
        if not parsed.netloc:
            continue
        canonical_url = canonicalize_repo_url(parsed)
        if not canonical_url:
            continue
        canonical_parsed = urlparse(canonical_url)
        if not is_repo_host(canonical_parsed.netloc, allowed_hosts) and not canonical_parsed.path.endswith('.git'):
            continue
        context = extract_context(text, match.start())
        matches.append(
            {
                "url": canonical_url,
                "context": context,
            }
        )
        
    return matches


def main():
    parser = parse_arguments()
    args = parser.parse_args()
    input_dir: Path = args.input_dir
    output_path: Path = args.output_path
    extensions = args.extensions
    allowed_hosts = args.hosts
    recursive: bool = args.recursive
    if not input_dir.exists() or not input_dir.is_dir():
        parser.error(f"Input directory does not exist or is not a directory: {input_dir}")
    output_file: Path
    if output_path.suffix and not output_path.is_dir():
        output_file = output_path
        output_file.parent.mkdir(parents=True, exist_ok=True)
    else:
        output_path.mkdir(parents=True, exist_ok=True)
        output_file = output_path / "repositories.json"
    files_processed = 0
    files_with_matches = 0
    matches_found = 0
    matched_files: set[Path] = set()
    repo_occurrences: Dict[Tuple[str, str], Dict[str, object]] = defaultdict(
        lambda: {"url": "", "occurrences": [], "seen": set()}
    )
    for md_file in iter_markdown_files(input_dir, extensions, recursive):
        files_processed += 1
        text = md_file.read_text(encoding="utf-8", errors="ignore")
        records = find_repository_links(text, allowed_hosts)
        if not records:
            continue
        relative_path = md_file.relative_to(input_dir)
        matched_files.add(relative_path)
        for record in records:
            occurrence_key = (str(relative_path), record["context"])
            parsed_url = urlparse(record["url"])
            repo_key = (parsed_url.netloc, parsed_url.path or "/")
            repo_entry = repo_occurrences[repo_key]
            stored_url = cast(str, repo_entry["url"])
            if not stored_url:
                repo_entry["url"] = record["url"]
            else:
                existing_scheme = urlparse(stored_url).scheme.lower()
                new_scheme = parsed_url.scheme.lower()
                if existing_scheme != "https" and new_scheme == "https":
                    repo_entry["url"] = record["url"]
            seen_keys = cast(set[Tuple[str, str]], repo_entry["seen"])
            if occurrence_key in seen_keys:
                continue
            seen_keys.add(occurrence_key)
            repo_entry["occurrences"].append(
                {
                    "file": str(relative_path),
                    "context": record["context"],
                }
            )
            matches_found += 1

    files_with_matches = len(matched_files)

    repositories = []
    for data in repo_occurrences.values():
        occurrences = data["occurrences"]
        repositories.append(
            {
                "url": cast(str, data["url"]),
                "occurrences": occurrences,
            }
        )
    repositories.sort(key=lambda entry: entry["url"])

    summary = {
        "files_processed": files_processed,
        "files_with_matches": files_with_matches,
        "matches_found": matches_found,
        "unique_repositories": len(repositories),
        "repositories": repositories,
    }
    with output_file.open("w", encoding="utf-8") as handle:
        json.dump(summary, handle, ensure_ascii=False, indent=2)


if __name__ == "__main__":
    main()
