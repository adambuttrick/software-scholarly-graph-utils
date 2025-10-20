import re
import csv
import sys
import gzip
import json
import argparse
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Set, Tuple
from urllib.parse import urlsplit, urlunsplit


REPO_PATTERNS = [
    re.compile(
        r"https?://(?:www\.)?github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:/[^\s\"'<>]*)?",
        re.IGNORECASE,
    ),
    re.compile(
        r"https?://(?:www\.)?gitlab\.com/[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)+(?:/[^\s\"'<>]*)?",
        re.IGNORECASE,
    ),
    re.compile(
        r"https?://(?:www\.)?bitbucket\.org/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:/[^\s\"'<>]*)?",
        re.IGNORECASE,
    ),
    re.compile(
        r"https?://(?:www\.)?sourceforge\.net/projects/[A-Za-z0-9_.-]+(?:/[^\s\"'<>]*)?",
        re.IGNORECASE,
    ),
    re.compile(
        r"https?://(?:www\.)?codeberg\.org/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:/[^\s\"'<>]*)?",
        re.IGNORECASE,
    ),
    re.compile(
        r"https?://git\.(?:srht|sr\.ht)/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:/[^\s\"'<>]*)?",
        re.IGNORECASE,
    ),
    re.compile(
        r"https?://(?:www\.)?gitee\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:/[^\s\"'<>]*)?",
        re.IGNORECASE,
    ),
    re.compile(
        r"https?://(?!(?:www\.)?(?:github\.com|gitlab\.com|bitbucket\.org|sourceforge\.net|codeberg\.org|gitee\.com|git\.(?:srht|sr\.ht)))[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\.git",
        re.IGNORECASE,
    ),
]


ZENODO_DOI_PATTERN = re.compile(r"10\.5281/zenodo\.[^/\s\"']+", re.IGNORECASE)
ZENODO_RECORD_URL_PATTERN = re.compile(
    r"zenodo\.org/records?/(\d+)", re.IGNORECASE
)


def canonicalize_doi(value: Optional[str]) -> Optional[str]:
    if value is None:
        return None

    if not isinstance(value, str):
        value = str(value)

    stripped = value.strip()
    if not stripped:
        return None

    return stripped.lower()


def normalize_zenodo_doi(value: Optional[str]) -> Optional[str]:
    if value is None:
        return None

    if not isinstance(value, str):
        value = str(value)

    stripped = value.strip()
    if not stripped:
        return None

    lowered = stripped.lower()

    doi_match = ZENODO_DOI_PATTERN.search(lowered)
    if doi_match:
        return doi_match.group(0)

    record_match = ZENODO_RECORD_URL_PATTERN.search(lowered)
    if record_match:
        record_id = record_match.group(1)
        return f"10.5281/zenodo.{record_id}"

    return None


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Extract repository-like URLs from DataCite JSONL records and output the DOI-URL pairs."
        )
    )
    parser.add_argument(
        "-i",
        "--input",
        required=True,
        type=Path,
        help="Path to the jsonl or jsonl.gz file.",
    )
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        help="Optional path to write CSV output (defaults to stdout).",
    )
    parser.add_argument(
        "-f",
        "--format",
        choices={"csv", "json"},
        default="csv",
        help="Output format: csv (default) or json.",
    )
    parser.add_argument(
        "--include-git-suffix",
        action="store_true",
        help="Keep `.git` suffixes instead of trimming them from URLs.",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Print progress information to stderr.",
    )
    return parser.parse_args()


def open_text(path: Path) -> Iterator[str]:
    if path.suffix == ".gz":
        with gzip.open(path, "rt", encoding="utf-8", errors="replace") as handle:
            for line in handle:
                yield line
    else:
        with path.open("r", encoding="utf-8", errors="replace") as handle:
            for line in handle:
                yield line


def iter_strings(node) -> Iterator[str]:
    if isinstance(node, str):
        yield node
    elif isinstance(node, dict):
        for value in node.values():
            yield from iter_strings(value)
    elif isinstance(node, (list, tuple)):
        for item in node:
            yield from iter_strings(item)


def normalize_url(url: str, keep_git_suffix: bool) -> str:
    trimmed = url.rstrip(").,;\"'")
    if not keep_git_suffix and trimmed.endswith(".git"):
        trimmed = trimmed[:-4]
    return trimmed


def is_stop_segment(segment: str) -> bool:
    return segment in {
        "tree",
        "blob",
        "raw",
        "commit",
        "commits",
        "issues",
        "pull",
        "pulls",
        "merge_requests",
        "releases",
        "tags",
        "archive",
        "archives",
        "wiki",
        "wikis",
        "snippets",
        "pipelines",
        "builds",
        "jobs",
        "compare",
        "milestones",
        "-",
        "downloads",
    }


def canonicalize_path_parts(
    host: str, path_parts: List[str], keep_git_suffix: bool
) -> List[str]:
    if not path_parts:
        return path_parts

    host = host.lower()
    trimmed_parts: List[str] = []

    if host.endswith("github.com") or host.endswith("bitbucket.org") or host.endswith(
        "codeberg.org"
    ) or host.endswith("gitee.com"):
        trimmed_parts = path_parts[: min(2, len(path_parts))]
    elif host.endswith("gitlab.com"):
        for part in path_parts:
            if is_stop_segment(part):
                break
            trimmed_parts.append(part)
        if not trimmed_parts:
            trimmed_parts = path_parts[: min(2, len(path_parts))]
    elif host.endswith("sourceforge.net"):
        if "projects" in path_parts:
            idx = path_parts.index("projects")
            trimmed_parts = path_parts[: idx + 2 if idx + 1 < len(path_parts) else idx + 1]
        elif "p" in path_parts:
            idx = path_parts.index("p")
            trimmed_parts = path_parts[: idx + 2 if idx + 1 < len(path_parts) else idx + 1]
        else:
            trimmed_parts = path_parts[: min(2, len(path_parts))]
    else:
        trimmed_parts = []
        for part in path_parts:
            if is_stop_segment(part):
                break
            trimmed_parts.append(part)
        if not trimmed_parts:
            trimmed_parts = path_parts

    if trimmed_parts and not keep_git_suffix and trimmed_parts[-1].endswith(".git"):
        trimmed_parts[-1] = trimmed_parts[-1][:-4]

    return trimmed_parts


def canonicalize_url(url: str, keep_git_suffix: bool) -> str:
    parsed = urlsplit(url)
    if not parsed.scheme or not parsed.netloc:
        return url.rstrip("/")

    path_parts = [part for part in parsed.path.split("/") if part]
    trimmed_parts = canonicalize_path_parts(parsed.netloc, path_parts, keep_git_suffix)
    new_path = "/" + "/".join(trimmed_parts) if trimmed_parts else ""

    canonical = urlunsplit((parsed.scheme, parsed.netloc, new_path, "", ""))
    return canonical.rstrip("/")


def extract_repository_urls(text: str, keep_git_suffix: bool) -> Set[str]:
    urls: Set[str] = set()
    for pattern in REPO_PATTERNS:
        for match in pattern.finditer(text):
            matched_url = normalize_url(match.group(0), keep_git_suffix)
            canonical = canonicalize_url(matched_url, keep_git_suffix)
            urls.add(canonical)
    return urls


def gather_repositories(record: Dict, keep_git_suffix: bool) -> Set[str]:
    urls: Set[str] = set()
    for value in iter_strings(record):
        urls.update(extract_repository_urls(value, keep_git_suffix))
    return urls


def write_output(rows: List[Dict[str, Any]], output_path: Optional[Path], fmt: str) -> None:
    if fmt == "csv":
        output_stream = sys.stdout if output_path is None else output_path.open(
            "w", encoding="utf-8", newline=""
        )
        try:
            writer = csv.writer(output_stream)
            writer.writerow(
                [
                    "container_doi",
                    "repository_url",
                    "citation_count",
                    "citations_over_time",
                    "citation_relationships",
                    "version_dois",
                ]
            )
            for row in rows:
                citations_over_time = (
                    json.dumps(row["citations_over_time"], separators=(",", ":"))
                    if row["citations_over_time"]
                    else ""
                )
                citation_rel = (
                    json.dumps(row["citation_relationships"], separators=(",", ":"))
                    if row["citation_relationships"]
                    else ""
                )
                versions_str = ";".join(row["version_dois"])
                writer.writerow(
                    [
                        row["container_doi"],
                        row["repository_url"],
                        "" if row["citation_count"] is None else row["citation_count"],
                        citations_over_time,
                        citation_rel,
                        versions_str,
                    ]
                )
        finally:
            if output_path is not None:
                output_stream.close()
    else:
        output_stream = sys.stdout if output_path is None else output_path.open(
            "w", encoding="utf-8"
        )
        try:
            json.dump(rows, output_stream, indent=2)
            output_stream.write("\n")
        finally:
            if output_path is not None:
                output_stream.close()


def get_container_doi(record: Dict, default_doi: str) -> str:
    relationships = record.get("relationships") or {}
    version_of = relationships.get("versionOf") or {}
    data = version_of.get("data")

    candidate_ids: List[str] = []
    if isinstance(data, list):
        for item in data:
            if isinstance(item, dict):
                candidate = item.get("id")
                if candidate:
                    candidate_ids.append(candidate)
    elif isinstance(data, dict):
        candidate = data.get("id")
        if candidate:
            candidate_ids.append(candidate)

    for candidate in candidate_ids:
        normalized = normalize_zenodo_doi(candidate)
        if normalized:
            return canonicalize_doi(normalized) or normalized

    identifiers = record.get("attributes", {}).get("relatedIdentifiers", [])
    for item in identifiers:
        if not isinstance(item, dict):
            continue
        if item.get("relationType") != "IsVersionOf":
            continue
        related = item.get("relatedIdentifier")
        normalized = normalize_zenodo_doi(related)
        if normalized:
            return canonicalize_doi(normalized) or normalized

    container_attr = record.get("attributes", {}).get("container", {})
    if isinstance(container_attr, dict):
        identifier = container_attr.get("identifier")
        normalized = normalize_zenodo_doi(identifier)
        if normalized:
            return canonicalize_doi(normalized) or normalized

    normalized_default = normalize_zenodo_doi(default_doi)
    if normalized_default:
        return canonicalize_doi(normalized_default) or normalized_default

    normalized_id = normalize_zenodo_doi(record.get("id"))
    if normalized_id:
        return canonicalize_doi(normalized_id) or normalized_id

    canonical_default = canonicalize_doi(default_doi)
    if canonical_default:
        return canonical_default

    canonical_id = canonicalize_doi(record.get("id"))
    if canonical_id:
        return canonical_id

    fallback = record.get("attributes", {}).get("doi") or record.get("id") or default_doi
    if isinstance(fallback, str):
        return fallback.strip()
    return str(fallback)


def get_citation_info(record: Dict) -> Tuple[Optional[int], List[Dict], List[Dict]]:
    attributes = record.get("attributes") or {}
    relationships = record.get("relationships") or {}

    citation_count = attributes.get("citationCount")
    citations_over_time = attributes.get("citationsOverTime") or []
    if not isinstance(citations_over_time, list):
        citations_over_time = []

    citation_rel = relationships.get("citations") or {}
    citation_rel_data = citation_rel.get("data") or []
    if not isinstance(citation_rel_data, list):
        citation_rel_data = []

    return citation_count, citations_over_time, citation_rel_data


def main():
    args = parse_args()

    if not args.input.exists():
        print(f"Input file not found: {args.input}", file=sys.stderr)
        return 1

    container_to_urls: Dict[str, Set[str]] = {}
    container_to_versions: Dict[str, Set[str]] = {}
    citation_by_doi: Dict[str, Tuple[Optional[int], List[Dict], List[Dict]]] = {}
    container_citation: Dict[str, Tuple[Optional[int], List[Dict], List[Dict]]] = {}
    line_count = 0
    records_with_repos = 0

    for line in open_text(args.input):
        line_count += 1
        stripped = line.strip()
        if not stripped:
            continue
        try:
            record = json.loads(stripped)
        except json.JSONDecodeError as exc:
            if args.verbose:
                print(
                    f"Skipping line {line_count}: invalid JSON ({exc})",
                    file=sys.stderr,
                )
            continue

        attributes = record.get("attributes", {})
        raw_doi = attributes.get("doi") or record.get("id")
        doi = canonicalize_doi(raw_doi)
        if not doi:
            if args.verbose:
                print(f"Skipping line {line_count}: missing DOI/id", file=sys.stderr)
            continue

        container_doi = canonicalize_doi(get_container_doi(record, doi)) or doi
        container_versions = container_to_versions.setdefault(container_doi, set())
        container_versions.add(container_doi)
        container_versions.add(doi)

        citation_info = get_citation_info(record)
        citation_by_doi[doi] = citation_info
        if doi == container_doi:
            container_citation[container_doi] = citation_info

        urls = gather_repositories(record, args.include_git_suffix)
        if not urls:
            continue

        records_with_repos += 1
        container_urls = container_to_urls.setdefault(container_doi, set())
        container_urls.update(urls)

        if container_doi not in container_citation:
            container_citation[container_doi] = citation_info

    for container_doi, versions in container_to_versions.items():
        if container_doi in container_citation:
            continue
        for version_doi in sorted(versions):
            citation_info = citation_by_doi.get(version_doi)
            if citation_info is not None:
                container_citation[container_doi] = citation_info
                break

    rows: List[Dict[str, Any]] = []
    for container_doi in sorted(container_to_urls.keys()):
        urls = container_to_urls[container_doi]
        if not urls:
            continue
        versions = sorted(container_to_versions.get(container_doi, {container_doi}))
        version_dois = [version for version in versions if version != container_doi]
        citation_count, citations_over_time, citation_rel = container_citation.get(
            container_doi, (None, [], [])
        )
        for url in sorted(urls):
            rows.append(
                {
                    "container_doi": container_doi,
                    "repository_url": url,
                    "citation_count": citation_count,
                    "citations_over_time": citations_over_time,
                    "citation_relationships": citation_rel,
                    "version_dois": version_dois,
                }
            )

    write_output(rows, args.output, args.format)

    if args.verbose:
        print(f"Processed {line_count} lines", file=sys.stderr)
        print(
            f"Found {len(rows)} container→URL pairs across {records_with_repos} records",
            file=sys.stderr,
        )

    return 0


if __name__ == "__main__":
    sys.exit(main())
