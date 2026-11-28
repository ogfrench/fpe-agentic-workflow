import hashlib
import json
from pathlib import Path
import re
import sys
import zipfile


def verified_digest_finding(finding, root):
    if finding.get("RuleID") != "generic-api-key":
        return False
    match = re.fullmatch(r"/scan/(agentic-workflow-chatgpt-v[0-9.]+\.zip)!assets/provenance\.json", finding.get("File", ""))
    if not match:
        return False
    with zipfile.ZipFile(root / match[1]) as archive:
        manifest = archive.read("assets/provenance.json").decode("utf-8")
        digests = json.loads(manifest)["sha256"]
        line = finding["StartLine"]
        if line != finding["EndLine"] or not 1 <= line <= len(manifest.splitlines()):
            return False
        entry = re.fullmatch(r'\s*("(?:[^"\\]|\\.)+"):\s*"([0-9a-f]{64})",?\s*', manifest.splitlines()[line - 1])
        if not entry:
            return False
        name, digest = json.loads(entry[1]), entry[2]
        return digests.get(name) == digest and hashlib.sha256(archive.read(name)).hexdigest() == digest


def main():
    report, root = Path(sys.argv[1]), Path(sys.argv[2])
    findings = json.loads(report.read_text())
    if not isinstance(findings, list) or not findings:
        return 1
    failed = False
    for finding in findings:
        verified = verified_digest_finding(finding, root)
        print(f"{finding['RuleID']}: {finding['File']}:{finding['StartLine']} ({'verified file digest' if verified else 'unresolved'})")
        failed |= not verified
    return int(failed)


if __name__ == "__main__":
    sys.exit(main())
