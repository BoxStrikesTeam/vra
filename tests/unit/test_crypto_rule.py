"""Tests for the crypto / PRNG misuse rule."""

from __future__ import annotations

from pathlib import Path

from vra.core.models import ProjectInfo, RuleContext
from vra.rules.crypto.crypto_misuse import SecureCryptoRule

SAMPLE = """\
#include <stdlib.h>
#include <time.h>

int gen(void) {
    srand(time(NULL));
    return rand();
}

void keys(void) {
    unsigned char key[16] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f};
    const char token[16] = "SuperSecretTokenValue";
    const char *nonsecret = "/some/path";
    unsigned char plain[16] = {1,2,3,4,5,6,7,8};
}

void hashes(void) {
    unsigned char digest[16];
    MD5(digest, (const unsigned char *)"x", 1);
}
"""

CLEAN = """\
#include <string.h>
size_t n = sizeof(int);
void f(void) { char buf[16]; (void)buf; }
"""


def _context(root: Path, content: str, name: str = "c.c") -> RuleContext:
    project = ProjectInfo(name="t", path=root, languages=["C"])
    return RuleContext(
        project=project,
        source_dir=root,
        file_path=str(root / name),
        file_content=content,
    )


def test_crypto_rule_findings(tmp_path: Path):
    rule = SecureCryptoRule()
    findings = rule.analyze(_context(tmp_path, SAMPLE))
    titles = [f.title for f in findings]
    assert any("time()" in t for t in titles)
    assert any("PRNG" in t for t in titles)
    assert any("Hard-coded" in t for t in titles)
    assert any("MD5/SHA-1" in t for t in titles)
    # Hard-coded material should carry higher confidence.
    hc = next(f for f in findings if "Hard-coded" in f.title)
    assert hc.confidence >= 0.5


def test_crypto_rule_clean(tmp_path: Path):
    rule = SecureCryptoRule()
    findings = rule.analyze(_context(tmp_path, CLEAN))
    assert findings == []
