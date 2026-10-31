#!/usr/bin/env python3
"""Lieferketten-Gate: Auswertung von OSV-Scanner und GuardDog (nur Standardbibliothek).

Vorlage der Betriebszentrale (FeierabendSysAdnNetAdmin, Schwachstellen-Patrouille §7),
abgeleitet vom Gate in afhOS (ADR-0090). Aufruf nur aus
.github/workflows/supply-chain-gate.yml:

  gate.py osv <osv.json>      bewertet den OSV-Bericht
  gate.py guarddog --base REF  scannt nur neue oder geaenderte Abhaengigkeiten

Blockiert immer: Schadpakete (OSV-ID/Alias MAL-*), GuardDog-Risiko >= 5 ohne Ausnahme,
Pakete ausserhalb der Standard-Registry ohne Ausnahme, Werkzeugfehler (fail-closed).
Blockiert erst mit Repo-Variable SUPPLY_CHAIN_BLOCK_VULNS=true: bekannte Schwachstellen
mit verfuegbarem Fix und Schwere HIGH/CRITICAL (bzw. CVSS >= 7). Vorher nur Bericht.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import re
import subprocess
import sys
import tomllib
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(os.environ.get("GITHUB_WORKSPACE", ".")).resolve()
GATE_DIR = Path(__file__).resolve().parent
ALLOWLIST = GATE_DIR / "guarddog-allowlist.txt"
NPM_REGISTRY = "https://registry.npmjs.org/"
BLOCK_SCORE = 5.0
HIGH_CVSS = 7.0
REQ = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?==([^\s;\\]+)")
LOCKFILES = re.compile(r"(^|/)(package-lock\.json|uv\.lock|requirements[^/]*\.txt|composer\.lock)$")


def block_vulns() -> bool:
    return os.environ.get("SUPPLY_CHAIN_BLOCK_VULNS", "").strip().lower() == "true"


def summary(lines: list[str]) -> None:
    path = os.environ.get("GITHUB_STEP_SUMMARY")
    if path:
        with open(path, "a", encoding="utf-8") as fh:
            fh.write("\n".join(lines) + "\n\n")
    else:
        print("\n".join(lines))


# ------------------------------------------------------------------ OSV

@dataclass
class Finding:
    source: str
    package: str
    ids: list[str]
    severity: str
    fixed: bool
    malicious: bool
    summary: str

    @property
    def high(self) -> bool:
        try:
            return float(self.severity) >= HIGH_CVSS
        except ValueError:
            return self.severity.upper() in {"HIGH", "CRITICAL"}

    @property
    def blocking(self) -> bool:
        return self.malicious or (block_vulns() and self.fixed and self.high)


def _has_fix(vulns: list[dict], name: str) -> bool:
    for v in vulns:
        for aff in v.get("affected", []):
            if aff.get("package", {}).get("name", name).lower() != name.lower():
                continue
            if any("fixed" in ev for rng in aff.get("ranges", []) for ev in rng.get("events", [])):
                return True
    return False


def _label(vulns: list[dict]) -> str:
    labels = {str(v.get("database_specific", {}).get("severity", "")).upper() for v in vulns}
    return next((l for l in ("CRITICAL", "HIGH", "MODERATE", "LOW") if l in labels), "")


def osv_findings(report: dict) -> list[Finding]:
    out: list[Finding] = []
    for res in report.get("results") or []:
        src = os.path.relpath(res.get("source", {}).get("path", "?"), "/src")
        for pkg in res.get("packages") or []:
            meta = pkg.get("package", {})
            vulns = {v["id"]: v for v in pkg.get("vulnerabilities") or []}
            for grp in pkg.get("groups") or [{"ids": [i]} for i in vulns]:
                ids = sorted(set(grp.get("ids", [])) | set(grp.get("aliases", [])))
                members = [vulns[i] for i in grp.get("ids", []) if i in vulns]
                out.append(Finding(
                    source=src,
                    package=f"{meta.get('name')}@{meta.get('version')}",
                    ids=ids,
                    severity=str(grp.get("max_severity") or "") or _label(members) or "unbekannt",
                    fixed=_has_fix(members, meta.get("name", "")),
                    malicious=any(i.startswith("MAL-") for i in ids),
                    summary=next((m.get("summary", "") for m in members if m.get("summary")), ""),
                ))
    return out


def cmd_osv(path: str) -> int:
    try:
        report = json.loads(Path(path).read_text(encoding="utf-8") or "{}")
    except (OSError, json.JSONDecodeError) as exc:
        print(f"::error::OSV-Bericht nicht lesbar ({exc}) - Gate blockiert (fail-closed).")
        return 1
    found = osv_findings(report)
    bad = [f for f in found if f.blocking]
    mal = [f for f in found if f.malicious]
    high_fix = [f for f in found if f.fixed and f.high]
    mode = "blockierend" if block_vulns() else "nur Bericht"
    lines = [
        "### OSV-Scanner (bekannte Schwachstellen und Schadpakete)",
        f"Modus Schwachstellen: **{mode}** (Repo-Variable `SUPPLY_CHAIN_BLOCK_VULNS`). Schadpakete blockieren immer.",
        "",
        f"Befunde: {len(found)} gesamt, davon behebbar HIGH/CRITICAL: {len(high_fix)}, Schadpakete: {len(mal)}.",
    ]
    if found:
        lines += ["", "| Quelle | Paket | IDs | Schwere | Fix | Wertung |", "| --- | --- | --- | --- | --- | --- |"]
        order = sorted(found, key=lambda f: (not f.malicious, not f.blocking, not (f.fixed and f.high), f.package))
        for f in order[:60]:
            verdict = "SCHADPAKET" if f.malicious else ("blockiert" if f.blocking else "Bericht")
            lines.append(f"| {f.source} | `{f.package}` | {', '.join(f.ids[:3])} | {f.severity} | "
                         f"{'ja' if f.fixed else 'nein'} | {verdict} |")
        if len(found) > 60:
            lines.append(f"| … | {len(found) - 60} weitere | | | | |")
    summary(lines)
    for f in [f for f in found if f.blocking][:20]:
        kind = "SCHADPAKET" if f.malicious else "behebbar"
        print(f"::error::OSV {kind}: {f.package} ({f.source}) {', '.join(f.ids[:3])} Schwere={f.severity}")
    for f in [f for f in high_fix if not f.blocking][:10]:
        print(f"::warning::OSV behebbar: {f.package} ({f.source}) {', '.join(f.ids[:3])} Schwere={f.severity}")
    if bad:
        print(f"::error::OSV: {len(bad)} blockierende(r) Befund(e). Schadpakete sofort entfernen (nie ausnehmen); "
              "Schwachstellen auf die behobene Version anheben oder begruendet und befristet in "
              ".github/supply-chain/osv-scanner.toml ausnehmen.")
        return 1
    print(f"OSV: {len(found)} Befund(e), {len(high_fix)} behebbar HIGH/CRITICAL, Modus {mode}, nichts blockierend.")
    return 0


# ------------------------------------------------------------------ GuardDog

@dataclass(frozen=True, order=True)
class Dep:
    eco: str  # npm | pypi | packagist
    name: str
    version: str
    source: str = ""

    @property
    def key(self) -> str:
        return f"{self.eco}:{self.name}@{self.version}"


def norm_py(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def parse(path: str, text: str) -> set[Dep]:
    name = path.rsplit("/", 1)[-1]
    deps: set[Dep] = set()
    if name == "package-lock.json":
        data = json.loads(text)
        for p, meta in (data.get("packages") or {}).items():
            if not p or meta.get("link") or "version" not in meta:
                continue
            resolved = meta.get("resolved", "")
            src = "" if not resolved or resolved.startswith(NPM_REGISTRY) else resolved
            deps.add(Dep("npm", meta.get("name") or p.rsplit("node_modules/", 1)[-1], meta["version"], src))
    elif name == "uv.lock":
        for pkg in tomllib.loads(text).get("package", []):
            src = pkg.get("source", {})
            if "registry" not in src:
                continue  # Projekt selbst, editable, git, Pfad
            reg = src["registry"]
            deps.add(Dep("pypi", norm_py(pkg["name"]), str(pkg["version"]),
                         "" if reg.rstrip("/") in ("https://pypi.org/simple",) else reg))
    elif name.startswith("requirements") and name.endswith(".txt"):
        for raw in text.splitlines():
            m = REQ.match(raw.strip())
            if m:
                deps.add(Dep("pypi", norm_py(m.group(1)), m.group(2)))
    elif name == "composer.lock":
        data = json.loads(text)
        for pkg in (data.get("packages") or []) + (data.get("packages-dev") or []):
            deps.add(Dep("packagist", pkg["name"], str(pkg.get("version", ""))))
    return deps


def git(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(["git", "-C", str(ROOT), *args], capture_output=True, text=True, check=False)


def changed_deps(base: str) -> list[Dep]:
    files = [f for f in git("ls-files").stdout.splitlines() if LOCKFILES.search(f)]
    changed: set[Dep] = set()
    for f in files:
        head = parse(f, (ROOT / f).read_text(encoding="utf-8"))
        old = git("show", f"{base}:{f}") if base else None
        before = parse(f, old.stdout) if old is not None and old.returncode == 0 else set()
        changed |= head - before
    return sorted(changed)


def load_allowlist(today: dt.date) -> dict[str, str]:
    allow: dict[str, str] = {}
    if not ALLOWLIST.exists():
        return allow
    for raw in ALLOWLIST.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(maxsplit=4)
        if len(parts) < 5:
            print(f"::warning::GuardDog-Allowlist: Zeile ohne Begruendung ignoriert: {line[:80]}")
            continue
        eco, name, version, until, reason = parts
        try:
            expired = dt.date.fromisoformat(until) < today
        except ValueError:
            expired = True
        if expired:
            print(f"::warning::GuardDog-Allowlist: abgelaufen/ungueltig: {eco} {name} {version} {until}")
            continue
        allow[f"{eco}:{name}@{version}"] = f"bis {until}: {reason}"
    return allow


def scan(dep: Dep, image: str) -> tuple[dict | None, str]:
    cmd = ["docker", "run", "--rm", "--user", "1000:1000", "--cap-drop", "ALL",
           "--security-opt", "no-new-privileges", "--tmpfs", "/tmp:size=2g", "-e", "HOME=/tmp",
           "-v", f"{GATE_DIR}:/gate:ro", "--entrypoint", "python", image,
           "/gate/guarddog_wrapper.py", dep.eco, "scan", dep.name, "--version", dep.version,
           "--output-format", "json"]
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=600, check=False)
    except subprocess.TimeoutExpired:
        return None, "Zeitueberschreitung (600 s)"
    try:
        return json.loads(res.stdout.strip().splitlines()[-1]), ""
    except (IndexError, json.JSONDecodeError):
        tail = (res.stderr or res.stdout).strip().splitlines()[-2:]
        return None, f"GuardDog-Fehler (exit {res.returncode}): {' | '.join(tail)[:300]}"


def cmd_guarddog(base: str, workers: int) -> int:
    if base and git("cat-file", "-e", f"{base}^{{commit}}").returncode != 0:
        print(f"::error::GuardDog: Basis-Stand '{base}' nicht auffindbar - Gate blockiert (fail-closed).")
        return 1
    deps = changed_deps(base)
    image = os.environ["GUARDDOG_IMAGE"]
    allow = load_allowlist(dt.date.today())
    print(f"GuardDog: {len(deps)} neue/geaenderte Abhaengigkeit(en) gegenueber {base or '(leer)'}")
    rows: list[tuple[str, str, str, str]] = []
    todo = []
    for d in deps:
        if d.eco == "packagist":
            rows.append((d.key, "nicht pruefbar", "-", "GuardDog kennt Packagist nicht; nur OSV"))
        elif d.source and d.key not in allow:
            rows.append((d.key, "blockiert", "-", f"Quelle ausserhalb der Registry ({d.source[:80]})"))
        else:
            todo.append(d)
    if todo:
        subprocess.run(["docker", "pull", "--quiet", image], check=True)
        with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
            results = list(pool.map(lambda d: (d, *scan(d, image)), todo))
        for d, report, err in results:
            if err or report is None:
                rows.append((d.key, "fehler", "-", err or "kein Ergebnis"))
                continue
            if report.get("errors"):
                rows.append((d.key, "fehler", "-", "; ".join(f"{k}: {v}" for k, v in report["errors"].items())[:300]))
                continue
            risk = report.get("risk_score") or {}
            score = float(risk.get("score") or 0.0)
            names = ", ".join(sorted({str(r.get("name") or r.get("rule") or r) for r in report.get("risks", [])}))[:200]
            if score < BLOCK_SCORE:
                rows.append((d.key, "ok", f"{score:.1f}", names))
            elif d.key in allow:
                rows.append((d.key, "ausgenommen", f"{score:.1f}", allow[d.key]))
            else:
                rows.append((d.key, "blockiert", f"{score:.1f}", names))
    failed = [r for r in rows if r[1] in ("blockiert", "fehler")]
    lines = ["### GuardDog (neue oder geaenderte Abhaengigkeiten)"]
    if not rows:
        lines.append("Keine neuen oder geaenderten Abhaengigkeiten gegenueber dem Basis-Stand.")
    else:
        lines += ["", "| Paket | Ergebnis | Risiko | Hinweis |", "| --- | --- | --- | --- |"]
        lines += [f"| `{k}` | {s} | {sc} | {h} |" for k, s, sc, h in sorted(rows, key=lambda r: (r[1] == "ok", r[0]))]
    summary(lines)
    for k, s, sc, h in failed:
        print(f"::error::GuardDog {s}: {k} (Risiko {sc}) {h}")
    if failed:
        print("::error::GuardDog blockiert. Paket und Befund manuell pruefen (Quellcode/Diff); Freigabe nur fuer "
              "genau diese Version mit Ablaufdatum und Begruendung in .github/supply-chain/guarddog-allowlist.txt.")
        return 1
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    o = sub.add_parser("osv")
    o.add_argument("report")
    g = sub.add_parser("guarddog")
    g.add_argument("--base", default="")
    g.add_argument("--workers", type=int, default=6)
    a = ap.parse_args()
    return cmd_osv(a.report) if a.cmd == "osv" else cmd_guarddog(a.base, a.workers)


if __name__ == "__main__":
    sys.exit(main())
