#!/usr/bin/env python3
"""
Medidor de efectividad contra el OWASP Benchmark.

El OWASP Benchmark es una aplicación deliberadamente vulnerable con miles de
casos de prueba *etiquetados* (ground truth): para cada caso se sabe a ciencia
cierta si la vulnerabilidad es real o si es un "sink" seguro. Esto permite
calcular métricas cuantitativas y comparables ---a diferencia de DVWA o Juice
Shop, donde el conteo es cualitativo--- y reportar el Índice de Youden, la
métrica oficial del Benchmark.

Este módulo NO requiere tener el Benchmark levantado: dado el archivo de
resultados esperados (expectedresults-*.csv) y un escaneo de VulnSeeker exportado
a JSON, calcula la matriz de confusión y las métricas. El flujo de trabajo es:

    1. (cuando se tenga tiempo/disco) levantar el OWASP Benchmark y escanearlo
       con VulnSeeker, exportando los hallazgos a JSON.
    2. correr:  python tools/benchmark_scorer.py expectedresults-1.2.csv scan.json

Honestidad metodológica: el Benchmark mide 11 categorías, varias de ellas
(criptografía débil, hashing, aleatoriedad, trust boundary) sólo son detectables
mediante análisis estático (SAST), no por un escáner dinámico (DAST) que observa
HTTP. Por eso el informe separa el resultado GLOBAL del resultado sobre las
categorías que VulnSeeker realmente ataca, que es la medida justa para un DAST.
"""
from __future__ import annotations

import csv
import json
import re
import sys
from dataclasses import dataclass, field
from typing import Dict, List, Optional

# Identificador de cada caso de prueba en las URLs del Benchmark.
_TEST_RE = re.compile(r"BenchmarkTest\d{5}", re.IGNORECASE)

# Categorías del Benchmark que VulnSeeker ataca dinámicamente (DAST).
# El resto (crypto, hash, weakrand, trustbound, securecookie, ...) requieren SAST.
COVERED_CATEGORIES = {"sqli", "xss", "cmdi", "pathtraver"}


def categoria_benchmark(nombre_hallazgo: str) -> Optional[str]:
    """Mapea el nombre de un hallazgo de VulnSeeker a la categoría del Benchmark."""
    n = (nombre_hallazgo or "").lower()
    if "sql injection" in n:
        return "sqli"
    if "cross-site scripting" in n or "xss" in n:
        return "xss"
    if "command injection" in n or "os command" in n or "rce" in n:
        return "cmdi"
    if ("local file inclusion" in n or "lfi" in n
            or "path traversal" in n or "directory traversal" in n):
        return "pathtraver"
    return None


@dataclass
class Confusion:
    """Matriz de confusión para una categoría o agregado."""
    TP: int = 0
    FP: int = 0
    FN: int = 0
    TN: int = 0

    @property
    def total(self) -> int:
        return self.TP + self.FP + self.FN + self.TN

    @property
    def tpr(self) -> float:
        """True Positive Rate (recall / sensibilidad)."""
        d = self.TP + self.FN
        return self.TP / d if d else 0.0

    @property
    def fpr(self) -> float:
        """False Positive Rate."""
        d = self.FP + self.TN
        return self.FP / d if d else 0.0

    @property
    def youden(self) -> float:
        """Índice de Youden J = TPR - FPR (métrica oficial del Benchmark)."""
        return self.tpr - self.fpr

    @property
    def precision(self) -> float:
        d = self.TP + self.FP
        return self.TP / d if d else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.tpr
        return 2 * p * r / (p + r) if (p + r) else 0.0


def load_ground_truth(csv_path: str) -> Dict[str, dict]:
    """Lee expectedresults-*.csv → {test_name: {category, real, cwe}}.

    Formato (columnas estables): nombre, categoría, real (true/false), CWE.
    Las líneas que comienzan con '#' son comentarios."""
    truth: Dict[str, dict] = {}
    with open(csv_path, newline="", encoding="utf-8") as f:
        for row in csv.reader(f):
            if not row or row[0].lstrip().startswith("#"):
                continue
            if len(row) < 3:
                continue
            name = row[0].strip()
            category = row[1].strip().lower()
            real = row[2].strip().lower() == "true"
            cwe = row[3].strip() if len(row) > 3 else ""
            truth[name] = {"category": category, "real": real, "cwe": cwe}
    return truth


def _load_findings(scan_path: str) -> List[dict]:
    """Carga el JSON de un escaneo de VulnSeeker. Acepta una lista directa de
    hallazgos o un objeto con la clave 'hallazgos'."""
    with open(scan_path, encoding="utf-8") as f:
        data = json.load(f)
    if isinstance(data, dict):
        data = data.get("hallazgos") or data.get("findings") or []
    return data


def _flagged_set(findings: List[dict]) -> set[tuple]:
    """Conjunto de (test_name, categoría) que la herramienta marcó como vulnerables."""
    flagged: set[tuple] = set()
    for f in findings:
        cat = categoria_benchmark(f.get("name", ""))
        if not cat:
            continue
        url = f.get("url") or f.get("target_url") or ""
        for tn in _TEST_RE.findall(url):
            flagged.add((tn.lower(), cat))
    return flagged


def score(ground_truth: Dict[str, dict], findings: List[dict],
          only_covered: bool = False) -> Dict[str, Confusion]:
    """Calcula la matriz de confusión por categoría. Si only_covered, restringe
    el ground truth a las categorías que VulnSeeker ataca (medida justa DAST)."""
    flagged = _flagged_set(findings)
    by_cat: Dict[str, Confusion] = {}

    for name, info in ground_truth.items():
        category = info["category"]
        if only_covered and category not in COVERED_CATEGORIES:
            continue
        cm = by_cat.setdefault(category, Confusion())
        tool_says = (name.lower(), category) in flagged
        real = info["real"]
        if real and tool_says:
            cm.TP += 1
        elif real and not tool_says:
            cm.FN += 1
        elif (not real) and tool_says:
            cm.FP += 1
        else:
            cm.TN += 1
    return by_cat


def aggregate(by_cat: Dict[str, Confusion]) -> Confusion:
    """Agrega las matrices de todas las categorías en una sola."""
    total = Confusion()
    for cm in by_cat.values():
        total.TP += cm.TP
        total.FP += cm.FP
        total.FN += cm.FN
        total.TN += cm.TN
    return total


def format_report(ground_truth: Dict[str, dict], findings: List[dict]) -> str:
    """Genera el informe de texto con el desglose por categoría y los dos
    agregados (global y sólo categorías cubiertas por DAST)."""
    by_cat = score(ground_truth, findings, only_covered=False)
    lines: List[str] = []
    lines.append("=" * 72)
    lines.append("EFECTIVIDAD CONTRA OWASP BENCHMARK")
    lines.append("=" * 72)
    header = f"{'Categoría':<14}{'TP':>5}{'FN':>5}{'FP':>5}{'TN':>6}{'TPR':>8}{'FPR':>8}{'Youden':>9}"
    lines.append(header)
    lines.append("-" * 72)
    for cat in sorted(by_cat):
        cm = by_cat[cat]
        cubierta = "*" if cat in COVERED_CATEGORIES else " "
        lines.append(f"{cubierta}{cat:<13}{cm.TP:>5}{cm.FN:>5}{cm.FP:>5}{cm.TN:>6}"
                     f"{cm.tpr:>8.2f}{cm.fpr:>8.2f}{cm.youden:>9.2f}")
    lines.append("-" * 72)

    glob = aggregate(by_cat)
    cov = aggregate(score(ground_truth, findings, only_covered=True))
    lines.append(f"{'GLOBAL (11 cat)':<14}{glob.TP:>5}{glob.FN:>5}{glob.FP:>5}{glob.TN:>6}"
                 f"{glob.tpr:>8.2f}{glob.fpr:>8.2f}{glob.youden:>9.2f}")
    lines.append(f"{'CUBIERTAS (*)':<14}{cov.TP:>5}{cov.FN:>5}{cov.FP:>5}{cov.TN:>6}"
                 f"{cov.tpr:>8.2f}{cov.fpr:>8.2f}{cov.youden:>9.2f}")
    lines.append("=" * 72)
    lines.append("(*) Categorías que VulnSeeker ataca dinámicamente (DAST). Las demás")
    lines.append("    (crypto, hash, weakrand, trustbound, ...) requieren análisis estático.")
    lines.append(f"Precision (cubiertas): {cov.precision:.2f} | F1 (cubiertas): {cov.f1:.2f}")
    return "\n".join(lines)


def main(argv: List[str]) -> int:
    if len(argv) != 3:
        print("Uso: python tools/benchmark_scorer.py <expectedresults.csv> <scan.json>")
        return 2
    truth = load_ground_truth(argv[1])
    findings = _load_findings(argv[2])
    print(format_report(truth, findings))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
