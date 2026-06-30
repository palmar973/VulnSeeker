#!/usr/bin/env python3
"""
Driver de VulnSeeker para el OWASP Benchmark.

El OWASP Benchmark es una aplicación Java (Tombcat + HSQLDB) con miles de casos
de prueba *etiquetados*. A diferencia de un sitio real, no se navega: cada caso
es un endpoint cuyo índice de categoría enlaza a una página con un formulario.
El reto es que el dato atacable no siempre viaja en un parámetro: según el caso,
va en un parámetro (GET/POST), en una cabecera HTTP, en el nombre de un
parámetro, o en un cuerpo JSON/XML enviado por AJAX (atributo method="submit*").

Este driver:
  1. Enumera los casos de las categorías que VulnSeeker ataca como DAST
     (sqli, xss, cmdi, pathtraver) leyendo los índices del propio Benchmark.
  2. Para cada caso descarga su página y determina el VECTOR de inyección.
     - Si el dato va por cabecera / nombre-de-parámetro / XML (method="submit*"),
       el caso NO es atacable por el motor actual y se omite (contará como no
       detectado en el medidor: es un falso negativo honesto, no se maquilla).
     - Si va por un parámetro de formulario (GET/POST), se ataca.
  3. REUTILIZA los módulos de detección reales de VulnSeeker SIN modificarlos
     (SQLInjectionScanner, XSSScanner, CommandInjectionScanner, LFIScanner),
     construyendo el Target en el formato que cada uno espera.
  4. Exporta los hallazgos a JSON, que luego consume tools/benchmark_scorer.py
     para calcular TPR / FPR / Índice de Youden.

Uso:
    python tools/benchmark_runner.py https://localhost:8444/benchmark/ \
        scratch/benchmark/expectedresults-1.2.csv scratch/benchmark/scan.json
    # opcional:  --categories sqli,xss   --limit 50   (muestra por categoría)

Nota de honestidad metodológica: el SQLi ciego time-based se desactiva porque
HSQLDB no implementa SLEEP/WAITFOR; mantenerlo sólo añadiría timeouts sin valor.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import time
from urllib.parse import urlparse, urlencode, urljoin

import requests
import urllib3
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from core.models import Target, PageElement
from modules.sqli_module import SQLInjectionScanner
from modules.xss_module import XSSScanner
from modules.cmd_injection import CommandInjectionScanner
from modules.lfi_scanner import LFIScanner
from tools.benchmark_scorer import (
    load_ground_truth, score, aggregate, format_report, COVERED_CATEGORIES,
)

urllib3.disable_warnings()

COVERED = ["sqli", "xss", "cmdi", "pathtraver"]

# Funciones AJAX del Benchmark que transportan el dato fuera de un parámetro
# de formulario (cabecera, nombre de parámetro, cuerpo XML/JSON). El motor
# actual no ataca estos vectores, así que esos casos se omiten.
_NONPARAM_RE = re.compile(r'method="(submit\w+)"')
_FORM_RE = re.compile(r'<form action="([^"]+)"\s+method="(\w+)"', re.I)
_NAME_RE = re.compile(r'name="([^"]+)"')


def _session() -> requests.Session:
    """Sesión HTTP resiliente (reintentos) para la fase de ENUMERACIÓN.
    Los módulos de ataque usan su propio requests (comportamiento real)."""
    s = requests.Session()
    s.verify = False
    retry = Retry(total=3, backoff_factor=0.5,
                  status_forcelist=[500, 502, 503, 504],
                  allowed_methods=["GET", "POST"])
    s.mount("https://", HTTPAdapter(max_retries=retry))
    s.mount("http://", HTTPAdapter(max_retries=retry))
    return s


def _origin(base_url: str) -> str:
    p = urlparse(base_url)
    return f"{p.scheme}://{p.netloc}"


def index_cases(sess, base_url, category):
    """Devuelve {nombre_caso: ruta_html_relativa} leyendo el índice de la categoría."""
    url = urljoin(base_url.rstrip("/") + "/", f"{category}-Index.html")
    html = sess.get(url, timeout=20).text
    pat = re.compile(rf"href='({category}-\d+/(BenchmarkTest\d+)\.html)")
    return {m.group(2): m.group(1) for m in pat.finditer(html)}


def load_truth(csv_path):
    truth = {}
    with open(csv_path, encoding="utf-8") as f:
        for line in f:
            if line.startswith("#") or not line.strip():
                continue
            p = line.split(",")
            if len(p) < 3:
                continue
            truth[p[0].strip()] = {"category": p[1].strip().lower(),
                                   "real": p[2].strip().lower() == "true"}
    return truth


def parse_case(html):
    """Extrae (action, method, params, vector) de la página de un caso.
    vector: 'param' (atacable) o el nombre submit* (no atacable)."""
    nonparam = _NONPARAM_RE.search(html)
    fm = _FORM_RE.search(html)
    if not fm:
        return None
    action, method = fm.group(1), fm.group(2).upper()
    names = list(dict.fromkeys(_NAME_RE.findall(html)))
    if not names:
        return None
    vector = nonparam.group(1) if nonparam else "param"
    return action, method, names, vector


def build_target(category, full_url, method, names):
    """Construye el Target en el formato que el módulo de cada categoría espera.
    Valor benigno inicial 'SafeText'; los módulos mutan/concatenan el payload."""
    params = {n: "SafeText" for n in names}
    element = PageElement(url=full_url, method=method, params=params, is_form=True)
    if method == "GET":
        # XSS y LFI leen los parámetros desde la query string de target.url;
        # SQLi y cmdi también los aprovechan desde ahí o desde el elemento.
        url_q = full_url + ("&" if "?" in full_url else "?") + urlencode(params)
        return Target(url=url_q, method="GET", elements=[element])
    return Target(url=full_url, method="POST", elements=[element])


def scanner_for(category):
    if category == "sqli":
        return SQLInjectionScanner(enable_blind=False)  # HSQLDB no soporta SLEEP
    if category == "xss":
        return XSSScanner()
    if category == "cmdi":
        return CommandInjectionScanner()
    if category == "pathtraver":
        return LFIScanner()
    raise ValueError(category)


def run(base_url, csv_path, out_path, categories, limit):
    sess = _session()
    origin = _origin(base_url)
    truth = load_truth(csv_path)
    findings = []
    meta = {}
    atacables_cases = []   # casos cuyo vector el motor SÍ puede atacar (param GET/POST)

    for cat in categories:
        scanner = scanner_for(cat)
        href = index_cases(sess, base_url, cat)
        cases = [n for n in truth if truth[n]["category"] == cat and n in href]
        cases.sort()
        if limit:
            cases = cases[:limit]
        stats = {"total": len(cases), "atacables": 0, "no_atacables": 0,
                 "detectados": 0, "errores": 0}
        print(f"\n[{cat}] casos enumerados: {len(cases)}", flush=True)

        for i, name in enumerate(cases, 1):
            try:
                page = sess.get(urljoin(base_url.rstrip('/') + '/', href[name]), timeout=20).text
            except Exception:
                stats["errores"] += 1
                continue
            parsed = parse_case(page)
            if not parsed:
                stats["no_atacables"] += 1
                continue
            action, method, names, vector = parsed
            if vector != "param":
                stats["no_atacables"] += 1          # cabecera/XML/nombre-param
                continue
            stats["atacables"] += 1
            atacables_cases.append(name)
            full_url = origin + action
            target = build_target(cat, full_url, method, names)
            try:
                vulns = scanner.run(target)
            except Exception as e:
                stats["errores"] += 1
                continue
            if vulns:
                stats["detectados"] += 1
                v = vulns[0]
                findings.append({"name": v.name, "url": v.target_url,
                                 "category": cat, "case": name, "vector": vector,
                                 "method": method})
            if i % 50 == 0:
                print(f"  [{cat}] {i}/{len(cases)} "
                      f"(atacables={stats['atacables']} det={stats['detectados']})",
                      flush=True)
        meta[cat] = stats
        print(f"  [{cat}] FIN -> {stats}", flush=True)

    out = {"hallazgos": findings, "meta": meta, "atacables_cases": atacables_cases,
           "base_url": base_url, "generado": time.strftime("%Y-%m-%d %H:%M:%S")}
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False, indent=2)
    print(f"\nGuardado: {len(findings)} hallazgos en {out_path}")
    print_report(csv_path, findings, atacables_cases, categories)
    return out


def print_report(csv_path, findings, atacables_cases, categories):
    """Imprime las DOS medidas honestas:
       (a) sobre TODOS los casos de las categorías cubiertas (los de vector no
           atacable cuentan como falso negativo: medida conservadora);
       (b) sobre el SUBCONJUNTO que el motor puede atacar (param GET/POST):
           la capacidad real del detector cuando el vector es alcanzable."""
    truth = load_ground_truth(csv_path)

    # (a) Medida global sobre las categorías cubiertas, escaneadas en esta corrida
    truth_cov = {n: i for n, i in truth.items()
                 if i["category"] in categories and i["category"] in COVERED_CATEGORIES}
    print("\n" + "#" * 72)
    print("# (a) MEDIDA GLOBAL sobre las categorías cubiertas escaneadas")
    print("#     (los vectores no atacables -cabecera/XML- cuentan como FN)")
    print("#" * 72)
    print(format_report(truth_cov, findings))

    # (b) Medida sobre el subconjunto realmente atacable por el motor
    atacable_set = set(atacables_cases)
    truth_atac = {n: i for n, i in truth_cov.items() if n in atacable_set}
    by_cat = score(truth_atac, findings)
    print("\n" + "#" * 72)
    print("# (b) MEDIDA sobre el SUBCONJUNTO ATACABLE (vector parámetro GET/POST)")
    print(f"#     {len(truth_atac)} casos cuyo vector el motor puede alcanzar")
    print("#" * 72)
    hdr = f"{'Categoría':<14}{'TP':>5}{'FN':>5}{'FP':>5}{'TN':>6}{'TPR':>8}{'FPR':>8}{'Youden':>9}"
    print(hdr); print("-" * 72)
    for cat in sorted(by_cat):
        cm = by_cat[cat]
        print(f"{cat:<14}{cm.TP:>5}{cm.FN:>5}{cm.FP:>5}{cm.TN:>6}"
              f"{cm.tpr:>8.2f}{cm.fpr:>8.2f}{cm.youden:>9.2f}")
    agg = aggregate(by_cat)
    print("-" * 72)
    print(f"{'TOTAL':<14}{agg.TP:>5}{agg.FN:>5}{agg.FP:>5}{agg.TN:>6}"
          f"{agg.tpr:>8.2f}{agg.fpr:>8.2f}{agg.youden:>9.2f}")
    print(f"Precision: {agg.precision:.2f} | F1: {agg.f1:.2f}")


def main(argv):
    ap = argparse.ArgumentParser(description="Driver de VulnSeeker para el OWASP Benchmark")
    ap.add_argument("base_url")
    ap.add_argument("csv_path")
    ap.add_argument("out_path")
    ap.add_argument("--categories", default=",".join(COVERED))
    ap.add_argument("--limit", type=int, default=0)
    args = ap.parse_args(argv)
    cats = [c.strip() for c in args.categories.split(",") if c.strip()]
    run(args.base_url, args.csv_path, args.out_path, cats, args.limit)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
