"""
Tests del medidor del OWASP Benchmark (tools/benchmark_scorer.py).
Validan la matriz de confusión y las métricas con un ground-truth sintético,
sin necesidad de levantar el Benchmark.
"""
import json
from tools.benchmark_scorer import (
    Confusion, categoria_benchmark, load_ground_truth, score, aggregate,
    format_report,
)


def test_categoria_benchmark_mapea_nombres():
    assert categoria_benchmark("SQL Injection (Error Based - GET)") == "sqli"
    assert categoria_benchmark("Reflected Cross-Site Scripting (XSS)") == "xss"
    assert categoria_benchmark("OS Command Injection (RCE)") == "cmdi"
    assert categoria_benchmark("Local File Inclusion (LFI)") == "pathtraver"
    assert categoria_benchmark("Missing HSTS") is None


def test_confusion_metricas():
    cm = Confusion(TP=8, FN=2, FP=1, TN=9)
    assert cm.tpr == 0.8                      # 8/10
    assert cm.fpr == 0.1                       # 1/10
    assert abs(cm.youden - 0.7) < 1e-9         # 0.8 - 0.1
    assert cm.precision == 8 / 9
    assert abs(cm.f1 - (2 * (8/9) * 0.8) / ((8/9) + 0.8)) < 1e-9


def _gt():
    # 2 sqli vulnerables + 2 sqli seguros; 1 xss vulnerable; 1 crypto (no cubierta)
    return {
        "BenchmarkTest00001": {"category": "sqli", "real": True, "cwe": "89"},
        "BenchmarkTest00002": {"category": "sqli", "real": True, "cwe": "89"},
        "BenchmarkTest00003": {"category": "sqli", "real": False, "cwe": "89"},
        "BenchmarkTest00004": {"category": "sqli", "real": False, "cwe": "89"},
        "BenchmarkTest00005": {"category": "xss", "real": True, "cwe": "79"},
        "BenchmarkTest00006": {"category": "crypto", "real": True, "cwe": "327"},
    }


def test_score_confusion_por_categoria():
    findings = [
        # Detecta TP00001, FN00002 (no detecta), FP00003 (seguro marcado), TN00004 (no marca)
        {"name": "SQL Injection (Error Based - GET)", "url": ".../BenchmarkTest00001?a=1"},
        {"name": "SQL Injection (Error Based - GET)", "url": ".../BenchmarkTest00003?a=1"},
        {"name": "Reflected Cross-Site Scripting (XSS)", "url": ".../BenchmarkTest00005"},
    ]
    by_cat = score(_gt(), findings)
    sqli = by_cat["sqli"]
    assert (sqli.TP, sqli.FN, sqli.FP, sqli.TN) == (1, 1, 1, 1)
    xss = by_cat["xss"]
    assert (xss.TP, xss.FN, xss.FP, xss.TN) == (1, 0, 0, 0)
    # crypto: no cubierta y no detectada → cuenta como FN (real y no marcada)
    crypto = by_cat["crypto"]
    assert (crypto.TP, crypto.FN) == (0, 1)


def test_only_covered_excluye_sast():
    findings = []
    completo = aggregate(score(_gt(), findings, only_covered=False))
    cubierto = aggregate(score(_gt(), findings, only_covered=True))
    # 'crypto' (SAST-only) está en el global pero no en el cubierto
    assert completo.total == 6
    assert cubierto.total == 5  # se excluye el caso crypto


def test_youden_perfecto_y_nulo():
    gt = {
        "BenchmarkTest00001": {"category": "sqli", "real": True, "cwe": "89"},
        "BenchmarkTest00002": {"category": "sqli", "real": False, "cwe": "89"},
    }
    # Detector perfecto: marca el real, no marca el seguro → Youden 1.0
    perfecto = [{"name": "SQL Injection", "url": "x/BenchmarkTest00001"}]
    cm = score(gt, perfecto)["sqli"]
    assert cm.youden == 1.0
    # Detector que marca todo → TPR 1, FPR 1 → Youden 0
    todo = [
        {"name": "SQL Injection", "url": "x/BenchmarkTest00001"},
        {"name": "SQL Injection", "url": "x/BenchmarkTest00002"},
    ]
    cm2 = score(gt, todo)["sqli"]
    assert cm2.youden == 0.0


def test_load_ground_truth(tmp_path):
    csv_file = tmp_path / "expected.csv"
    csv_file.write_text(
        "# test name, category, real vulnerability, cwe\n"
        "BenchmarkTest00001,sqli,true,89\n"
        "BenchmarkTest00002,xss,false,79\n",
        encoding="utf-8",
    )
    gt = load_ground_truth(str(csv_file))
    assert gt["BenchmarkTest00001"] == {"category": "sqli", "real": True, "cwe": "89"}
    assert gt["BenchmarkTest00002"]["real"] is False


def test_format_report_incluye_agregados():
    reporte = format_report(_gt(), [])
    assert "GLOBAL" in reporte and "CUBIERTAS" in reporte and "Youden" in reporte
