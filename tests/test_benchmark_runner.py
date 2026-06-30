"""
Tests del driver del OWASP Benchmark (tools/benchmark_runner.py).
Validan la clasificación del vector de inyección y la construcción del Target,
que son las piezas que deciden qué casos son atacables y cómo se ataca cada uno.
No requieren el Benchmark levantado (operan sobre HTML de ejemplo).
"""
from tools.benchmark_runner import parse_case, build_target
from core.models import Target, PageElement


# --- HTML de ejemplo representativo de los casos del Benchmark ---
HTML_POST_PARAM = '''<html><body>
<form action="/benchmark/sqli-00/BenchmarkTest00024" method="POST" id="F">
<input type="text" name="BenchmarkTest00024" value="SafeText">
<input type="text" name="foo" value="bar">
</form></body></html>'''

HTML_GET_PARAM = '''<html><body>
<form action="/benchmark/sqli-00/BenchmarkTest00026" method="GET" id="F">
<input type="text" name="username"><input type="text" name="BenchmarkTest00026">
</form></body></html>'''

HTML_HEADER_VECTOR = '''<html><body>
<form action="/benchmark/sqli-00/BenchmarkTest00008" method="POST" id="F">
<input type="text" name="BenchmarkTest00008" value="x">
<input type="button" method="submitHeaderForm" testcase="BenchmarkTest00008">
</form></body></html>'''

HTML_SIN_FORM = '<html><body><p>Sin formulario</p></body></html>'


def test_parse_case_post_param_es_atacable():
    action, method, names, vector = parse_case(HTML_POST_PARAM)
    assert action == "/benchmark/sqli-00/BenchmarkTest00024"
    assert method == "POST"
    assert "BenchmarkTest00024" in names and "foo" in names
    assert vector == "param"


def test_parse_case_get_param_es_atacable():
    action, method, names, vector = parse_case(HTML_GET_PARAM)
    assert method == "GET"
    assert vector == "param"
    assert "BenchmarkTest00026" in names


def test_parse_case_vector_cabecera_no_atacable():
    """Un caso con method='submitHeaderForm' inyecta por cabecera: no es 'param'."""
    _, _, _, vector = parse_case(HTML_HEADER_VECTOR)
    assert vector == "submitHeaderForm"


def test_parse_case_sin_form_devuelve_none():
    assert parse_case(HTML_SIN_FORM) is None


def test_build_target_get_pone_params_en_query():
    """En GET, los parámetros deben viajar en la query de target.url
    (XSS y LFI los leen de ahí) y también en el PageElement."""
    t = build_target("sqli", "https://h/benchmark/sqli-00/BenchmarkTest00026",
                      "GET", ["username", "BenchmarkTest00026"])
    assert isinstance(t, Target)
    assert t.method == "GET"
    assert "username=" in t.url and "?" in t.url
    assert t.elements and t.elements[0].is_form


def test_build_target_post_sin_query():
    """En POST, target.url no lleva query; los params van en el PageElement."""
    t = build_target("sqli", "https://h/benchmark/sqli-00/BenchmarkTest00024",
                      "POST", ["BenchmarkTest00024"])
    assert t.method == "POST"
    assert "?" not in t.url
    assert t.elements[0].method == "POST"
    assert t.elements[0].params["BenchmarkTest00024"] == "SafeText"
