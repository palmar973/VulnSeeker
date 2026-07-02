"""
Tests unitarios del componente de vectores de inyección (modules/injection_points.py).

Valida que collect_points enumera los cuatro vectores (GET query, POST form,
GET form, JSON) sin duplicados y que InjectionPoint.send construye la petición
correcta para cada vector, preservando el resto de parámetros.
"""
from unittest.mock import patch, MagicMock

from core.models import Target, PageElement
from modules.injection_points import collect_points, InjectionPoint


def test_get_query_genera_un_punto_por_parametro():
    target = Target(url="http://h/app?a=1&b=2")
    points = collect_points(target)
    assert {p.param_name for p in points} == {"a", "b"}
    assert all(p.method == "GET" for p in points)
    # action_url no debe arrastrar la query mutada
    assert all("?" not in p.action_url for p in points)


def test_post_form_genera_puntos_post():
    el = PageElement(url="http://h/login", method="POST",
                     params={"user": "x", "pass": "y"}, is_form=True)
    points = collect_points(Target(url="http://h/login", elements=[el]))
    assert {p.param_name for p in points} == {"user", "pass"}
    assert all(p.method == "POST" and p.body_type == "form" for p in points)


def test_json_body_marca_body_type_json():
    el = PageElement(url="http://h/rest/login", method="POST",
                     params={"email": "a", "password": "b"},
                     is_form=True, body_type="json")
    points = collect_points(Target(url="http://h/rest/login", elements=[el]))
    assert points and all(p.body_type == "json" for p in points)


def test_no_duplica_query_y_get_form_equivalentes():
    """GET con params en la query Y en un PageElement GET del mismo action
    (como arma el benchmark_runner) debe colapsar a un punto por parámetro."""
    el = PageElement(url="http://h/case", method="GET",
                     params={"p": "SafeText"}, is_form=True)
    target = Target(url="http://h/case?p=SafeText", elements=[el])
    points = collect_points(target)
    assert len([p for p in points if p.param_name == "p"]) == 1


def test_fallback_solo_si_no_hay_params():
    target = Target(url="http://h/ping")  # sin query, sin elements
    points = collect_points(target, fallback_params=["ip", "host"])
    assert {p.param_name for p in points} == {"ip", "host"}
    # con params descubiertos NO se usan los de fallback
    target2 = Target(url="http://h/ping?ip=1")
    points2 = collect_points(target2, fallback_params=["host"])
    assert {p.param_name for p in points2} == {"ip"}


def test_send_get_preserva_otros_parametros():
    pt = InjectionPoint("GET", "http://h/app", "a", {"a": "1", "b": "2"}, report_url="http://h/app")
    with patch("modules.injection_points.requests.get", return_value=MagicMock()) as mg:
        pt.send("PAYLOAD")
    sent_url = mg.call_args[0][0]
    assert "a=PAYLOAD" in sent_url and "b=2" in sent_url


def test_send_post_form_envia_data():
    pt = InjectionPoint("POST", "http://h/login", "user", {"user": "x", "pass": "y"})
    with patch("modules.injection_points.requests.post", return_value=MagicMock()) as mp:
        pt.send("PAYLOAD")
    assert mp.call_args.kwargs["data"] == {"user": "PAYLOAD", "pass": "y"}


def test_send_json_usa_body_json():
    pt = InjectionPoint("POST", "http://h/rest", "email", {"email": "a"}, body_type="json")
    with patch("modules.injection_points.requests.post", return_value=MagicMock()) as mp:
        pt.send("PAYLOAD")
    assert mp.call_args.kwargs["json"] == {"email": "PAYLOAD"}
    assert mp.call_args.kwargs["headers"]["Content-Type"] == "application/json"


def test_send_devuelve_none_si_falla():
    import requests as _rq
    pt = InjectionPoint("GET", "http://h/app", "a", {"a": "1"})
    with patch("modules.injection_points.requests.get", side_effect=_rq.RequestException("boom")):
        assert pt.send("x") is None
