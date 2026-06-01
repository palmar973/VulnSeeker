"""
Registro centralizado de módulos de escaneo.
Evita duplicación entre CLI (main.py) y GUI (ui/main_window.py).
"""

from modules.sqli_module import SQLInjectionScanner
from modules.xss_module import XSSScanner
from modules.header_analyzer import HeaderAnalyzer
from modules.port_scanner import PortScanner
from modules.path_fuzzer import PathFuzzer
from modules.waf_detector import WAFDetector
from modules.cms_auditor import CMSAuditor
from modules.exposure_scanner import ExposureScanner
from modules.email_harvester import EmailHarvester
from modules.subdomain_takeover import SubdomainTakeover
from modules.lfi_scanner import LFIScanner
from modules.cookie_scanner import CookieScanner
from modules.rfi_scanner import RFIScanner
from modules.cmd_injection import CommandInjectionScanner
from modules.open_redirect import OpenRedirectScanner
from modules.csrf_auditor import CSRFAuditor
from modules.tls_checker import TLSChecker
from modules.brute_force_detector import BruteForceDetector
from modules.file_upload_detector import FileUploadDetector
from modules.weak_session_auditor import WeakSessionAuditor
from modules.cors_scanner import CORSMisconfigScanner
from modules.http_method_scanner import HTTPMethodTamperingScanner
from modules.dir_listing_detector import DirectoryListingDetector
from modules.sensitive_data_scanner import SensitiveDataExposure
from modules.cve_lookup import CVELookupScanner
from modules.ssrf_scanner import SSRFScanner


def get_default_modules():
    """Retorna una lista con instancias de todos los módulos de escaneo."""
    return [
        SQLInjectionScanner(),
        XSSScanner(),
        HeaderAnalyzer(),
        PortScanner(),
        PathFuzzer(),
        WAFDetector(),
        CMSAuditor(),
        ExposureScanner(),
        EmailHarvester(),
        SubdomainTakeover(),
        LFIScanner(),
        CookieScanner(),
        RFIScanner(),
        CommandInjectionScanner(),
        OpenRedirectScanner(),
        CSRFAuditor(),
        TLSChecker(),
        BruteForceDetector(),
        FileUploadDetector(),
        WeakSessionAuditor(),
        CORSMisconfigScanner(),
        HTTPMethodTamperingScanner(),
        DirectoryListingDetector(),
        SensitiveDataExposure(),
        CVELookupScanner(),
        SSRFScanner(),
    ]
