import sys
import argparse
import urllib3
import logging

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from core.engine import VulnSeekerEngine
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
from reports.report_generator import ReportGenerator
from core.config import GlobalConfig
from core.db_manager import DatabaseManager

logging.basicConfig(level=logging.INFO, format='%(message)s')
logger = logging.getLogger("VulnSeeker")


def parse_arguments():
    parser = argparse.ArgumentParser(
        description="VulnSeeker - Escáner de Vulnerabilidades Web (JSON + SQLite)",
        epilog="Ejemplo: python main.py -u http://testphp.vulnweb.com --crawl"
    )
    parser.add_argument("-u", "--url", required=True, help="URL objetivo completa")
    parser.add_argument("--crawl", action="store_true", help="Habilitar Crawler")
    return parser.parse_args()


def main() -> None:
    args = parse_arguments()
    target_url = args.url
    use_crawler = args.crawl

    print("\n" + "=" * 70)
    print(" VULNSEEKER - Automated Vulnerability Scanner")
    print(f" Target: {target_url}")
    print(f" Mode: {'CRAWLING + SCAN' if use_crawler else 'SINGLE URL SCAN'}")
    print(f" Threads: {GlobalConfig.MAX_THREADS}")
    print("=" * 70 + "\n")

    engine = VulnSeekerEngine()

    engine.register_module(SQLInjectionScanner())
    engine.register_module(XSSScanner())
    engine.register_module(HeaderAnalyzer())
    engine.register_module(PortScanner())
    engine.register_module(PathFuzzer())
    engine.register_module(WAFDetector())
    engine.register_module(CMSAuditor())
    engine.register_module(ExposureScanner())
    engine.register_module(EmailHarvester())
    engine.register_module(SubdomainTakeover())
    engine.register_module(LFIScanner())
    engine.register_module(CookieScanner())
    engine.register_module(RFIScanner())
    engine.register_module(CommandInjectionScanner())
    engine.register_module(OpenRedirectScanner())
    engine.register_module(CSRFAuditor())
    engine.register_module(TLSChecker())
    engine.register_module(BruteForceDetector())
    engine.register_module(FileUploadDetector())
    engine.register_module(WeakSessionAuditor())
    engine.register_module(CORSMisconfigScanner())
    engine.register_module(HTTPMethodTamperingScanner())
    engine.register_module(DirectoryListingDetector())
    engine.register_module(SensitiveDataExposure())
    engine.register_module(CVELookupScanner())
    engine.register_module(SSRFScanner())

    try:
        print(f"[*] Iniciando motor de análisis...")
        results = engine.scan(target_url, crawl=use_crawler)

        print("\n" + "=" * 70)
        print(f" RESUMEN DE EJECUCIÓN: {len(results)} hallazgos totales")
        print("=" * 70)

        if results:
            severity_counts = {}
            for v in results:
                print(f"[{v.severity.value}] {v.name} -> {v.target_url}")
                severity_counts[v.severity.value] = severity_counts.get(v.severity.value, 0) + 1

            print("-" * 50)
            print("Desglose por Severidad:")
            for sev, count in severity_counts.items():
                print(f"  {sev}: {count}")

            reporter = ReportGenerator(output_dir=GlobalConfig.REPORTS_DIR)
            json_path = reporter.export_json(results, target_url)
            print(f"\n[+] Reporte JSON guardado en:\n    {json_path}")

            print("[*] Guardando en Base de Datos Histórica...")
            db = DatabaseManager()
            scan_id = db.save_scan_results(target_url, results)
            print(f"[+] Datos persistidos en SQLite (Scan ID: {scan_id})")

        else:
            print("[-] No se encontraron vulnerabilidades en el objetivo.")

    except KeyboardInterrupt:
        print("\n[!] Operación interrumpida por el usuario.")
        sys.exit(0)
    except Exception as e:
        print(f"\n[!] Error crítico no controlado: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()