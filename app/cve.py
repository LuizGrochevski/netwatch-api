import requests
from datetime import datetime, timedelta, timezone

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def _get_severity(cve: dict) -> str:
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if key in metrics:
            data = metrics[key][0]["cvssData"]
            sev = data.get("baseSeverity")
            if sev:
                return sev
            score = data.get("baseScore", 0)
            if score >= 9:
                return "CRITICAL"
            if score >= 7:
                return "HIGH"
            if score >= 4:
                return "MEDIUM"
            if score > 0:
                return "LOW"
    return "N/A"


def search_cves(keyword: str, limit: int = 10, days: int = 119) -> list[dict]:
    """Busca CVEs na NVD para uma keyword, dentro da janela de dias permitida (máx 119)."""
    end = datetime.now(timezone.utc)
    start = end - timedelta(days=days)

    params = {
        "keywordSearch": keyword,
        "resultsPerPage": 50,
        "pubStartDate": start.strftime("%Y-%m-%dT00:00:00.000"),
        "pubEndDate": end.strftime("%Y-%m-%dT23:59:59.999"),
    }

    try:
        r = requests.get(NVD_API, params=params, timeout=15)
        r.raise_for_status()
    except requests.RequestException as e:
        return [{"error": f"Falha ao consultar NVD: {str(e)}"}]

    data = r.json()
    vulns = data.get("vulnerabilities", [])
    vulns.sort(key=lambda v: v["cve"]["published"], reverse=True)
    vulns = vulns[:limit]

    output = []
    for item in vulns:
        cve = item["cve"]
        desc = next((d["value"] for d in cve["descriptions"] if d["lang"] == "en"), "")
        output.append({
            "id": cve["id"],
            "published": cve["published"][:10],
            "severity": _get_severity(cve),
            "description": desc,
        })
    return output


def extract_services(scan_results: list[dict]) -> list[str]:
    """Extrai nomes de serviços únicos a partir dos resultados de um scan do Sentinel-RS."""
    services = set()
    for r in scan_results:
        for p in r.get("open_ports", []):
            servico = p.get("service")
            if servico and servico.lower() not in ("desconhecido", "unknown", ""):
                services.add(servico)
    return sorted(services)
