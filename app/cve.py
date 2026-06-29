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


def _tem_versao_especifica(keyword: str) -> bool:
    """Heurística: se a keyword tem mais de uma palavra (ex: 'OpenSSH 6.6.1p1'),
    assume que é produto+versao e a busca deve ser histórica (sem filtro de data).
    Keywords de uma palavra (ex: 'HTTP', 'nginx') usam a janela recente de 119 dias."""
    return len(keyword.strip().split()) > 1


def search_cves(keyword: str, limit: int = 10, days: int = 119) -> list[dict]:
    """Busca CVEs na NVD para uma keyword.

    Se a keyword contém produto+versao (ex: 'OpenSSH 6.6.1p1'), busca em todo o
    histórico da NVD, já que o objetivo é achar vulnerabilidades conhecidas dessa
    versão específica, não apenas avisos recentes. Caso contrário, aplica a janela
    de 'days' (máx 119, limite da NVD) para mostrar achados recentes do termo genérico.

    keywordSearch da NVD busca substring literal na descrição em texto livre, então
    versões completas (ex: '6.6.1p1') raramente batem -- descrições costumam dizer
    'before 6.7'. Por isso, quando há versão específica, tentamos primeiro só o
    produto (sem a versão) via keywordSearch, sem filtro de data, trazendo o
    histórico completo de CVEs daquele produto para o usuário avaliar manualmente.
    """
    tem_versao = _tem_versao_especifica(keyword)
    termo_busca = keyword.split()[0] if tem_versao else keyword

    params = {
        "keywordSearch": termo_busca,
        "resultsPerPage": 50,
    }

    if not tem_versao:
        end = datetime.now(timezone.utc)
        start = end - timedelta(days=days)
        params["pubStartDate"] = start.strftime("%Y-%m-%dT00:00:00.000")
        params["pubEndDate"] = end.strftime("%Y-%m-%dT23:59:59.999")

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
    """Extrai keywords de busca a partir dos resultados de um scan do Sentinel-RS.

    Prioriza 'produto + versao' (ex: 'OpenSSH 6.6.1p1') quando disponível,
    que gera CVEs muito mais precisas do que o nome genérico do serviço
    (ex: 'HTTP'). Cai para o nome genérico quando produto/versao não existem.
    """
    services = set()
    for r in scan_results:
        for p in r.get("open_ports", []):
            produto = p.get("produto")
            versao = p.get("versao")
            servico = p.get("service")

            if produto:
                keyword = f"{produto} {versao}".strip() if versao else produto
                services.add(keyword)
            elif servico and servico.lower() not in ("desconhecido", "unknown", ""):
                services.add(servico)
    return sorted(services)
