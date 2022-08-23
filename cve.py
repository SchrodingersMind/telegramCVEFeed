import requests
from datetime import datetime
from typing import List, Dict

class Reference:
    def __init__(self, type, url):
        self.type = type
        self.url = url


# contains important cve data
class CVE:
    def __init__(self, json_data):
        self._init_variables()

        self.pub_date = json_data["publishedDate"]
        self.mod_date = json_data["lastModifiedDate"]
        cve = json_data["cve"]
        self.cve_id = cve["CVE_data_meta"]["ID"]
        if json_data["impact"].get("baseMetricV3", None) is not None:
            self.score = json_data["impact"]["baseMetricV3"]["cvssV3"]["baseScore"]
            self.severity = json_data["impact"]["baseMetricV3"]["cvssV3"]["baseSeverity"]

        descriptions = cve["description"]["description_data"]
        self.description = ""
        for description_json in descriptions:
            if description_json["lang"] == "en":
                self.description = description_json["value"]

        for reference in cve["references"]["reference_data"]:
            ref_type = ",".join(reference["tags"])
            ref_url = reference["url"]
            self.references.append(Reference(ref_type, ref_url))
            # print(f"Reference {ref_type}: {ref_url}")

    def __str__(self):
        result = f"""CVE ID: {self.cve_id} \nScore: {self.score} \nSeverity: {self.severity} \nDescription: {self.description}\n """
        return result

    def _init_variables(self):
        self.cve_id = ""
        self.score = 0
        self.severity = ""
        self.description = ""
        self.pub_date = None
        self.mod_date = None
        self.references: List[Reference] = []


# Parse json-encoded cve data
def parse_json_entry(data):
    items = data["CVE_Items"]

    for item in items:
        pub_date = item["publishedDate"]
        mod_date = item["lastModifiedDate"]
        cve = item["cve"]
        cve_id = cve["CVE_data_meta"]["ID"]
        v3_score = item["impact"]["baseMetricV3"]["cvssV3"]["baseScore"]
        vuln_severity = item["impact"]["baseMetricV3"]["cvssV3"]["baseSeverity"]
        print(
            "\nPub date: " + pub_date +
            "\nMod date: " + mod_date +
            "\nCVE id: " + cve_id +
            "\nScore: " + str(v3_score) +
            "\nSeverity: " + vuln_severity
        )

        descriptions = cve["description"]["description_data"]
        description = ""
        for description_json in descriptions:
            if description_json["lang"] == "en":
                description = description_json["value"]
        print(f"Description: {description}")

        for reference in cve["references"]["reference_data"]:
            ref_type = ",".join(reference["tags"])
            ref_url = reference["url"]
            print(f"Reference {ref_type}: {ref_url}")


def get_cvedetails(api_key: str, cve_id: str):
    params = {"apiKey": api_key}
    r = requests.get("https://services.nvd.nist.gov/rest/json/cve/1.0/" + cve_id, params=params)

    if r.status_code != 200:
        print("[-] Error executing request\n" + r.text)
        return

    print(r.text)
    cve = CVE(r.json()["result"]["CVE_Items"][0])
    print(cve)


# severity could be None, "LOW", "MEDIUM", "HIGH", or "CRITICAL"
def get_list_by_date(api_key: str, start_date: datetime, end_date: datetime, count=50, modified=False,
                     keyword=None, severity=None) -> List[CVE]:
    # Request no more than 50 results
    # date should be in format: yyyy-MM-ddTHH:mm:ss:SSS Z
    start_date_s = start_date.strftime("%Y-%m-%dT%H:%M:%S:000 UTC+00:00")
    end_date_s = end_date.strftime("%Y-%m-%dT%H:%M:%S:000 UTC+00:00")
    params = {"apiKey": api_key, "resultsPerPage": count}
    if severity is not None:
        params["cvssV3Severity"] = severity

    if modified:
        params["modStartDate"] = start_date_s
        params["modEndDate"] = end_date_s
    else:
        params["pubStartDate"] = start_date_s
        params["pubEndDate"] = end_date_s

    if keyword is not None:
        params["isExactMatch"] = True
        params["keyword"] = keyword

    r = requests.get("https://services.nvd.nist.gov/rest/json/cves/1.0/", params=params)

    if r.status_code != 200:
        print("[-] Error executing request\n" + r.text)
        return []

    print(r.text)
    items = r.json()["result"]["CVE_Items"]
    results = []

    for item in items:
        results.append(CVE(item))

    return results
