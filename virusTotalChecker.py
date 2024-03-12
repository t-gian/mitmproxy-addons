from mitmproxy import http
from typing import Optional
from mitmproxy import ctx
from mitmproxy import flowfilter
from time import sleep
import requests

APIKEY = "Please insert your API Key here"
url = "https://www.virustotal.com/api/v3/urls"
headers = {
    "accept": "application/json",
    "content-type": "application/x-www-form-urlencoded",
    "x-apikey": APIKEY,
}
matchall = flowfilter.parse(".")
class VirusTotalChecker:
    def __init__(self):
        self.filter: Optional[flowfilter.TFilter] = matchall

    def load(self, loader):
        loader.add_option(
            "virus_total_filter", Optional[str], None,
            "Apply VirusTotal check only on filtered flows"
        )

    def configure(self, updates):
        if "virus_total_filter" in updates:
            filter_str = ctx.options.virus_total_filter
            self.filter = flowfilter.parse(filter_str) if filter_str else None

    def request(self, flow: http.HTTPFlow):
        if self.filter and not flowfilter.match(self.filter, flow):
            return

        payload = {
            "url": flow.request.pretty_url
        }
        response = requests.post(url, headers=headers, data=payload)
        sleep(1) # the API rate limit seems harsh...
        if response.status_code == 200:
            analysis_id = response.json().get("data", {}).get("id")

            if analysis_id:
                analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
                response = requests.get(analysis_url, headers=headers)
                sleep(1) # the API rate limit seems harsh...
                if response.status_code == 200:
                    analysis_results = response.json().get("data", {}).get("attributes", {}).get("results", {})

                    malicious_or_suspicious = False
                    for engine, result in analysis_results.items():
                        category = result.get("category")
                        if category == "malicious" or category == "suspicious":
                            malicious_or_suspicious = True
                            break

                    if malicious_or_suspicious:
                        flow.kill()

addons = [
    VirusTotalChecker()
]
