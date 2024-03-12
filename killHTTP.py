"Simple addon that kills all HTTP requests simulating a Denial Of Service of the mitmproxy"

from mitmproxy import http

def request(flow: http.HTTPFlow) -> None:
    flow.kill()