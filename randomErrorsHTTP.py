"Simple addon that returns random HTTP error codes for a specified rate of HTTP responses"
import random
from mitmproxy import http

RATE_ERROR = 20

http_erros = [400, 403, 404, 500, 502, 503, 504]

def response(flow: http.HTTPFlow) -> None:
    if random.randrange(1, 101) <= RATE_ERROR:
        flow.response.status_code = random.choice(http_erros)
        flow.response.content = None
