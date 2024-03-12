"Simple addon that add random delay selected from a specified range to HTTP requests"

import random
from time import sleep
from mitmproxy import http

MIN_DELAY = 2
MAX_DELAY = 5

def request(flow: http.HTTPFlow) -> None:
    delay = random.uniform(MIN_DELAY, MAX_DELAY)
    sleep(delay)



