import random
from typing import Optional
from mitmproxy import ctx
from mitmproxy import flowfilter
from mitmproxy.exceptions import OptionsError
from mitmproxy.flow import Flow
from mitmproxy.optmanager import OptManager
from mitmproxy.script import concurrent

matchall = flowfilter.parse(".")


class RandomResponseError:
    def __init__(self):
        self.filter: Optional[flowfilter.TFilter] = matchall

    def load(self, loader: OptManager):
        loader.add_option(
            "error_rate", Optional[int], None,
            "Rate of HTTP responses with random error codes (0-100)",
        )
        loader.add_option(
            "error_filter", Optional[str], None,
            "Apply error HTTP responses to filtered flows"
        )
        
    def configure(self, updates: set[str]):
        if "error_rate" in updates:
            error_rate = ctx.options.error_rate
            if error_rate < 0 or error_rate > 100:
                raise OptionsError("error_rate must be between 0 and 100")
        if "error_filter" in updates:
            filt_str = ctx.options.error_filter
            filt = matchall if not filt_str else flowfilter.parse(filt_str)
            if not filt:
                raise OptionsError("Invalid filter: %s" % filt_str)
            self.filter = filt

    @concurrent
    def response(self, flow: Flow):
        error_rate = ctx.options.error_rate
        if error_rate > 0 and random.randrange(1, 101) <= error_rate and flowfilter.match(self.filter, flow):
            http_errors = [400, 403, 404, 500, 502, 503, 504]
            flow.response.status_code = random.choice(http_errors)
            flow.response.content = None


addons = [
    RandomResponseError()
]
