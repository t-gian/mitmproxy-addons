import time
from typing import Optional
from mitmproxy import ctx
from mitmproxy import flowfilter
from mitmproxy.exceptions import OptionsError
from mitmproxy.flow import Flow
from mitmproxy.optmanager import OptManager
from mitmproxy.script import concurrent

matchall = flowfilter.parse(".")


class Delay:
    def __init__(self):
        self.filter: Optional[flowfilter.TFilter] = matchall

    def load(self, loader: OptManager):
        loader.add_option(
            "sleep", Optional[int], None,
            "Delay client requests (seconds)",
        )
        loader.add_option(
            "sleep_filter", Optional[str], None,
            "Apply delay to filtered flows (seconds)"
        )

    def configure(self, updates: set[str]):
        if "sleep" in updates:
            sleep = ctx.options.sleep
            if sleep and sleep < 0:
                raise OptionsError("sleep must be >= 0")
        if "sleep_filter" in updates:
            filt_str = ctx.options.sleep_filter
            filt = matchall if not filt_str else flowfilter.parse(filt_str)
            if not filt:
                raise OptionsError("Invalid filter: %s" % filt_str)
            self.filter = filt

    @concurrent
    def request(self, flow: Flow):
        delay = ctx.options.sleep
        if delay and delay > 0 and flowfilter.match(self.filter, flow):
            time.sleep(delay)


addons = [
    Delay()
]