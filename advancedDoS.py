
from mitmproxy import ctx
from mitmproxy import flowfilter
from mitmproxy.exceptions import OptionsError
from mitmproxy.optmanager import OptManager
from typing import Optional

class DoS:
    def __init__(self):
        self.DoS = False
        self.matchall = flowfilter.parse(".")
        self.filter: Optional[flowfilter.TFilter] = self.matchall
    
    def configure(self, updates: set[str]):
        if "DoS" in updates:
            value = ctx.options.DoS
            if value is not None:
                self.DoS = value
        if "DoS_filter" in updates:
            filt_str = ctx.options.DoS_filter
            filt = self.matchall if not filt_str else flowfilter.parse(filt_str)
            if not filt:
                raise OptionsError("Invalid filter: %s" % filt_str)
            self.filter = filt

    def load(self, loader: OptManager):
        loader.add_option(
            name="DoS", typespec=bool, default=False,
            help="kill all flows",
        )
        loader.add_option(
            name="DoS_filter", typespec=Optional[str], default=None,
            help="kill filtered flows"
        )


    def request(self, flow):
        if ctx.options.DoS and flowfilter.match(self.filter, flow):
            flow.kill()
        
addons = [
    DoS()
]