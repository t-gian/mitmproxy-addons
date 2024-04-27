from mitmproxy import contentviews
from mitmproxy.flow import Flow
from mitmproxy.http import Message
from mitmproxy.addonmanager import Loader
import protobuf.proto_deser as proto_deser
import proto_option

class GoogleProtobufView(contentviews.View):

    name = "Google Protobuf View"
    __content_types = [
        "application/x-protobuf"
    ]
    
    def __init__(self, protobuf_modifier: proto_deser.ProtoDeserializer) -> None:
        self.protobuf_modifier = protobuf_modifier
    def __call__(self, data: bytes, *, content_type: str | None = None, flow: Flow | None = None, http_message: Message | None = None, **unknown_metadata):
        deserialized_proto = self.protobuf_modifier.deserialize(http_message, data)
        return self.name, contentviews.base.format_text(deserialized_proto)
    
    def render_priority(self, data: bytes, *, content_type: str | None = None, flow: Flow | None = None, http_message: Message | None = None, **unknown_metadata) -> float:
        return float(content_type in self.__content_types)

protobuf_modifier = proto_deser.ProtoDeserializer()   
view = GoogleProtobufView(protobuf_modifier)

def load(loader: Loader):
    contentviews.add(view)

def done():
    contentviews.remove(view)

addons = [
    proto_option.protoOption(protobuf_modifier)
]
