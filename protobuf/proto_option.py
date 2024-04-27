import typing
import protobuf.proto_deser as proto_deser
import mitmproxy


class protoOption:

    def __init__(self, protobuf_modifier: proto_deser.ProtoDeserializer) -> None:
        self.protobuf_modifier = protobuf_modifier

    def load(self, loader):
        loader.add_option(
            name = "descriptor",
            typespec = typing.Optional[str],
            default=None,
            help = "Set the descriptor file for the specific protobuf"
        )

    def configure(self, updates):
        if("descriptor" in updates and mitmproxy.ctx.options.descriptor is not None):
            self.protobuf_modifier.set_descriptor(mitmproxy.ctx.options.descriptor)