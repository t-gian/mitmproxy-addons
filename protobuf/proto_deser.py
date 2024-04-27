from google.protobuf.descriptor_pool import DescriptorPool
from google.protobuf.descriptor_pb2 import FileDescriptorSet
from google.protobuf.message_factory import MessageFactory
from google.protobuf.message import DecodeError
from google.protobuf.text_format import MessageToString
import mitmproxy

class ProtoDeserializer:


    def __init__(self) -> None:
        self.descriptor_pool = DescriptorPool()


    def set_descriptor(self, descriptor_path: str) -> None:
        with open(descriptor_path, mode="rb") as f:
            descriptor = FileDescriptorSet.FromString(f.read())
            for proto in descriptor.file:
                self.descriptor_pool.Add(proto)
            self.message_factory = MessageFactory(self.descriptor_pool)
    
    def deserialize(self, http_message: mitmproxy.http.Message, serialized_protobuf: bytes) -> str:
        if (mitmproxy.ctx.options.__contains__("descriptor") and mitmproxy.ctx.options.descriptor is not None):
            messages = self.message_factory.GetMessages(mitmproxy.ctx.options.descriptor)
            try:
                merged = messages.MergeFromString(serialized_protobuf)
            except DecodeError as err:
                raise ValueError("Unable to merge") from err
            
            deserialized_message = MessageToString(
                message=merged,
                descriptor_pool=self.descriptor_pool
            )
            return deserialized_message
        else:
            mitmproxy.ctx.log("No descriptor option file set when trying to deserialize")


