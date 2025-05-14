from dataclasses import dataclass
from typing import Optional, List
from .strategies.basic_id import BasicIdParsingStrategy
from .strategies.location_vector import LocationVectorParsingStrategy
from .strategies.reserved import ReservedParsingStrategy
from .strategies.self_id import SelfIdParsingStrategy
from .strategies.system_message import SystemMessageParsingStrategy
from .strategies.operator_id import OperatorIdParsingStrategy
from .strategies.message_pack import MessagePackParsingStrategy
from .messages.direct_remote_id import DirectRemoteIdMessage
from ..parser import Parser
import struct

from scapy.packet import Packet

class DirectRemoteIdMessageParser(Parser):
    oui: List[str] = ["FA:0B:BC", "50:6F:9A"]  
    
    _strategies = {
        0x0: BasicIdParsingStrategy(),
        0x1: LocationVectorParsingStrategy(),
        # 0x2: ReservedParsingStrategy(),
        0x3: SelfIdParsingStrategy(),
        0x4: SystemMessageParsingStrategy(),
        0x5: OperatorIdParsingStrategy(),
        0xF: MessagePackParsingStrategy()
    }

    @staticmethod
    def parse(data: bytes) -> DirectRemoteIdMessage:
        """
        Parse a Direct Remote ID message from a byte array.
        """
        header = data[0]  # the first byte is the header
        msg_type = header >> 4  # first four bits represent the message type
        payload = data[1:]  # everything after is message type specific
        
        strategy = DirectRemoteIdMessageParser._strategies.get(msg_type)
        if strategy is None:
            raise ValueError(f"Unknown message type: {msg_type}")
       
        """
        Legacy Message Format: 
        - On older ADS_STAN versions, messages could be concatenated together in a single payload.
        - If the payload is longer than a single message would be, convert the payload into a ADS_STAN message pack.
        """ 
        if(len(payload) > 25 and msg_type != 0xF):
            n_messages = len(payload) // 25 
            message_size = 25 # hardcoded per protocol
            n_messages = struct.pack('B', n_messages)
            message_size = struct.pack('B', message_size)
            payload =  message_size + n_messages + data
            strategy = DirectRemoteIdMessageParser._strategies.get(0xF)

        parsed_message = strategy.parse(payload)
        return parsed_message

    @staticmethod
    def from_wifi(packet: Packet, oui: str) -> Optional[DirectRemoteIdMessage]:
        """
        @returns
            - DirectRemoteIdMessage: Parsed message
        """
        return DirectRemoteIdMessageParser.parse(packet[8:])


