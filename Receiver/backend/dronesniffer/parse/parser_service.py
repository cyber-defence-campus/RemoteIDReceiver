from dataclasses import dataclass
from typing import Optional, Dict, Type, List
from scapy.packet import Packet
import logging

from .ads_stan.messages.direct_remote_id import DirectRemoteIdMessage
from .ads_stan.parser import DirectRemoteIdMessageParser
from .dji.parser import DjiParser
from .dji.messages.dji_message import DjiMessage

@dataclass
class ParsedMessage:
    """Represents a parsed Remote ID message from any supported protocol."""
    provider: str
    message: DirectRemoteIdMessage | DjiMessage

    @property
    def is_ads_stan(self) -> bool:
        return self.provider == "ADS-STAN"

    @property
    def is_dji(self) -> bool:
        return self.provider == "DJI"

class RemoteIdParser:
    """Main service for parsing Remote ID messages from different protocols."""
    
    def __init__(self):
        # Map of OUI to their respective parser classes and provider names
        self._parsers: Dict[str, tuple[Type, str]] = {}
        
        # Register all parsers and their OUIs
        self._register_parser(DjiParser, "DJI")
        self._register_parser(DirectRemoteIdMessageParser, "ADS-STAN")

    def _register_parser(self, parser_class: Type, provider: str) -> None:
        """Register a parser class and all its supported OUIs."""
        for oui in parser_class.oui:
            self._parsers[oui] = (parser_class, provider)

    def from_wifi(self, packet: Packet, oui: str) -> Optional[ParsedMessage]:
        """
        Parse a Remote ID packet based on its OUI.
        
        Args:
            packet: The Wi-Fi packet containing Remote ID data
            oui: The Organizationally Unique Identifier of the packet
            
        Returns:
            ParsedMessage if parsing successful, None otherwise
        """
        if oui not in self._parsers:
            return None
            
        parser_class, provider = self._parsers[oui]
        
        try:
            message = parser_class.from_wifi(packet, oui)
            return ParsedMessage(provider=provider, message=message) if message else None
        except Exception as e:
            logging.error(f"Unexpected error parsing {provider} message: {e}")
            return None

    def is_supported_protocol(self, oui: str) -> bool:
        """
        Check if a given OUI is supported by any of the parsers.
        
        Args:
            oui: The Organizationally Unique Identifier to check
            
        Returns:
            bool: True if the OUI is supported, False otherwise
        """
        return oui in self._parsers

# Create a singleton instance for easy access
parser = RemoteIdParser() 