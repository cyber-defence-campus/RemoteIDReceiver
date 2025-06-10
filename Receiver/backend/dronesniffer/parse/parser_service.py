from typing import Optional, Dict
from scapy.packet import Packet
import logging

from .ads_stan.parser import DirectRemoteIdMessageParser
from .dji.parser import DjiParser
from .parser import ParsedMessage, Parser

class ParserService:
    """Main service for parsing Remote ID messages from different protocols."""
    
    _parsers: Dict[str, tuple[Parser, str]] = {}
    
    def __init__(self):
        # Map of OUI to their respective parser classes and provider names
        self._parsers: Dict[str, tuple[Parser, str]] = {}

        # Register all parsers and their OUIs
        self.__register_parser(DjiParser, "DJI")
        self.__register_parser(DirectRemoteIdMessageParser, "ADS-STAN")

    def __register_parser(self, parser_class: Parser, provider: str) -> None:
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
            return parser_class.from_wifi(packet, oui)
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
parser = ParserService() 