from parse.parser import ParsedMessage

class DirectRemoteIdMessage(ParsedMessage):
    """
    A class that represents a Direct Remote ID message.
    Attributes:
        message_type: The type of the message (0x0-0x5, 0xF).
        version: The version of the message (0x0-0xF).
    """
    message_type: int
    version: int    
    
    def __init__(self, message_type: int, version: int):
        """
        Initialize a Direct Remote ID message.
        
        Args:
            message_type: The type of the message (0x0-0x5, 0xF)
            version: The version of the message (0x0-0xF)
        """
        super().__init__(provider="ADS-STAN")
        self.message_type = message_type
        self.version = version
