"""NWK exceptions
"""

class NWKTimeoutException(Exception):
    def __init__(self):
        super().__init__()

class NWKInvalidKey(Exception):
    def __init__(self):
        super().__init__()