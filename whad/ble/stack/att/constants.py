"""ATT constants (error and operation codes)
"""

class BleAttOpcode:
    """ATT operation codes
    """
    ERROR_RESPONSE = 0x01
    EXCHANGE_MTU_REQUEST = 0x02
    EXCHANGE_MTU_RESPONSE = 0x03
    FIND_INFO_REQUEST = 0x04
    FIND_INFO_RESPONSE = 0x05
    FIND_BY_TYPE_VALUE_REQUEST = 0x06
    FIND_BY_TYPE_VALUE_RESPONSE = 0x07
    READ_BY_TYPE_REQUEST = 0x08
    READ_BY_TYPE_RESPONSE = 0x09
    READ_REQUEST = 0x0A
    READ_RESPONSE = 0x0B
    READ_BLOB_REQUEST = 0x0C
    READ_BLOB_RESPONSE = 0x0D
    READ_MULTIPLE_REQUEST = 0x0E
    READ_MULTIPLE_RESPONSE = 0x0F
    READ_BY_GROUP_TYPE_REQUEST = 0x10
    READ_BY_GROUP_TYPE_RESPONSE = 0x11
    WRITE_REQUEST = 0x12
    WRITE_RESPONSE = 0x13
    WRITE_COMMAND = 0x52
    SIGNED_WRITE_COMMAND = 0xD2
    PREPARE_WRITE_REQUEST = 0x16
    PREPARE_WRITE_RESPONSE = 0x17
    EXECUTE_WRITE_REQUEST = 0x18
    EXECUTE_WRITE_RESPONSE = 0x19
    HANDLE_VALUE_NOTIFICATION = 0x1B
    HANDLE_VALUE_INDICATION = 0x1D
    HANDLE_VALUE_CONFIRMATION = 0x1E

class BleAttErrorCode:
    """ATT error code
    """
    INVALID_HANDLE = 0x01
    READ_NOT_PERMITTED = 0x02
    WRITE_NOT_PERMITTED = 0x03
    INVALID_PDU = 0x04
    INSUFFICIENT_AUTHENT = 0x05
    REQUEST_NOT_SUPP = 0x06
    INVALID_OFFSET = 0x07
    INSUFFICIENT_AUTHOR = 0x08
    PREPARE_QUEUE_FULL = 0x09
    ATTRIBUTE_NOT_FOUND = 0x0A
    ATTRIBUTE_NOT_LONG = 0x0B
    INSUFFICIENT_ENC_KEY_SIZE = 0x0C
    INVALID_ATTR_VALUE_LENGTH = 0x0D
    UNLIKELY_ERROR = 0x0E
    INSUFFICIENT_ENCRYPTION = 0x0F
    UNSUPPORTED_GROUP_TYPE = 0x10
    INSUFFICIENT_RESOURCES = 0x11

class SecurityMode:
    def __init__(self, security_mode=0, security_level=0):
        self.security_mode = security_mode
        self.security_level = security_level

class BleAttSecurityMode:
    NO_ACCESS = SecurityMode(0, 0)
    OPEN = SecurityMode(1, 1)
    ENCRYPTION_NO_AUTHENTICATION = SecurityMode(1, 2)
    ENCRYPTION_WITH_AUTHENTICATION = SecurityMode(1, 3)
    ENCRYPTION_WITH_SECURE_CONNECTIONS = SecurityMode(1, 4)
    DATA_SIGNING_NO_AUTHENTICATION = SecurityMode(2, 1)
    DATA_SIGNING_WITH_AUTHENTICATION = SecurityMode(2, 2)

class BleAttProperties:
    READ = 0x01
    WRITE = 0x02
    DEFAULT = READ | WRITE


class SecurityProperty:
    def __repr__(self):
        return self.__class__.__name__

class Encryption(SecurityProperty):
    pass

class Authentication(SecurityProperty):
    pass

class Authorization(SecurityProperty):
    pass

class SecurityAccess:

    def __init__(self, property_name, *args):
        self.__property_name = property_name
        self.__access = {}
        if isinstance(args, types.UnionType):
            self.__access[self.__property_name] = list(args.__args__)
        else:
            self.__access[self.__property_name] = args


    def requires_encryption(self, property=None):
        key = property if property is not None else self.__property_name
        return Encryption in self.__access[key]

    def requires_authentication(self, property=None):
        key = property if property is not None else self.__property_name
        return Authentication in self.__access[key]

    def requires_authorization(self, property=None):
        key = property if property is not None else self.__property_name
        return Authorization in self.__access[key]

    @property
    def property_name(self):
        return self.__property_name

    @property
    def access(self):
        return self.__access

    @access.setter
    def access(self, value):
        self.__access = value

    def __or__(self, other):
        self.access.update(other.access)

'''
ReadAccess(Encryption, Authentication, Authorization) | WriteAccess(Encryption, Authentication)
'''
