"""Bluetooth LE SMP constants
"""
SM_PAIRING_REQUEST              = 1
SM_PAIRING_RESPONSE             = 2
SM_CONFIRM                      = 3
SM_RANDOM                       = 4
SM_FAILED                       = 5
SM_ENCRYPTION_INFORMATION       = 6
SM_MASTER_IDENTIFICATION        = 7
SM_IDENTITY_INFORMATION         = 8
SM_IDENTITY_ADDRESS_INFORMATION = 9
SM_SIGNING_INFORMATION          = 0x0a
SM_SECURITY_REQUEST             = 0x0b
SM_PUBLIC_KEY                   = 0x0c
SM_DHKEY_CHECK                  = 0x0d


OOB_DISABLED = 0x00
OOB_ENABLED = 0x01

IOCAP_DISPLAY_ONLY = 0x00
IOCAP_DISPLAY_YESNO = 0x01
IOCAP_KEYBD_ONLY = 0x02
IOCAP_NOINPUT_NOOUTPUT = 0x03
IOCAP_KEYBD_DISPLAY = 0x04

PM_LEGACY_JUSTWORKS = 0x00
PM_LEGACY_PASSKEY = 0x01
PM_LEGACY_OOB = 0x02
PM_LESC_JUSTWORKS = 0x03
PM_LESC_NUMCOMP = 0x04
PM_LESC_PASSKEY = 0x05
PM_LESC_OOB = 0x06

AUTHENTICATED_METHODS = (PM_LEGACY_PASSKEY, PM_LEGACY_OOB, PM_LESC_PASSKEY, PM_LESC_NUMCOMP, PM_LESC_OOB)

SM_ERROR_PASSKEY_ENTRY_FAILED = 0x01
SM_ERROR_OOB_NOT_AVAIL = 0x02
SM_ERROR_AUTH_REQ = 0x03
SM_ERROR_CONFIRM_VALUE_FAILED = 0x04
SM_ERROR_UNSUPP_PAIRING = 0x05
SM_ERROR_ENC_KEY_SIZE = 0x06
SM_ERROR_UNSUPP_COMMAND = 0x07
SM_ERROR_UNSPEC_REASON = 0x08
SM_ERROR_REPEATED_ATTEMPTS = 0x09
SM_ERROR_INVALID_PARAMS = 0x0A
SM_ERROR_DHKEY_CHECK_FAILED = 0x0B
SM_ERROR_NUMCOMP_FAILED = 0x0C
SM_ERROR_BREDR_PAIRING = 0x0D
SM_ERROR_CROSS_TRANSP_NOT_ALLOWED = 0x0E
SM_ERROR_KEY_REJECTED = 0x0F


IOCAP_KEY_GENERATION_MAPPING = {}
IOCAP_KEY_GENERATION_MAPPING[(IOCAP_DISPLAY_ONLY, IOCAP_DISPLAY_ONLY)] = (PM_LEGACY_JUSTWORKS, PM_LESC_JUSTWORKS)
IOCAP_KEY_GENERATION_MAPPING[(IOCAP_DISPLAY_YESNO, IOCAP_DISPLAY_ONLY)] = (PM_LEGACY_JUSTWORKS, PM_LESC_JUSTWORKS)
IOCAP_KEY_GENERATION_MAPPING[(IOCAP_KEYBD_ONLY, IOCAP_DISPLAY_ONLY)] = (PM_LEGACY_PASSKEY, PM_LESC_PASSKEY)
IOCAP_KEY_GENERATION_MAPPING[(IOCAP_NOINPUT_NOOUTPUT, IOCAP_DISPLAY_ONLY)] = (PM_LEGACY_JUSTWORKS, PM_LESC_JUSTWORKS)
IOCAP_KEY_GENERATION_MAPPING[(IOCAP_KEYBD_DISPLAY, IOCAP_DISPLAY_ONLY)] = (PM_LEGACY_PASSKEY, PM_LESC_PASSKEY)

IOCAP_KEY_GENERATION_MAPPING[(IOCAP_DISPLAY_ONLY, IOCAP_DISPLAY_YESNO)] = (PM_LEGACY_JUSTWORKS, PM_LESC_JUSTWORKS)
IOCAP_KEY_GENERATION_MAPPING[(IOCAP_DISPLAY_YESNO, IOCAP_DISPLAY_YESNO)] = (PM_LEGACY_JUSTWORKS, PM_LESC_NUMCOMP)
IOCAP_KEY_GENERATION_MAPPING[(IOCAP_KEYBD_ONLY, IOCAP_DISPLAY_YESNO)] = (PM_LEGACY_PASSKEY, PM_LESC_PASSKEY)
IOCAP_KEY_GENERATION_MAPPING[(IOCAP_NOINPUT_NOOUTPUT, IOCAP_DISPLAY_YESNO)] = (PM_LEGACY_JUSTWORKS, PM_LESC_JUSTWORKS)
IOCAP_KEY_GENERATION_MAPPING[(IOCAP_KEYBD_DISPLAY, IOCAP_DISPLAY_YESNO)] = (PM_LEGACY_PASSKEY, PM_LESC_NUMCOMP)

IOCAP_KEY_GENERATION_MAPPING[(IOCAP_DISPLAY_ONLY, IOCAP_KEYBD_ONLY)] = (PM_LEGACY_PASSKEY, PM_LESC_PASSKEY)
IOCAP_KEY_GENERATION_MAPPING[(IOCAP_DISPLAY_YESNO, IOCAP_KEYBD_ONLY)] = (PM_LEGACY_PASSKEY, PM_LESC_PASSKEY)
IOCAP_KEY_GENERATION_MAPPING[(IOCAP_KEYBD_ONLY, IOCAP_KEYBD_ONLY)] = (PM_LEGACY_PASSKEY, PM_LESC_PASSKEY)
IOCAP_KEY_GENERATION_MAPPING[(IOCAP_NOINPUT_NOOUTPUT, IOCAP_KEYBD_ONLY)] = (PM_LEGACY_JUSTWORKS, PM_LESC_JUSTWORKS)
IOCAP_KEY_GENERATION_MAPPING[(IOCAP_KEYBD_DISPLAY, IOCAP_KEYBD_ONLY)] = (PM_LEGACY_PASSKEY, PM_LESC_PASSKEY)

IOCAP_KEY_GENERATION_MAPPING[(IOCAP_DISPLAY_ONLY, IOCAP_NOINPUT_NOOUTPUT)] = (PM_LEGACY_JUSTWORKS, PM_LESC_JUSTWORKS)
IOCAP_KEY_GENERATION_MAPPING[(IOCAP_DISPLAY_YESNO, IOCAP_NOINPUT_NOOUTPUT)] = (PM_LEGACY_JUSTWORKS, PM_LESC_JUSTWORKS)
IOCAP_KEY_GENERATION_MAPPING[(IOCAP_KEYBD_ONLY, IOCAP_NOINPUT_NOOUTPUT)] = (PM_LEGACY_JUSTWORKS, PM_LESC_JUSTWORKS)
IOCAP_KEY_GENERATION_MAPPING[(IOCAP_NOINPUT_NOOUTPUT, IOCAP_NOINPUT_NOOUTPUT)] = (PM_LEGACY_JUSTWORKS, PM_LESC_JUSTWORKS)
IOCAP_KEY_GENERATION_MAPPING[(IOCAP_KEYBD_DISPLAY, IOCAP_NOINPUT_NOOUTPUT)] = (PM_LEGACY_JUSTWORKS, PM_LESC_JUSTWORKS)

IOCAP_KEY_GENERATION_MAPPING[(IOCAP_DISPLAY_ONLY, IOCAP_KEYBD_DISPLAY)] = (PM_LEGACY_PASSKEY, PM_LESC_PASSKEY)
IOCAP_KEY_GENERATION_MAPPING[(IOCAP_DISPLAY_YESNO, IOCAP_KEYBD_DISPLAY)] = (PM_LEGACY_PASSKEY, PM_LESC_NUMCOMP)
IOCAP_KEY_GENERATION_MAPPING[(IOCAP_KEYBD_ONLY, IOCAP_KEYBD_DISPLAY)] = (PM_LEGACY_PASSKEY, PM_LESC_PASSKEY)
IOCAP_KEY_GENERATION_MAPPING[(IOCAP_NOINPUT_NOOUTPUT, IOCAP_KEYBD_DISPLAY)] = (PM_LEGACY_JUSTWORKS, PM_LESC_JUSTWORKS)
IOCAP_KEY_GENERATION_MAPPING[(IOCAP_KEYBD_DISPLAY, IOCAP_KEYBD_DISPLAY)] = (PM_LEGACY_PASSKEY, PM_LESC_NUMCOMP)
