from enum import IntEnum

class ClickType(IntEnum):
    NONE = 0
    LEFT = 1
    RIGHT = 2
    MIDDLE = 4


class UnifyingRole(IntEnum):
    DONGLE = 0
    MOUSE = 1
    KEYBOARD = 2


class MultimediaKey(IntEnum):
    VOLUME_DOWN = 0xEA
    VOLUME_UP = 0xE9
    VOLUME_TOGGLE = 0xE2
