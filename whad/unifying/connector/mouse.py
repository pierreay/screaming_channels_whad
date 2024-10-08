from whad.unifying.connector import Unifying
from whad.esb.stack import ESBStack
from whad.unifying.stack import UnifyingApplicativeLayer, UnifyingRole, ClickType
from whad.exceptions import UnsupportedCapability


class Mouse(Unifying):
    """
    Logitech Unifying Mouse interface for compatible WHAD device.
    """
    def __init__(self, device):
        super().__init__(device)

        self.__channel = 5
        self.__address = "ca:e9:06:ec:a4"
        self.__started = False
        ESBStack.add(UnifyingApplicativeLayer)
        self.__stack = ESBStack(self)
        # Check if device can choose its own address
        if not self.can_set_node_address():
            raise UnsupportedCapability("SetNodeAddress")

        # Check if device can perform mouse simulation
        if not self.can_be_mouse():
            raise UnsupportedCapability("MouseSimulation")

        self._enable_role()


    def lock(self):
        return self.__stack.app.lock_channel()

    def unlock(self):
        return self.__stack.app.unlock_channel()

    def _enable_role(self):
        if self.__started:
            super().stop()
        self.set_node_address(self.__address)
        self.enable_mouse_mode(channel=self.__channel)
        self.__stack.app.role = UnifyingRole.MOUSE
        if self.__started:
            super().start()
    @property
    def channel(self):
        return self.__channel

    @channel.setter
    def channel(self, channel=5):
        self.__channel = channel
        self._enable_role()

    def start(self):
        self.__started = True
        self._enable_role()

    def stop(self):
        self.__started = False
        self.unlock()
        super().stop()

    @property
    def stack(self):
        return self.__stack

    @property
    def address(self):
        return self.__address

    @address.setter
    def address(self, address):
        self.__address = address
        self._enable_role()

    def on_pdu(self, packet):
        self.__stack.on_pdu(packet)

    def synchronize(self, timeout=10):
        return self.__stack.ll.synchronize(timeout=timeout)

    def move(self, x, y):
        return self.__stack.app.move_mouse(x, y)

    def left_click(self):
        return self.__stack.app.click_mouse(type=ClickType.LEFT)

    def right_click(self):
        return self.__stack.app.click_mouse(type=ClickType.RIGHT)

    def middle_click(self):
        return self.__stack.app.click_mouse(type=ClickType.MIDDLE)

    def wheel_up(self):
        return self.__stack.app.wheel_mouse(x=0, y=1)

    def wheel_down(self):
        return self.__stack.app.wheel_mouse(x=0, y=-1)

    def wheel_right(self):
        return self.__stack.app.wheel_mouse(x=1, y=0)

    def wheel_left(self):
        return self.__stack.app.wheel_mouse(x=-1, y=0)
