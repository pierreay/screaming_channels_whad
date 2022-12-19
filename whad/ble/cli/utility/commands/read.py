"""BLE characteristic read command handler
"""

from prompt_toolkit import print_formatted_text, HTML
from whad.cli.app import command
from whad.ble import Central
from hexdump import hexdump
from whad.ble.utils.att import UUID
from whad.ble.stack.att.exceptions import AttError
from whad.ble.stack.gatt.exceptions import GattTimeoutException
from whad.ble.cli.utility.helpers import show_att_error

@command('read')
def read_handler(app, command_args):
    """read a GATT attribute
    
    <ansicyan><b>read</b> <i>[UUID | handle] ([offset])</i></ansicyan>

    Read an attribute identified by its handle, or read the value of a characteristic
    identified by its UUID (if unique). An optional offset can be provided
    to start reading from the specified byte position (it will issue a
    <i>ReadBlob</i> operation).

    Result is displayed as an hexadecimal dump with corresponding ASCII text:

    $ whad-ble -i hci0 -b 00:11:22:33:44:55 read 42
    00000000: 74 68 69 73 20 69 73 20  61 20 74 65 73 74        this is a test
    """
    # We need to have an interface specified
    if app.interface is not None and app.args.bdaddr is not None:
        
        # Switch to central mode
        central = Central(app.interface)
        central.start()

        # Connect to target device
        device = central.connect(app.args.bdaddr)
        if device is None:
            app.error('Cannot connect to %s, device does not respond.' % app.args.bdaddr)
        else:
            # Connected to target device, read characteristic
            # parse target arguments
            if len(command_args) == 0:
                app.error('You must provide at least a characteristic value handle or characteristic UUID.')
                return
            else:
                handle = None
                offset = None
                uuid = None

            # figure out what the handle is
            if command_args[0].lower().startswith('0x'):
                try:
                    handle = int(command_args[0].lower(), 16)
                except ValueError as badval:
                    app.error('Wrong handle: %s' % command_args[0])
                    return
            else:
                try:
                    handle = int(command_args[0])
                except ValueError as badval:
                    try:
                        handle = UUID(command_args[0].replace('-',''))
                    except:
                        app.error('Wrong UUID: %s' % command_args[0])
                        return

            # Check offset and length
            if len(command_args) >= 2:
                try:
                    offset = int(command_args[1])
                except ValueError as badval:
                    app.error('Wrong offset value, will use 0 instead.')
                    offset = None
                
            # Perform characteristic read by handle
            if not isinstance(handle, UUID):
                try:
                    value = device.read(handle, offset=offset)

                    # Display result as hexdump
                    hexdump(value)
                except AttError as att_err:
                    show_att_error(app, att_err)
                except GattTimeoutException as timeout:
                    app.error('GATT timeout while reading.')

            else:
                # Perform discovery if UUID is given
                device.discover()

                # Search characteristic from its UUID
                target_charac = device.find_characteristic_by_uuid(handle)                       
                if target_charac is not None:
                    try:
                        # Read data
                        if offset is not None:
                            value = target_charac.read(offset=offset)
                        else:
                            value = target_charac.read()

                        # Display result as hexdump
                        hexdump(value)
                    
                    except AttError as att_err:
                        show_att_error(app, att_err)
                    except GattTimeoutException as timeout:
                        app.error('GATT timeout while reading.')
                else:
                    app.error('No characteristic found with UUID %s' % handle)

            # Disconnect
            device.disconnect()

        # Terminate central
        central.stop()

    elif app.interface is None:
        app.error('You need to specify an interface with option --interface.')
    else:
        app.error('You need to specify a target device with option --bdaddr.')