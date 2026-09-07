import abc
import struct
import time

import usb

from goodix_fp_dump.usb_backend import get_libusb_backend


class Protocol(abc.ABC):

    @abc.abstractmethod
    def __init__(self, vendor: int, product: int, timeout: float | None = 5):
        ...

    @abc.abstractmethod
    def write(self, data: bytes, timeout: float | None = 5):
        ...

    @abc.abstractmethod
    def read(self, size: int = 0x4000, timeout: float | None = 5) -> bytes:
        ...

    @abc.abstractmethod
    def disconnect(self, timeout: float | None = 5):
        ...


class USBProtocol(Protocol):
    MAX_FRAME_LENGTH = 0x4000

    def __init__(self, vendor, product, timeout=5, *, strict_read_only=False):
        super().__init__(vendor, product, timeout)

        if timeout is not None:
            timeout += time.time()

        while True:
            device = usb.core.find(
                idVendor=vendor,
                idProduct=product,
                backend=get_libusb_backend(),
            )

            if device is not None:
                try:
                    usb.control.get_status(device)
                    break

                except usb.core.USBError as error:
                    if (error.backend_error_code != -1
                            and error.backend_error_code != -4):
                        raise error

            if timeout is not None and time.time() > timeout:
                if device is None:
                    raise TimeoutError("Device not found", -5, 19)

                raise TimeoutError("Invalid device state", -12, 131)

            time.sleep(0.01)

        self.device: usb.core.Device = device
        self.strict_read_only = strict_read_only
        self._read_buffer = bytearray()

        print(f"Found Goodix device: \"{self.device.product}\" "
              f"from \"{self.device.manufacturer}\" "
              f"on bus {self.device.bus} "
              f"address {self.device.address}.")

        interface_data = usb.util.find_descriptor(
            self.device.get_active_configuration(),
            custom_match=lambda interface: interface.bInterfaceClass == usb.
            legacy.CLASS_DATA or interface.bInterfaceClass == usb.legacy.
            CLASS_VENDOR_SPEC)

        if interface_data is None:
            raise ConnectionError("Interface data not found", -5, 6)

        self.interface_number: int = interface_data.bInterfaceNumber
        self.detached_kernel_driver = False

        print(f"Found interface data: {self.interface_number}")

        endpoint_in = usb.util.find_descriptor(
            interface_data,
            custom_match=lambda endpoint: usb.util.endpoint_direction(
                endpoint.bEndpointAddress) == usb.legacy.ENDPOINT_IN and usb.
            util.endpoint_type(endpoint.bmAttributes
                               ) == usb.legacy.ENDPOINT_TYPE_BULK)

        if endpoint_in is None:
            raise ConnectionError("Endpoint in not found", -5, 6)

        self.endpoint_in: int = endpoint_in.bEndpointAddress
        self._read_buffer = bytearray()
        print(f"Found endpoint in: {hex(self.endpoint_in)}")

        endpoint_out = usb.util.find_descriptor(
            interface_data,
            custom_match=lambda endpoint: usb.util.endpoint_direction(
                endpoint.bEndpointAddress) == usb.legacy.ENDPOINT_OUT and usb.
            util.endpoint_type(endpoint.bmAttributes
                               ) == usb.legacy.ENDPOINT_TYPE_BULK)

        if endpoint_out is None:
            raise ConnectionError("Endpoint out not found", -5, 6)

        self.endpoint_out: int = endpoint_out.bEndpointAddress
        print(f"Found endpoint out: {hex(self.endpoint_out)}")

        try:
            kernel_driver_active = self.device.is_kernel_driver_active(
                self.interface_number
            )
        except (NotImplementedError, usb.core.USBError):
            kernel_driver_active = False

        if kernel_driver_active and not self.strict_read_only:
            self.device.detach_kernel_driver(self.interface_number)
            self.detached_kernel_driver = True

        if not self.strict_read_only:
            self.device.set_configuration()
            usb.util.claim_interface(self.device, self.interface_number)
            self._clear_endpoint_halts()

    def _clear_endpoint_halts(self):
        for endpoint in (self.endpoint_in, self.endpoint_out):
            try:
                self.device.clear_halt(endpoint)
            except (NotImplementedError, usb.core.USBError):
                pass

    def write(self, data, timeout=5):
        timeout = 0 if timeout is None else round(timeout * 1000)

        length = len(data)
        if length % 0x40:
            data += b"\x00" * (0x40 - length % 0x40)

        for i in range(0, length, 0x40):
            self.device.write(self.endpoint_out, data[i:i + 0x40], timeout)

    def read(self, size=0x10000, timeout=5):
        timeout = 0 if timeout is None else round(timeout * 1000)

        while True:
            if len(self._read_buffer) >= 4:
                if sum(self._read_buffer[:3]) & 0xff != self._read_buffer[3]:
                    raise ValueError("Invalid USB message pack header")
                payload_length = int.from_bytes(self._read_buffer[1:3],
                                                byteorder="little")
                frame_length = 4 + payload_length
                if frame_length > self.MAX_FRAME_LENGTH:
                    raise ValueError("USB message pack is too large")
                if len(self._read_buffer) >= frame_length:
                    frame = bytes(self._read_buffer[:frame_length])
                    del self._read_buffer[:frame_length]
                    return frame

            data = self.device.read(self.endpoint_in, size, timeout).tobytes()
            if not data:
                raise ValueError("Truncated USB message pack")
            self._read_buffer.extend(data)

    def disconnect(self, timeout=5):
        # pyusb claims the interface lazily on the first bulk transfer even in
        # strict_read_only mode; dropping the handle is the only thing that
        # releases it, and a later init in the same process needs it back.
        if self.strict_read_only:
            try:
                usb.util.dispose_resources(self.device)
            except usb.core.USBError:
                pass
            return
        try:
            usb.util.release_interface(self.device, self.interface_number)
        except usb.core.USBError as error:
            if error.backend_error_code not in (-4, -5):
                raise error
        finally:
            if self.detached_kernel_driver:
                try:
                    self.device.attach_kernel_driver(self.interface_number)
                except usb.core.USBError:
                    pass
            usb.util.dispose_resources(self.device)


class SPIProtocol(Protocol):
    READ_SIZE = 256  # higher values could lock up the device until full power reset

    def __init__(self, vendor, product, timeout=5):
        super().__init__(vendor, product, timeout)

        import periphery
        import spidev

        self.device: spidev.SpiDev = spidev.SpiDev(0, 0)
        self.interrupt: periphery.CdevGPIO = periphery.CdevGPIO(
            "/dev/gpiochip0", 279, 'in', edge='falling')
        self.buffer = bytearray()
        self.seq = int()

    def _xfer(self, data: bytes, read_size=READ_SIZE):
        return bytearray(
            self.device.xfer2(data +
                              b'\0' * read_size)[len(data):]).rstrip(b'\0')

    def write(self, data, timeout=5):
        #timeout = 0 if timeout is None else round(timeout * 1000)

        self.seq += 1
        data = b"\xcc\xf2" + struct.pack('<H', self.seq) + data

        self.buffer = self._xfer(data)

    def read(self, size=READ_SIZE, timeout=5):
        if timeout is not None:
            t = time.time()

        l = len(self.buffer)
        while l < size:
            if timeout is not None and time.time() - t > timeout:
                raise TimeoutError()
            time.sleep(0.12)
            #self.interrupt.poll()
            self.buffer += self._xfer(b"\xbb\xf1\x00\x00", size - l)
            l = len(self.buffer)

        return bytes(self.buffer[:size])

    def disconnect(self, timeout=5):
        pass
