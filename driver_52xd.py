import argparse
import hashlib
import json
import random
import re
import socket
import time

import goodix
import protocol
import tool
from goodix_fp_dump import preview
from goodix_fp_dump.firmware import (
    OTPReadResult,
    classify_otp,
    classify_otp_error,
)
from goodix_fp_dump.tls_proxy import TLSServer

VALID_FIRMWARE = "GFUSB_GM168SEC_APP_100[0-9]{2}"

PMK_HASH_LENGTH = 32
PSK_FILE_LEN = 32

DEVICE_CONFIG = bytes.fromhex(
    "701160712c9d2cc91ce518fd00fd00fd03ba000180ca0008008400bec38600b1"
    "b68800baba8a00b3b38c00bcbc8e00b1b19000bbbb9200b1b194000000960000"
    "00980000009a000000d2000000d4000000d6000000d800000050000105d00000"
    "00700000007200785674003412200010402a0102042200012024003200800001"
    "005c000101560024205800010232000402660000027c00005882007f082a0182"
    "072200012024001400800001405c00ea00560006145800040232000c02660000"
    "027c000058820080082a0108005c000101540000016200080464001000660000"
    "027c0000582a0108005c00e8005200080054000001660000027c00005820c50e")

DEVICE_POV_CONFIG = bytes.fromhex(
    "040f8d8d868697978f8f9b9b929296968c8c00000000000000000803a700a100"
    "a700a3000a020503")

SENSOR_WIDTH = 80
SENSOR_HEIGHT = 64
IMAGE_FRAME_BYTES = 7684

def init_device(product: int, *, strict_read_only: bool = False):
    transport = (lambda vendor, product, timeout:
                 protocol.USBProtocol(vendor, product, timeout,
                                      strict_read_only=strict_read_only))
    device = goodix.Device(product, transport)

    device.nop()

    return device


def classify_device_psk_state(reply):
    """Whether the 0xbb020001 reply is a well-formed 32-byte device hash.

    There is no "recognized" outcome for this family. The siblings can
    recognise a hash because they share one factory PSK; the 521d is
    provisioned with a random per-device key, so the only hash this code
    could ever match is one specific unit's, which is not something a
    published probe should report on.
    """
    if not isinstance(reply, (tuple, list)) or len(reply) < 3:
        return "invalid/unreadable"
    if not reply[0] or reply[1] != 0xbb020001:
        return "invalid/unreadable"
    if not isinstance(reply[2], bytes) or len(reply[2]) != PMK_HASH_LENGTH:
        return "invalid/unreadable"
    return "unknown_device_hash"


def read_otp_diagnostics(device: goodix.Device, retries: int = 1, delay: float = 0.1):
    errors = []
    for attempt in range(retries + 1):
        try:
            result = classify_otp(goodix.Device.read_otp(device))
        except Exception as error:
            result = classify_otp_error(error)
            errors.append(result.as_dict())
        else:
            if result.ok or attempt == retries:
                return result

        if attempt < retries:
            time.sleep(delay)

    final = classify_otp_error(RuntimeError("OTP read failed"))
    return OTPReadResult(
        final.status,
        error=final.error,
        metadata={"attempts": retries + 1, "errors": errors},
    )


def read_only_probe(product: int):
    device = init_device(product, strict_read_only=True)
    try:
        firmware = None
        device_psk_reply = None
        device_psk_state = "invalid/unreadable"
        try:
            firmware = device.firmware_version()
        except Exception as error:
            firmware = {"error": str(error)}

        try:
            device_psk_reply = device.preset_psk_read(0xbb020001,
                                                       PMK_HASH_LENGTH, 0)
            device_psk_state = classify_device_psk_state(device_psk_reply)
        except Exception as error:
            device_psk_state = "invalid/unreadable"

        return {
            "product": f"{product:04x}",
            "path": "run_521d.py -> driver_52xd.py -> protocol.USBProtocol",
            "firmware": firmware,
            "device_psk_state": device_psk_state,
            "otp": read_otp_diagnostics(device, retries=1).as_dict(),
        }
    finally:
        try:
            device.disconnect()
        except Exception:
            pass


def _verify_and_get_psk(device: goodix.Device, psk_file: str) -> bytes:
    """Live self-check: sha256(PSK from --psk-file) must equal the device's
    0xbb020001 readback. No hardcoded unit hash; works on any 521d."""
    firmware = device.firmware_version()
    assert re.fullmatch(VALID_FIRMWARE, firmware)

    reply = device.preset_psk_read(0xbb020001, PMK_HASH_LENGTH, 0)
    assert reply[0] and reply[1] == 0xbb020001
    device_hash = reply[2]

    assert psk_file
    with open(psk_file, 'rb') as fh:
        psk = fh.read()
    assert len(psk) == PSK_FILE_LEN
    assert hashlib.sha256(psk).digest() == device_hash
    return psk


def _bring_up(device: goodix.Device, tls_client: socket.socket, tls_server: TLSServer):
    if not device.upload_config_mcu(DEVICE_CONFIG):
        raise ValueError("Failed to upload config")

    device.set_drv_state()
    device.mcu_get_pov_image()

    device.mcu_switch_to_fdt_mode(
        b"\x0d\x01\x27\x01\x21\x01\x27\x01"
        b"\x23\x01\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00", False)
    device.mcu_switch_to_fdt_mode(
        b"\x0d\x01\x27\x01\x21\x01\x27\x01"
        b"\x23\x01\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x01", True)

    # Calibration/"clear" frames: reverse-engineered as required sensor
    # bring-up; omitting them left the sensor saturated on the first real
    # attempt.
    device.write_sensor_register(0x022c, b"\x0a\x03")
    tls_client.sendall(
        device.mcu_get_image(
            b"\x01\x03\x27\x01\x21\x01\x27\x01\x23\x01",
            goodix.FLAGS_TRANSPORT_LAYER_SECURITY_DATA)[9:])
    tls_server.stdout.read(IMAGE_FRAME_BYTES)

    device.write_sensor_register(0x022c, b"\x0a\x02")
    device.write_sensor_register(0x022c, b"\x0a\x03")
    tls_client.sendall(
        device.mcu_get_image(
            b"\x81\x03\x27\x01\x21\x01\x27\x01\x23\x01",
            goodix.FLAGS_TRANSPORT_LAYER_SECURITY_DATA)[9:])
    tls_server.stdout.read(IMAGE_FRAME_BYTES)

    device.write_sensor_register(0x022c, b"\x0a\x02")
    device.write_sensor_register(0x022c, b"\x0a\x03")
    tls_client.sendall(
        device.mcu_get_image(
            b"\x81\x03\x18\x01\x12\x01\x18\x01\x14\x01",
            goodix.FLAGS_TRANSPORT_LAYER_SECURITY_DATA)[9:])
    tls_server.stdout.read(IMAGE_FRAME_BYTES)

    device.write_sensor_register(0x022c, b"\x0a\x02")

    device.mcu_switch_to_fdt_mode(
        b"\x8d\x01\x27\x01\x21\x01\x27\x01"
        b"\x23\x01\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00", False)
    device.mcu_switch_to_fdt_mode(
        b"\x8d\x01\x27\x01\x21\x01\x27\x01"
        b"\x23\x01\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x01", True)

    device.write_sensor_register(0x022c, b"\x0a\x03")
    tls_client.sendall(
        device.mcu_get_image(
            b"\x81\x03\x27\x01\x21\x01\x27\x01\x23\x01",
            goodix.FLAGS_TRANSPORT_LAYER_SECURITY_DATA)[9:])
    tls_server.stdout.read(IMAGE_FRAME_BYTES)

    device.write_sensor_register(0x022c, b"\x0a\x02")

    device.mcu_switch_to_fdt_mode(
        b"\x0d\x01\x27\x01\x21\x01\x27\x01"
        b"\x23\x01\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00", False)
    device.mcu_switch_to_fdt_mode(
        b"\x0d\x01\x27\x01\x21\x01\x27\x01"
        b"\x23\x01\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x01", True)

    device.set_pov_config(DEVICE_POV_CONFIG)

    device.mcu_switch_to_sleep_mode()
    device.query_mcu_state(b"\x01\x01\x01", False)


def _arm_and_capture_one(
        device: goodix.Device, tls_client: socket.socket, tls_server: TLSServer):
    device.mcu_switch_to_fdt_down(
        b"\x9c\x01\x27\x01\x21\x01\x27\x01"
        b"\x23\x01\x8d\x8d\x86\x86\x97\x97"
        b"\x8f\x8f\x9b\x9b\x92\x92\x96\x96"
        b"\x8c\x8c\x00\x00\x05\x03\xa7\x00"
        b"\xa1\x00\xa7\x00\xa3\x00\x00", False)
    device.mcu_switch_to_fdt_down(
        b"\x9c\x01\x27\x01\x21\x01\x27\x01"
        b"\x23\x01\x8d\x8d\x86\x86\x97\x97"
        b"\x8f\x8f\x9b\x9b\x92\x92\x96\x96"
        b"\x8c\x8c\x01\x00\x05\x03\xa7\x00"
        b"\xa1\x00\xa7\x00\xa3\x00\x00", False)

    device.mcu_switch_to_sleep_mode()
    device.query_mcu_state(b"\x00\x00\x00", False)
    device.query_mcu_state(b"\x01\x01\x01", False)

    device.mcu_switch_to_fdt_down(
        b"\x9c\x01\x27\x01\x21\x01\x27\x01"
        b"\x23\x01\x8d\x8d\x86\x86\x97\x97"
        b"\x8f\x8f\x9b\x9b\x92\x92\x96\x96"
        b"\x8c\x8c\x00\x00\x05\x03\xa7\x00"
        b"\xa1\x00\xa7\x00\xa3\x00\x00", False)

    print("Waiting for finger...")
    device.mcu_switch_to_fdt_down(
        b"\x9c\x01\x27\x01\x21\x01\x27\x01"
        b"\x23\x01\x8d\x8d\x86\x86\x97\x97"
        b"\x8f\x8f\x9b\x9b\x92\x92\x96\x96"
        b"\x8c\x8c\x01\x00\x05\x03\xa7\x00"
        b"\xa1\x00\xa7\x00\xa3\x00\x00", True)

    device.mcu_switch_to_fdt_mode(
        b"\x0d\x01\x27\x01\x21\x01\x27\x01"
        b"\x23\x01\x8d\x8d\x86\x86\x97\x97"
        b"\x8f\x8f\x9b\x9b\x92\x92\x96\x96"
        b"\x8c\x8c\x00", False)
    device.mcu_switch_to_fdt_mode(
        b"\x0d\x01\x27\x01\x21\x01\x27\x01"
        b"\x23\x01\x8d\x8d\x86\x86\x97\x97"
        b"\x8f\x8f\x9b\x9b\x92\x92\x96\x96"
        b"\x8c\x8c\x01", True)

    device.write_sensor_register(0x022c, b"\x05\x03")

    tls_client.sendall(
        device.mcu_get_image(
            b"\x45\x03\xa7\x00\xa1\x00\xa7\x00\xa3\x00",
            goodix.FLAGS_TRANSPORT_LAYER_SECURITY_DATA)[9:])

    raw = tls_server.stdout.read(IMAGE_FRAME_BYTES)[:-4]
    return tool.decode_image(raw)


def single_shot_capture(product: int, psk_file: str):
    """Read-only-PSK real capture: bring up the chip, wait for a finger, grab
    exactly one frame, and feed it to the live preview."""
    device = init_device(product)
    try:
        device.nop()
        psk = _verify_and_get_psk(device, psk_file)

        tls_server = TLSServer(psk=psk.hex()).start()
        try:
            tls_client = socket.socket()
            tls_client.connect((tls_server.bind, tls_server.port))
            try:
                tool.connect_device(device, tls_client)
                _bring_up(device, tls_client, tls_server)
                frame = _arm_and_capture_one(device, tls_client, tls_server)
            finally:
                tls_client.close()
        finally:
            tls_server.stop()
    finally:
        device.disconnect()

    tool.write_pgm(frame, SENSOR_WIDTH, SENSOR_HEIGHT, "capture.pgm")
    preview.preview_stream([frame], SENSOR_WIDTH, SENSOR_HEIGHT, max_frames=1)


def live_capture(product: int, max_frames: int | None = None, psk_file: str = ""):
    """Same as single_shot_capture, but keeps re-arming and capturing frames
    into the live preview: place your finger again each time it prints
    "Waiting for finger...". Stops when the preview window is closed, or
    after max_frames if given. Saves the last captured frame to capture.pgm
    when max_frames bounds the run (skipped for an open-ended live session).
    """
    device = init_device(product)
    last_frame: list = []
    try:
        device.nop()
        psk = _verify_and_get_psk(device, psk_file)

        tls_server = TLSServer(psk=psk.hex()).start()
        try:
            tls_client = socket.socket()
            tls_client.connect((tls_server.bind, tls_server.port))
            try:
                tool.connect_device(device, tls_client)
                _bring_up(device, tls_client, tls_server)

                def frames():
                    count = 0
                    while max_frames is None or count < max_frames:
                        frame = _arm_and_capture_one(device, tls_client, tls_server)
                        last_frame[:] = [frame]
                        yield frame
                        count += 1

                preview.preview_stream(
                    frames(), SENSOR_WIDTH, SENSOR_HEIGHT, max_frames=max_frames)
            finally:
                tls_client.close()
        finally:
            tls_server.stop()
    finally:
        device.disconnect()

    if max_frames is not None and last_frame:
        tool.write_pgm(last_frame[0], SENSOR_WIDTH, SENSOR_HEIGHT, "capture.pgm")


def cli(product: int):
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--live",
        action="store_true",
        help="repeatedly wait for a finger and show captured frames live "
             "(read-only PSK use, no device writes)",
    )
    parser.add_argument(
        "--psk-file",
        default=None,
        help="32-byte raw PSK file (recovered with tools/psk.py); required "
             "for --live, verified against the device hash readback",
    )
    parser.add_argument(
        "--frames",
        type=int,
        default=None,
        help="--live: stop after this many frames instead of running until "
             "the preview window is closed",
    )
    args = parser.parse_args()

    if args.live:
        assert args.psk_file
        code = random.randint(0, 9999)
        if input(f"Type {code} to continue and start the live capture: "
                 ) != str(code):
            print("Abort")
            return
        live_capture(product, max_frames=args.frames, psk_file=args.psk_file)
        return

    print(json.dumps(read_only_probe(product), indent=2, sort_keys=True))
