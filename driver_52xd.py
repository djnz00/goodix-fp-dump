import hashlib
import hmac
import argparse
import json
import random
import re
import socket
import struct
import subprocess
import time

import goodix
import protocol
import tool
from goodix_fp_dump.firmware import (
    OTPReadResult,
    build_flash_plan,
    classify_otp,
    classify_otp_error,
)
from goodix_fp_dump.safety import SafetyPlan
from goodix_fp_dump.tls_proxy import TLSServer

TARGET_FIRMWARE = "GFUSB_GM168SEC_APP_10019"
IAP_FIRMWARE = "MILAN_GM168SEC_IAP_10007"
VALID_FIRMWARE = "GFUSB_GM168SEC_APP_100[0-9]{2}"

PSK = bytes.fromhex(
    "0000000000000000000000000000000000000000000000000000000000000000")

PSK_WHITE_BOX = bytes.fromhex(
    "ec35ae3abb45ed3f12c4751f1e5c2cc05b3c5452e9104d9f2a3118644f37a04b"
    "6fd66b1d97cf80f1345f76c84f03ff30bb51bf308f2a9875c41e6592cd2a2f9e"
    "60809b17b5316037b69bb2fa5d4c8ac31edb3394046ec06bbdacc57da6a756c5")

PMK_HASH = bytes.fromhex(
    "66687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925")

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

ACTIVE_SAFETY_PLAN: SafetyPlan | None = None


def set_safety_plan(plan: SafetyPlan | None):
    global ACTIVE_SAFETY_PLAN
    ACTIVE_SAFETY_PLAN = plan


def require_destructive_operation(operation: str):
    if ACTIVE_SAFETY_PLAN is None:
        raise RuntimeError(f"{operation} requires a safety plan")
    SafetyPlan(
        target=ACTIVE_SAFETY_PLAN.target,
        allow_write=ACTIVE_SAFETY_PLAN.allow_write,
        confirmation=ACTIVE_SAFETY_PLAN.confirmation,
        stock_dump_sha256=ACTIVE_SAFETY_PLAN.stock_dump_sha256,
        firmware_family=ACTIVE_SAFETY_PLAN.firmware_family,
        psk_evidence=ACTIVE_SAFETY_PLAN.psk_evidence,
        operations=(operation,),
    ).validate()


def init_device(product: int):
    device = goodix.Device(product, protocol.USBProtocol)

    device.nop()

    return device


def check_psk(device: goodix.Device):
    reply = device.preset_psk_read(0xbb020001, len(PMK_HASH), 0)
    if not reply[0]:
        raise ValueError("Failed to read PSK")

    if reply[1] != 0xbb020001:
        raise ValueError("Invalid flags")

    return reply[2] == PMK_HASH


def write_psk(device: goodix.Device):
    require_destructive_operation("write_psk")

    if not device.preset_psk_write(0xbb010003, PSK_WHITE_BOX, 114, 0,
                                   bytes.fromhex("56a5bb956b7c8d9e0000")):
        return False

    if not check_psk(device):
        return False

    return True


def erase_firmware(device: goodix.Device):
    require_destructive_operation("erase_firmware")
    device.mcu_erase_app(50, True)


def update_firmware(device: goodix.Device):
    require_destructive_operation("update_firmware")

    firmware_file = open(f"firmware/52xd/{TARGET_FIRMWARE}.bin", "rb")
    firmware = firmware_file.read()
    firmware_file.close()

    mod = b""
    for i in range(1, 65):
        mod += struct.pack("<B", i)
    raw_pmk = (struct.pack(">H", len(PSK)) + PSK) * 2
    pmk = hashlib.sha256(raw_pmk).digest()
    pmk_hmac = hmac.new(pmk, mod, hashlib.sha256).digest()
    firmware_hmac = hmac.new(pmk_hmac, firmware, hashlib.sha256).digest()

    try:
        length = len(firmware)
        for i in range(0, length, 256):
            if not device.write_firmware(i, firmware[i:i + 256], 2):
                raise ValueError("Failed to write firmware")

        if not device.check_firmware(None, None, None, firmware_hmac):
            raise ValueError("Failed to check firmware")

    except Exception as error:
        print(
            tool.warning(
                f"The program went into serious problems while trying to "
                f"update the firmware: {error}"))

        erase_firmware(device)

        raise error

    device.reset(False, True, 50)
    device.disconnect()


def read_otp_diagnostics(device: goodix.Device, retries: int = 1, delay: float = 0.1):
    errors = []
    for attempt in range(retries + 1):
        try:
            result = classify_otp(device.read_otp())
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
    device = init_device(product)
    try:
        firmware = None
        valid_psk = None
        try:
            firmware = device.firmware_version()
        except Exception as error:
            firmware = {"error": str(error)}

        try:
            valid_psk = check_psk(device)
        except Exception as error:
            valid_psk = {"error": str(error)}

        return {
            "product": f"{product:04x}",
            "path": "run_521d.py -> driver_52xd.py -> protocol.USBProtocol",
            "firmware": firmware,
            "valid_psk": valid_psk,
            "otp": read_otp_diagnostics(device, retries=1).as_dict(),
        }
    finally:
        try:
            device.disconnect()
        except Exception:
            pass


def run_driver(device: goodix.Device):
    tls_server = TLSServer(PSK.hex()).start()

    try:
        if not device.reset(True, False, 20)[0]:
            raise ValueError("Reset failed")

        device.read_sensor_register(0x0000,
                                    4)  # Read chip ID (0x00a5 or 0x00a6)

        otp = device.read_otp()

        if len(otp) < 64:
            raise ValueError("Invalid OTP")

        # OTP 1: 4e4c4d31372e0000b9828da2a2d73e09
        #        08196896800000ee6014a774a060b614
        #        ea2704009b0056f007212723a1a7a300
        #        00000000000000000000000083760000
        # OTP 2: 4e4b35594c2e00002983759520190009
        #        08274c96800000f0103cae6ea010593c
        #        ea2f04009c0053f00729312ba8b0aa00
        #        000000000000000000000000f3830000

        tls_client = socket.socket()
        tls_client.connect(("localhost", 4433))

        try:
            tool.connect_device(device, tls_client)

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

            device.write_sensor_register(0x022c, b"\x0a\x03")

            tls_client.sendall(
                device.mcu_get_image(
                    b"\x01\x03\x27\x01\x21\x01\x27\x01\x23\x01",
                    goodix.FLAGS_TRANSPORT_LAYER_SECURITY_DATA)[9:])

            tool.write_pgm(
                tool.decode_image(tls_server.stdout.read(7684)[:-4]),
                SENSOR_WIDTH, SENSOR_HEIGHT, "clear-0.pgm")

            device.write_sensor_register(0x022c, b"\x0a\x02")

            device.write_sensor_register(0x022c, b"\x0a\x03")

            tls_client.sendall(
                device.mcu_get_image(
                    b"\x81\x03\x27\x01\x21\x01\x27\x01\x23\x01",
                    goodix.FLAGS_TRANSPORT_LAYER_SECURITY_DATA)[9:])

            tool.write_pgm(
                tool.decode_image(tls_server.stdout.read(7684)[:-4]),
                SENSOR_WIDTH, SENSOR_HEIGHT, "clear-1.pgm")

            device.write_sensor_register(0x022c, b"\x0a\x02")

            device.write_sensor_register(0x022c, b"\x0a\x03")

            tls_client.sendall(
                device.mcu_get_image(
                    b"\x81\x03\x18\x01\x12\x01\x18\x01\x14\x01",
                    goodix.FLAGS_TRANSPORT_LAYER_SECURITY_DATA)[9:])

            tool.write_pgm(
                tool.decode_image(tls_server.stdout.read(7684)[:-4]),
                SENSOR_WIDTH, SENSOR_HEIGHT, "clear-2.pgm")

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

            tool.write_pgm(
                tool.decode_image(tls_server.stdout.read(7684)[:-4]),
                SENSOR_WIDTH, SENSOR_HEIGHT, "clear-3.pgm")

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

            tool.write_pgm(
                tool.decode_image(tls_server.stdout.read(7684)[:-4]),
                SENSOR_WIDTH, SENSOR_HEIGHT, "fingerprint.pgm")

        finally:
            tls_client.close()
    finally:
        tls_server.stop()


def main(product: int):
    print(
        tool.warning(
            "This program might break your device.\n"
            "Consider that it may flash the device firmware.\n"
            "Continue at your own risk.\n"
            "But don't hold us responsible if your device is broken!\n"
            "Don't run this program as part of a regular process."))

    code = random.randint(0, 9999)

    if input(f"Type {code} to continue and confirm that you are not a bot: "
             ) != str(code):
        print("Abort")
        return

    previous_firmware = None

    device = init_device(product)

    while True:
        firmware = device.firmware_version()
        print(f"Firmware: {firmware}")

        valid_psk = check_psk(device)
        print(f"Valid PSK: {valid_psk}")

        if firmware == previous_firmware:
            raise ValueError("Unchanged firmware")

        previous_firmware = firmware

        if re.fullmatch(TARGET_FIRMWARE, firmware):
            if not valid_psk:
                erase_firmware(device)
                continue

            run_driver(device)
            return

        if re.fullmatch(VALID_FIRMWARE, firmware):
            erase_firmware(device)
            continue

        if re.fullmatch(IAP_FIRMWARE, firmware):
            if not valid_psk:
                if not write_psk(device):
                    raise ValueError("Failed to write PSK")

            update_firmware(device)

            device = init_device(product)

            continue

        raise ValueError(
            "Invalid firmware\n" +
            tool.warning("Please consider that removing this security "
                         "is a very bad idea!"))


def cli(product: int):
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--allow-write",
        action="store_true",
        help="run the legacy destructive firmware path after confirmation",
    )
    parser.add_argument("--confirm")
    parser.add_argument("--stock-dump-sha256")
    parser.add_argument("--firmware-family", default="52xd")
    parser.add_argument("--psk-evidence", action="store_true")
    parser.add_argument(
        "--read-only",
        action="store_true",
        default=True,
        help="run safe firmware/OTP diagnostics only",
    )
    args = parser.parse_args()

    if args.allow_write:
        build_flash_plan(
            product=product,
            firmware_family=args.firmware_family,
            target=f"27c6:{product:04x}",
            stock_dump_sha256=args.stock_dump_sha256 or "",
            confirmation=args.confirm or "",
            psk_evidence=args.psk_evidence,
            operations=("erase_firmware", "write_psk", "update_firmware"),
        )
        set_safety_plan(
            SafetyPlan(
                target=f"27c6:{product:04x}",
                allow_write=True,
                confirmation=args.confirm,
                stock_dump_sha256=args.stock_dump_sha256,
                firmware_family=args.firmware_family,
                psk_evidence=args.psk_evidence,
                operations=("erase_firmware", "write_psk", "update_firmware"),
            )
        )
        main(product)
        return

    print(json.dumps(read_only_probe(product), indent=2, sort_keys=True))
