from fido2.ctap2.base import Ctap2, Info

from ..utils import ENABLE_RK_CONFIG


def test_get_info(client):
    ctap2_info = client.ctap2.get_info()

    assert ctap2_info == client.ctap2.info
    raw_info = Info.from_dict(client.ctap2.send_cbor(Ctap2.CMD.GET_INFO))
    assert raw_info == client.ctap2.info


def test_get_info_version(client):
    info = client.ctap2.info

    assert "U2F_V2" in info.versions
    assert "FIDO_2_0" in info.versions
    # "FIDO_2_1" is advertised when the app is built with it (Android needs it)
    assert set(info.versions) <= {"U2F_V2", "FIDO_2_0", "FIDO_2_1"}


def test_get_info_extensions(client):
    info = client.ctap2.info

    assert "hmac-secret" in info.extensions
    assert len(info.extensions) == 1


def test_get_info_aaguid(client):
    # This app is not Ledger's: it has its own AAGUID, the same on every device
    info = client.ctap2.info
    assert info.aaguid.hex() == "c45922b4256a4ce680a537bce7ab79f5"


def test_get_info_options(client):
    info = client.ctap2.info

    # Specified options with fix value
    if ENABLE_RK_CONFIG:
        assert not info.options["rk"]
    else:
        assert info.options["rk"]

    assert info.options["up"]

    # There is no FIDO client PIN: the device unlock PIN is the built-in user verification.
    # "clientPin" is only advertised when turned on in the settings (needed by Android), it is off
    # by default
    assert info.options["uv"]
    assert info.options["pinUvAuthToken"]

    # Default value options
    assert not info.options["plat"]

    assert "clientPin" not in info.options

    # Vendor option: resident credential restore, always listed, usable while resident keys are
    assert info.options["ledgerMy1RkRestore"] == info.options["rk"]

    # clientPin (needed by Android) and credMgmt (while resident keys are enabled) are optional
    assert set(info.options) - {"clientPin", "credMgmt"} == {"rk", "up", "uv", "plat",
                                                             "pinUvAuthToken",
                                                             "ledgerMy1RkRestore"}


def test_get_info_max_msg_size(client):
    info = client.ctap2.info
    assert info.max_msg_size == 1024


def test_get_info_pin_protocol(client):
    info = client.ctap2.info
    # In order of preference
    assert info.pin_uv_protocols == [2, 1]
