"""
Tests of authenticatorCredentialManagement (read-only part: metadata, enumerate RPs, enumerate
credentials), authenticated with a pinUvAuthToken carrying the cm permission. It is only offered
while resident keys are enabled in the settings.
"""
import pytest

from fido2 import cbor
from fido2.ctap import CtapError
from fido2.ctap2.credman import CredentialManagement
from fido2.ctap2.pin import ClientPin
from fido2.cose import CoseKey
from fido2.webauthn import AttestedCredentialData

from ..utils import generate_random_bytes, generate_make_credentials_params, \
    ctap2_get_assertion, get_rp_id_hash, Nav

PERM = ClientPin.PERMISSION

# Keys of the authenticatorCredentialManagement responses
KEY_EXISTING_COUNT = 1
KEY_REMAINING_COUNT = 2
KEY_RP = 3
KEY_RP_ID_HASH = 4
KEY_USER = 6
KEY_CREDENTIAL_ID = 7
KEY_PUBLIC_KEY = 8


def get_cm(client, rp_id=None, **kwargs):
    """A credential management session; the cm token is approved on the device."""
    pin = ClientPin(client.ctap2)
    token = client.ctap2.get_cm_token(pin, rp_id, **kwargs)
    return CredentialManagement(client.ctap2, pin.protocol, token)


def create_rk(client, rp_id, **kwargs):
    t = ctap2_get_assertion(client, rk=True, rp={"id": rp_id}, **kwargs)
    return t


@pytest.mark.skip_if_not_rk_config_ui
def test_cred_mgmt_info(client):
    # Not advertised while the resident keys are disabled...
    assert "credMgmt" not in client.ctap2.info.options
    # (restore is listed, as not usable)
    assert client.ctap2.info.options["ledgerMy1RkRestore"] is False

    # ... and a cm token is refused
    pin = ClientPin(client.ctap2)
    with pytest.raises(CtapError) as e:
        pin.get_uv_token(PERM.CREDENTIAL_MGMT)
    assert e.value.code == CtapError.ERR.UNAUTHORIZED_PERMISSION

    client.enable_rk_option()
    assert client.ctap2.info.options["credMgmt"]
    assert client.ctap2.info.options["ledgerMy1RkRestore"] is True


@pytest.mark.skip_if_not_rk_config_ui
def test_cred_mgmt_metadata(client):
    client.enable_rk_option()

    cm = get_cm(client)
    metadata = cm.get_metadata()
    assert metadata[KEY_EXISTING_COUNT] == 0
    capacity = metadata[KEY_REMAINING_COUNT]
    assert capacity > 0

    create_rk(client, "webctap.metadata.com")
    create_rk(client, "webctap.metadata2.com")

    metadata = get_cm(client).get_metadata()
    assert metadata[KEY_EXISTING_COUNT] == 2
    assert metadata[KEY_REMAINING_COUNT] == capacity - 2


@pytest.mark.skip_if_not_rk_config_ui
def test_cred_mgmt_no_credentials(client):
    client.enable_rk_option()

    # The device answers NO_CREDENTIALS (python-fido2's enumerate_rps / enumerate_creds turn it
    # into an empty list, so the "begin" calls are used to see the error)
    cm = get_cm(client)
    with pytest.raises(CtapError) as e:
        cm.enumerate_rps_begin()
    assert e.value.code == CtapError.ERR.NO_CREDENTIALS
    assert cm.enumerate_rps() == []

    with pytest.raises(CtapError) as e:
        cm.enumerate_creds_begin(get_rp_id_hash("webctap.unknown.com"))
    assert e.value.code == CtapError.ERR.NO_CREDENTIALS
    assert cm.enumerate_creds(get_rp_id_hash("webctap.unknown.com")) == []


@pytest.mark.skip_if_not_rk_config_ui
def test_cred_mgmt_enumerate(client):
    client.enable_rk_option()

    rp1 = "webctap.cm-one.com"
    rp2 = "webctap.cm-two.com"
    t1 = create_rk(client, rp1)
    t2 = create_rk(client, rp1)
    t3 = create_rk(client, rp2)

    cm = get_cm(client)
    rps = cm.enumerate_rps()
    assert len(rps) == 2
    # The RP ID is stored with the credentials created by this app, so it is reported
    assert sorted(rp[KEY_RP]["id"] for rp in rps) == sorted([rp1, rp2])
    for rp in rps:
        assert rp[KEY_RP_ID_HASH] == get_rp_id_hash(rp[KEY_RP]["id"])

    # Credentials of the first RP
    creds = cm.enumerate_creds(get_rp_id_hash(rp1))
    assert len(creds) == 2
    expected = {
        t.args.user["id"]: AttestedCredentialData(t.attestation.auth_data.credential_data)
        for t in (t1, t2)
    }
    for cred in creds:
        user_id = cred[KEY_USER]["id"]
        assert user_id in expected
        assert cred[KEY_PUBLIC_KEY] == expected[user_id].public_key

        # The credential id is usable as is in a getAssertion
        client_data_hash = generate_random_bytes(32)
        assertion = client.ctap2.get_assertion(rp1, client_data_hash,
                                               [cred[KEY_CREDENTIAL_ID]])
        assertion.verify(client_data_hash, CoseKey.parse(cred[KEY_PUBLIC_KEY]))

    # Credentials of the second RP
    creds = cm.enumerate_creds(get_rp_id_hash(rp2))
    assert len(creds) == 1
    assert creds[0][KEY_USER]["id"] == t3.args.user["id"]


@pytest.mark.skip_if_not_rk_config_ui
def test_cred_mgmt_user_name(client):
    client.enable_rk_option()

    t = ctap2_get_assertion(client, rk=True, ref=1)
    rp_id = t.args.rp["id"]

    creds = get_cm(client).enumerate_creds(get_rp_id_hash(rp_id))
    assert len(creds) == 1
    assert creds[0][KEY_USER]["id"] == t.args.user["id"]
    assert creds[0][KEY_USER]["name"] == t.args.user["name"]


@pytest.mark.skip_if_not_rk_config_ui
def test_cred_mgmt_token_checks(client):
    client.enable_rk_option()
    rp_id = "webctap.cm-auth.com"
    create_rk(client, rp_id)

    pin = ClientPin(client.ctap2)

    # A token without the cm permission is not valid for credential management
    token = pin.get_uv_token(PERM.GET_ASSERTION, rp_id)
    cm = CredentialManagement(client.ctap2, pin.protocol, token)
    with pytest.raises(CtapError) as e:
        cm.get_metadata()
    assert e.value.code == CtapError.ERR.PIN_AUTH_INVALID

    # No pinUvAuthParam at all
    with pytest.raises(CtapError) as e:
        client.ctap2.credential_mgmt(CredentialManagement.CMD.GET_CREDS_METADATA)
    assert e.value.code == CtapError.ERR.PUAT_REQUIRED

    # Wrong pinUvAuthParam
    token = client.ctap2.get_cm_token(pin)
    with pytest.raises(CtapError) as e:
        client.ctap2.credential_mgmt(CredentialManagement.CMD.GET_CREDS_METADATA,
                                     pin_uv_protocol=pin.protocol.VERSION,
                                     pin_uv_param=generate_random_bytes(
                                         pin.protocol.VERSION * 16))
    assert e.value.code == CtapError.ERR.PIN_AUTH_INVALID

    # A token bound to an RP can only enumerate the credentials of this RP
    cm = get_cm(client, rp_id)
    assert len(cm.enumerate_creds(get_rp_id_hash(rp_id))) == 1
    with pytest.raises(CtapError) as e:
        cm.enumerate_creds(get_rp_id_hash("webctap.cm-other.com"))
    assert e.value.code == CtapError.ERR.PIN_AUTH_INVALID


@pytest.mark.skip_if_not_rk_config_ui
def test_cred_mgmt_unsupported_subcommands(client):
    client.enable_rk_option()
    create_rk(client, "webctap.cm-subcmd.com")

    # Updating the user information is not supported yet
    pin = ClientPin(client.ctap2)
    token = client.ctap2.get_cm_token(pin)
    cm = CredentialManagement(client.ctap2, pin.protocol, token)
    with pytest.raises(CtapError) as e:
        cm.update_user_info({"id": generate_random_bytes(40), "type": "public-key"},
                                   {"id": generate_random_bytes(8), "name": "new name"})
    assert e.value.code == CtapError.ERR.INVALID_SUBCOMMAND


def delete(client, cred_id, rp_id=None, **kwargs):
    """Sends a deleteCredential, authenticated by a new token (bound to the RP if rp_id)."""
    pin = ClientPin(client.ctap2)
    token = client.ctap2.get_cm_token(pin, rp_id)
    params = {CredentialManagement.PARAM.CREDENTIAL_ID: cred_id}
    message = bytes([CredentialManagement.CMD.DELETE_CREDENTIAL]) + cbor.encode(params)
    client.ctap2.delete_credential(cred_id, pin.protocol.VERSION,
                                   pin.protocol.authenticate(token, message), **kwargs)


def stored_creds(client, rp_id):
    try:
        return get_cm(client).enumerate_creds(get_rp_id_hash(rp_id))
    except CtapError as e:
        assert e.code == CtapError.ERR.NO_CREDENTIALS
        return []


@pytest.mark.skip_if_not_rk_config_ui
@pytest.mark.skip_endpoint("NFC", reason="deleteCredential is denied over NFC")
def test_cred_mgmt_delete(client):
    client.enable_rk_option()

    rp1 = "webctap.cm-del-one.com"
    rp2 = "webctap.cm-del-two.com"
    create_rk(client, rp1)
    create_rk(client, rp1)
    create_rk(client, rp2)
    assert get_cm(client).get_metadata()[KEY_EXISTING_COUNT] == 3

    creds = stored_creds(client, rp1)
    assert len(creds) == 2
    deleted, kept = creds[0], creds[1]

    delete(client, deleted[KEY_CREDENTIAL_ID])

    # The credential is gone, the others are untouched
    assert get_cm(client).get_metadata()[KEY_EXISTING_COUNT] == 2
    remaining = stored_creds(client, rp1)
    assert [c[KEY_USER]["id"] for c in remaining] == [kept[KEY_USER]["id"]]
    with pytest.raises(CtapError) as e:
        client.ctap2.get_assertion(rp1, generate_random_bytes(32), [deleted[KEY_CREDENTIAL_ID]],
                                   will_fail=True)
    assert e.value.code == CtapError.ERR.NO_CREDENTIALS
    client_data_hash = generate_random_bytes(32)
    assertion = client.ctap2.get_assertion(rp1, client_data_hash, [kept[KEY_CREDENTIAL_ID]])
    assertion.verify(client_data_hash, CoseKey.parse(kept[KEY_PUBLIC_KEY]))

    # Deleting the last credential of an RP makes the RP disappear
    delete(client, remaining[0][KEY_CREDENTIAL_ID])
    assert stored_creds(client, rp1) == []
    rps = get_cm(client).enumerate_rps()
    assert [rp[KEY_RP]["id"] for rp in rps] == [rp2]


@pytest.mark.skip_if_not_rk_config_ui
@pytest.mark.skip_endpoint("NFC", reason="deleteCredential is denied over NFC")
def test_cred_mgmt_delete_refused(client):
    client.enable_rk_option()

    rp_id = "webctap.cm-refuse.com"
    create_rk(client, rp_id)
    cred = stored_creds(client, rp_id)[0]

    with pytest.raises(CtapError) as e:
        delete(client, cred[KEY_CREDENTIAL_ID], navigation=Nav.USER_REFUSE)
    assert e.value.code == CtapError.ERR.OPERATION_DENIED
    assert len(stored_creds(client, rp_id)) == 1


@pytest.mark.skip_if_not_rk_config_ui
@pytest.mark.skip_endpoint("NFC", reason="deleteCredential is denied over NFC")
def test_cred_mgmt_delete_errors(client):
    client.enable_rk_option()

    rp_id = "webctap.cm-delerr.com"
    create_rk(client, rp_id)
    cred = stored_creds(client, rp_id)[0]

    # A credential id that is not one of a resident credential
    with pytest.raises(CtapError) as e:
        delete(client, {"id": generate_random_bytes(48), "type": "public-key"}, will_fail=True)
    assert e.value.code == CtapError.ERR.NO_CREDENTIALS
    with pytest.raises(CtapError) as e:
        delete(client, {"id": generate_random_bytes(300), "type": "public-key"}, will_fail=True)
    assert e.value.code == CtapError.ERR.NO_CREDENTIALS

    # A token bound to another RP can't delete it
    with pytest.raises(CtapError) as e:
        delete(client, cred[KEY_CREDENTIAL_ID], rp_id="webctap.cm-other.com", will_fail=True)
    assert e.value.code == CtapError.ERR.PIN_AUTH_INVALID

    # Wrong pinUvAuthParam
    pin = ClientPin(client.ctap2)
    client.ctap2.get_cm_token(pin)
    with pytest.raises(CtapError) as e:
        client.ctap2.delete_credential(cred[KEY_CREDENTIAL_ID], pin.protocol.VERSION,
                                       generate_random_bytes(pin.protocol.VERSION * 16),
                                       will_fail=True)
    assert e.value.code == CtapError.ERR.PIN_AUTH_INVALID

    # Missing pinUvAuthParam
    with pytest.raises(CtapError) as e:
        client.ctap2.delete_credential(cred[KEY_CREDENTIAL_ID], None, None, will_fail=True)
    assert e.value.code == CtapError.ERR.PUAT_REQUIRED

    # None of it deleted anything
    assert len(stored_creds(client, rp_id)) == 1


@pytest.mark.skip_if_not_rk_config_ui
def test_cred_mgmt_delete_denied_over_nfc(client):
    if not client.ctap2.nfc:
        pytest.skip("NFC only")
    client.enable_rk_option()

    rp_id = "webctap.cm-nfc.com"
    create_rk(client, rp_id)
    cred = stored_creds(client, rp_id)[0]

    # The user can't confirm the deletion over NFC
    with pytest.raises(CtapError) as e:
        delete(client, cred[KEY_CREDENTIAL_ID])
    assert e.value.code == CtapError.ERR.OPERATION_DENIED
    assert len(stored_creds(client, rp_id)) == 1


@pytest.mark.skip_if_not_rk_config_ui
@pytest.mark.skip_endpoint("NFC", reason="the cm token can't be approved over NFC")
def test_cred_mgmt_token_refused(client):
    client.enable_rk_option()
    create_rk(client, "webctap.cm-refuse.com")

    # The user refuses: no token, nothing can be listed
    pin = ClientPin(client.ctap2)
    with pytest.raises(CtapError) as e:
        client.ctap2.get_cm_token(pin, navigation=Nav.USER_REFUSE)
    assert e.value.code == CtapError.ERR.OPERATION_DENIED

    # A previous token doesn't survive a refused one
    with pytest.raises(CtapError) as e:
        client.ctap2.credential_mgmt(CredentialManagement.CMD.GET_CREDS_METADATA)
    assert e.value.code == CtapError.ERR.PUAT_REQUIRED

    # The host gives up while the screen is shown
    with pytest.raises(CtapError) as e:
        client.ctap2.get_cm_token(pin, navigation=Nav.CLIENT_CANCEL)
    assert e.value.code == CtapError.ERR.KEEPALIVE_CANCEL

    # Asking again works
    assert get_cm(client).get_metadata()



# Vendor subcommand to restore a resident credential from what a standard enumeration reported
# Vendor command: resident credential backup ID and restore, shaped like credential management
CMD_VENDOR_RK = 0x50
SUBCMD_RESTORE = 0x01


def vendor_rk(client, sub_command, params=None, pin_uv_protocol=None, pin_uv_param=None):
    """Sends the vendor command, map keys as authenticatorCredentialManagement."""
    request = {1: sub_command}
    if params is not None:
        request[2] = params
    if pin_uv_protocol is not None:
        request[3] = pin_uv_protocol
    if pin_uv_param is not None:
        request[4] = pin_uv_param
    return client.ctap2.send_cbor(CMD_VENDOR_RK, request)
VENDOR_CRED_ID = 0x42
VENDOR_USER_ID = 0x44
VENDOR_USER_NAME = 0x45
VENDOR_RP_ID = 0x46
VENDOR_ALG = 0x47
VENDOR_CHECK = 0x48
RESP_RESULT = 0x45
RESULT_STORED, RESULT_ALREADY_THERE, RESULT_USER_EXISTS, RESULT_WOULD_STORE = 0, 1, 2, 3


def restore(client, pin, token, rp_id, cred, changes=None):
    """Restores a credential as reported by enumerateCredentials for rp_id."""
    params = {
        1: get_rp_id_hash(rp_id),
        VENDOR_CRED_ID: cred[KEY_CREDENTIAL_ID]["id"],
        VENDOR_USER_ID: cred[KEY_USER]["id"],
        VENDOR_RP_ID: rp_id,
        VENDOR_ALG: cred[KEY_PUBLIC_KEY][3],
    }
    if "name" in cred[KEY_USER]:
        params[VENDOR_USER_NAME] = cred[KEY_USER]["name"]
    for key, value in (changes or {}).items():
        # None removes a parameter
        if value is None:
            params.pop(key, None)
        else:
            params[key] = value
    message = bytes([SUBCMD_RESTORE]) + cbor.encode(params)
    return vendor_rk(client, SUBCMD_RESTORE, params, pin.protocol.VERSION,
                     pin.protocol.authenticate(token, message))


@pytest.mark.skip_if_not_rk_config_ui
@pytest.mark.skip_endpoint("NFC", reason="the cm token can't be approved over NFC")
def test_cred_mgmt_restore(client):
    client.enable_rk_option()

    rp_id = "webctap.cm-restore.com"
    create_rk(client, rp_id, ref=1)
    create_rk(client, rp_id, ref=2)
    backup = stored_creds(client, rp_id)
    assert len(backup) == 2

    # Wipe the RP, then restore it from the enumeration
    for cred in backup:
        delete(client, cred[KEY_CREDENTIAL_ID])
    assert stored_creds(client, rp_id) == []

    pin = ClientPin(client.ctap2)
    token = client.ctap2.get_cm_token(pin)
    # Check only: the device recognizes them as its own and missing, and stores nothing
    for cred in backup:
        result = restore(client, pin, token, rp_id, cred, {VENDOR_CHECK: 1})
        assert result[RESP_RESULT] == RESULT_WOULD_STORE
    assert stored_creds(client, rp_id) == []

    token = client.ctap2.get_cm_token(pin)
    for cred in backup:
        assert restore(client, pin, token, rp_id, cred)[RESP_RESULT] == RESULT_STORED

    restored = stored_creds(client, rp_id)
    assert {c[KEY_CREDENTIAL_ID]["id"] for c in restored} == \
        {c[KEY_CREDENTIAL_ID]["id"] for c in backup}
    assert {c[KEY_USER]["id"] for c in restored} == {c[KEY_USER]["id"] for c in backup}
    assert {c[KEY_USER].get("name") for c in restored} == {c[KEY_USER].get("name") for c in backup}
    assert get_cm(client).enumerate_rps()[0][KEY_RP]["id"] == rp_id

    # Restored credentials work
    for cred in restored:
        client_data_hash = generate_random_bytes(32)
        assertion = client.ctap2.get_assertion(rp_id, client_data_hash, [cred[KEY_CREDENTIAL_ID]])
        assertion.verify(client_data_hash, CoseKey.parse(cred[KEY_PUBLIC_KEY]))

    # Restoring again changes nothing (listing took a new token), checking says so too
    token = client.ctap2.get_cm_token(pin)
    for cred in backup:
        assert restore(client, pin, token, rp_id, cred)[RESP_RESULT] == RESULT_ALREADY_THERE
        result = restore(client, pin, token, rp_id, cred, {VENDOR_CHECK: 1})
        assert result[RESP_RESULT] == RESULT_ALREADY_THERE
    assert len(stored_creds(client, rp_id)) == 2


@pytest.mark.skip_if_not_rk_config_ui
@pytest.mark.skip_endpoint("NFC", reason="the cm token can't be approved over NFC")
def test_cred_mgmt_restore_errors(client):
    client.enable_rk_option()

    rp_id = "webctap.cm-restore-err.com"
    create_rk(client, rp_id, ref=3)
    cred = stored_creds(client, rp_id)[0]
    delete(client, cred[KEY_CREDENTIAL_ID])

    pin = ClientPin(client.ctap2)
    token = client.ctap2.get_cm_token(pin)
    cred_id = cred[KEY_CREDENTIAL_ID]["id"]

    # A credential id the device didn't create / for another RP / damaged
    damaged = bytearray(cred_id)
    damaged[-1] ^= 1
    for changes in [{VENDOR_CRED_ID: generate_random_bytes(len(cred_id))},
                    {VENDOR_CRED_ID: bytes(damaged)},
                    {VENDOR_CRED_ID: bytes(damaged), VENDOR_CHECK: 1},
                    {1: get_rp_id_hash("webctap.cm-restore-other.com"), VENDOR_RP_ID: None}]:
        with pytest.raises(CtapError) as e:
            restore(client, pin, token, rp_id, cred, changes)
        assert e.value.code == CtapError.ERR.INVALID_CREDENTIAL

    # An RP ID that is not the one of the RP ID hash
    with pytest.raises(CtapError) as e:
        restore(client, pin, token, rp_id, cred, {VENDOR_RP_ID: "webctap.cm-restore-other.com"})
    assert e.value.code == CtapError.ERR.INVALID_PARAMETER

    # Missing parameters
    for key in [1, VENDOR_CRED_ID, VENDOR_USER_ID, VENDOR_ALG]:
        params = {1: get_rp_id_hash(rp_id), VENDOR_CRED_ID: cred_id,
                  VENDOR_USER_ID: cred[KEY_USER]["id"], VENDOR_ALG: -7}
        del params[key]
        message = bytes([SUBCMD_RESTORE]) + cbor.encode(params)
        with pytest.raises(CtapError) as e:
            vendor_rk(client, SUBCMD_RESTORE, params, pin.protocol.VERSION,
                      pin.protocol.authenticate(token, message))
        assert e.value.code == CtapError.ERR.MISSING_PARAMETER

    # Nothing was stored; without RP ID and name the credential is still restored
    assert stored_creds(client, rp_id) == []
    token = client.ctap2.get_cm_token(pin)
    result = restore(client, pin, token, rp_id, cred, {VENDOR_RP_ID: None})
    assert result[RESP_RESULT] == RESULT_STORED
    assert len(stored_creds(client, rp_id)) == 1

    # Same user already there (a newer credential of that user): not replaced
    delete(client, stored_creds(client, rp_id)[0][KEY_CREDENTIAL_ID])
    create_rk(client, rp_id, ref=3)
    token = client.ctap2.get_cm_token(pin)
    assert restore(client, pin, token, rp_id, cred)[RESP_RESULT] == RESULT_USER_EXISTS
    assert len(stored_creds(client, rp_id)) == 1

    # A token bound to an RP only restores for this RP
    bound = client.ctap2.get_cm_token(pin, "webctap.cm-restore-other.com")
    with pytest.raises(CtapError) as e:
        restore(client, pin, bound, rp_id, cred)
    assert e.value.code == CtapError.ERR.PIN_AUTH_INVALID

    # No authentication
    with pytest.raises(CtapError) as e:
        vendor_rk(client, SUBCMD_RESTORE, {1: get_rp_id_hash(rp_id),
                                           VENDOR_CRED_ID: cred_id,
                                           VENDOR_USER_ID: cred[KEY_USER]["id"],
                                           VENDOR_ALG: -7})
    assert e.value.code == CtapError.ERR.PUAT_REQUIRED


SUBCMD_BACKUP_ID = 0x02
RESP_BACKUP_ID = 0x46


@pytest.mark.skip_if_not_rk_config_ui
@pytest.mark.skip_endpoint("NFC", reason="the cm token can't be approved over NFC")
def test_cred_mgmt_backup_id(client):
    client.enable_rk_option()

    pin = ClientPin(client.ctap2)
    token = client.ctap2.get_cm_token(pin)
    message = bytes([SUBCMD_BACKUP_ID])
    ids = [vendor_rk(client, SUBCMD_BACKUP_ID, None, pin.protocol.VERSION,
                     pin.protocol.authenticate(token, message))[RESP_BACKUP_ID]
           for _ in range(2)]

    # 8 lowercase hex digits, the same every time (it only depends on the seed)
    assert ids[0] == ids[1]
    assert len(ids[0]) == 8 and all(c in "0123456789abcdef" for c in ids[0])

    # Only with a cm token
    with pytest.raises(CtapError) as e:
        vendor_rk(client, SUBCMD_BACKUP_ID)
    assert e.value.code == CtapError.ERR.PUAT_REQUIRED


@pytest.mark.skip_if_not_rk_config_ui
@pytest.mark.skip_endpoint("NFC", reason="the cm token can't be approved over NFC")
def test_cred_mgmt_vendor_command_separation(client):
    """The vendor subcommands only exist in the vendor command, the standard command only has the
    standard subcommands."""
    client.enable_rk_option()

    pin = ClientPin(client.ctap2)
    token = client.ctap2.get_cm_token(pin)

    # The former place of restore / backup ID in authenticatorCredentialManagement
    for sub_command in (0x41, 0x42):
        message = bytes([sub_command])
        with pytest.raises(CtapError) as e:
            client.ctap2.credential_mgmt(sub_command, None, pin.protocol.VERSION,
                                         pin.protocol.authenticate(token, message))
        assert e.value.code == CtapError.ERR.INVALID_SUBCOMMAND

    # A standard subcommand number that is not a vendor one
    message = bytes([0x03])
    with pytest.raises(CtapError) as e:
        vendor_rk(client, 0x03, None, pin.protocol.VERSION,
                  pin.protocol.authenticate(token, message))
    assert e.value.code == CtapError.ERR.INVALID_SUBCOMMAND

    # The standard command still works with the same token
    assert get_metadata_with(client, pin, token)


def get_metadata_with(client, pin, token):
    return CredentialManagement(client.ctap2, pin.protocol, token).get_metadata()
