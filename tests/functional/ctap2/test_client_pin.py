"""
Tests of authenticatorClientPIN.

There is no FIDO client PIN on this authenticator: the device unlock PIN is the built-in user
verification. What is supported is the PIN/UV auth protocols 1 and 2, getKeyAgreement,
getUVRetries and getPinUvAuthTokenUsingUvWithPermissions (pinUvAuthToken, "PUAT"), with the
makeCredential and getAssertion permissions.
"""
import pytest

from fido2.ctap import CtapError
from fido2.ctap2.extensions import HmacSecretExtension
from fido2.ctap2.pin import ClientPin, PinProtocolV1, PinProtocolV2
from fido2.webauthn import AttestedCredentialData, AuthenticatorData

from ..utils import generate_random_bytes, generate_make_credentials_params, \
    ctap2_get_assertion, Nav

PERM = ClientPin.PERMISSION
PROTOCOLS = [PinProtocolV1, PinProtocolV2]


def protocol_id(protocol):
    return f"protocol{protocol.VERSION}"


def get_token(client, protocol, permissions, rp_id):
    return ClientPin(client.ctap2, protocol()).get_uv_token(permissions, rp_id)


def uv_flag(auth_data):
    return bool(auth_data.flags & AuthenticatorData.FLAG.UV)


def raw_get_uv_token(client, protocol, **kwargs):
    """Sends a getPinUvAuthTokenUsingUvWithPermissions with full control on the parameters."""
    pin = ClientPin(client.ctap2, protocol())
    key_agreement, _ = pin._get_shared_secret()
    return client.ctap2.client_pin(
        protocol.VERSION,
        ClientPin.CMD.GET_PIN_UV_AUTH_TOKEN_USING_UV_WITH_PERMISSIONS,
        key_agreement=key_agreement,
        **kwargs)


def test_client_pin_default_protocol(client):
    # Highest supported protocol is preferred
    assert client.client_pin.protocol.VERSION == PinProtocolV2.VERSION


def test_client_pin_get_uv_retries(client):
    # Built-in UV has no retry counter, a constant non zero value is reported
    assert client.client_pin.get_uv_retries() > 0


@pytest.mark.parametrize("subcommand", [
    ClientPin.CMD.GET_PIN_RETRIES,
    ClientPin.CMD.SET_PIN,
    ClientPin.CMD.CHANGE_PIN,
    ClientPin.CMD.GET_PIN_TOKEN,
    ClientPin.CMD.GET_PIN_UV_AUTH_TOKEN_USING_PIN_WITH_PERMISSIONS,
])
def test_client_pin_no_pin_subcommands(client, subcommand):
    # No FIDO client PIN: all the PIN related subcommands are unsupported
    with pytest.raises(CtapError) as e:
        client.ctap2.client_pin(PinProtocolV1.VERSION, subcommand)
    assert e.value.code == CtapError.ERR.UNSUPPORTED_OPTION


def test_client_pin_bad_protocol(client):
    with pytest.raises(CtapError) as e:
        client.ctap2.client_pin(3, ClientPin.CMD.GET_KEY_AGREEMENT)
    assert e.value.code == CtapError.ERR.INVALID_PARAMETER


@pytest.mark.parametrize("protocol", PROTOCOLS, ids=protocol_id)
def test_puat_make_credential(client, protocol):
    args = generate_make_credentials_params(client)
    token = get_token(client, protocol, PERM.MAKE_CREDENTIAL, args.rp["id"])
    args.pin_uv_param = protocol().authenticate(token, args.client_data_hash)
    args.pin_uv_protocol = protocol.VERSION

    attestation = client.ctap2.make_credential(args)
    assert uv_flag(attestation.auth_data)


@pytest.mark.parametrize("protocol", PROTOCOLS, ids=protocol_id)
def test_puat_get_assertion(client, protocol):
    t = ctap2_get_assertion(client)
    # No UV was requested at creation
    assert not uv_flag(t.attestation.auth_data)

    rp_id = t.args.rp["id"]
    client_data_hash = generate_random_bytes(32)
    allow_list = [{"id": t.credential_data.credential_id, "type": "public-key"}]

    token = get_token(client, protocol, PERM.GET_ASSERTION, rp_id)
    assertion = client.ctap2.get_assertion(
        rp_id, client_data_hash, allow_list,
        pin_uv_param=protocol().authenticate(token, client_data_hash),
        pin_uv_protocol=protocol.VERSION)
    assert uv_flag(assertion.auth_data)

    # Without a pinUvAuthParam (and without the uv option), no UV is reported
    assertion = client.ctap2.get_assertion(rp_id, client_data_hash, allow_list)
    assert not uv_flag(assertion.auth_data)


def test_puat_both_permissions(client):
    protocol = PinProtocolV2
    args = generate_make_credentials_params(client)
    rp_id = args.rp["id"]

    # One token, used for one makeCredential and then for one getAssertion
    token = get_token(client, protocol, PERM.MAKE_CREDENTIAL | PERM.GET_ASSERTION, rp_id)
    args.pin_uv_param = protocol().authenticate(token, args.client_data_hash)
    args.pin_uv_protocol = protocol.VERSION
    attestation = client.ctap2.make_credential(args)
    assert uv_flag(attestation.auth_data)

    credential_data = AttestedCredentialData(attestation.auth_data.credential_data)
    allow_list = [{"id": credential_data.credential_id, "type": "public-key"}]
    client_data_hash = generate_random_bytes(32)
    assertion = client.ctap2.get_assertion(
        rp_id, client_data_hash, allow_list,
        pin_uv_param=protocol().authenticate(token, client_data_hash),
        pin_uv_protocol=protocol.VERSION)
    assert uv_flag(assertion.auth_data)


@pytest.mark.parametrize("protocol", PROTOCOLS, ids=protocol_id)
def test_puat_single_use(client, protocol):
    # makeCredential tokens are single use
    args = generate_make_credentials_params(client)
    token = get_token(client, protocol, PERM.MAKE_CREDENTIAL, args.rp["id"])
    args.pin_uv_param = protocol().authenticate(token, args.client_data_hash)
    args.pin_uv_protocol = protocol.VERSION
    client.ctap2.make_credential(args)

    # The mc permission is consumed: same token, new request
    args = generate_make_credentials_params(client, rp=args.rp)
    args.pin_uv_param = protocol().authenticate(token, args.client_data_hash)
    args.pin_uv_protocol = protocol.VERSION
    with pytest.raises(CtapError) as e:
        client.ctap2.make_credential(args, navigation=Nav.NONE, will_fail=True)
    assert e.value.code == CtapError.ERR.PIN_AUTH_INVALID


def test_puat_get_assertion_spent_by_user_presence(client):
    # Platforms probe the allowList with silent requests (up=false) and then send the real
    # getAssertion with the same token: silent requests must not spend the ga permission, the
    # request asking for user presence does.
    protocol = PinProtocolV2
    t = ctap2_get_assertion(client)
    rp_id = t.args.rp["id"]
    allow_list = [{"id": t.credential_data.credential_id, "type": "public-key"}]
    token = get_token(client, protocol, PERM.GET_ASSERTION, rp_id)

    def get_assertion(options=None, **kwargs):
        client_data_hash = generate_random_bytes(32)
        return client.ctap2.get_assertion(
            rp_id, client_data_hash, allow_list, options=options,
            pin_uv_param=protocol().authenticate(token, client_data_hash),
            pin_uv_protocol=protocol.VERSION, **kwargs)

    for _ in range(2):
        assert uv_flag(get_assertion({"up": False}).auth_data)
    assert uv_flag(get_assertion().auth_data)

    with pytest.raises(CtapError) as e:
        get_assertion(navigation=Nav.NONE, will_fail=True)
    assert e.value.code == CtapError.ERR.PIN_AUTH_INVALID


def test_puat_new_token_replaces_previous(client):
    protocol = PinProtocolV2
    args = generate_make_credentials_params(client)
    old_token = get_token(client, protocol, PERM.MAKE_CREDENTIAL, args.rp["id"])
    get_token(client, protocol, PERM.MAKE_CREDENTIAL, args.rp["id"])

    args.pin_uv_param = protocol().authenticate(old_token, args.client_data_hash)
    args.pin_uv_protocol = protocol.VERSION
    with pytest.raises(CtapError) as e:
        client.ctap2.make_credential(args, navigation=Nav.NONE, will_fail=True)
    assert e.value.code == CtapError.ERR.PIN_AUTH_INVALID


def test_puat_wrong_rp_id(client):
    protocol = PinProtocolV2
    args = generate_make_credentials_params(client)
    token = get_token(client, protocol, PERM.MAKE_CREDENTIAL, "webctap.other.com")
    args.pin_uv_param = protocol().authenticate(token, args.client_data_hash)
    args.pin_uv_protocol = protocol.VERSION
    with pytest.raises(CtapError) as e:
        client.ctap2.make_credential(args, navigation=Nav.NONE, will_fail=True)
    assert e.value.code == CtapError.ERR.PIN_AUTH_INVALID


def test_puat_wrong_permission(client):
    protocol = PinProtocolV2

    # A getAssertion token can't be used for makeCredential...
    args = generate_make_credentials_params(client)
    token = get_token(client, protocol, PERM.GET_ASSERTION, args.rp["id"])
    args.pin_uv_param = protocol().authenticate(token, args.client_data_hash)
    args.pin_uv_protocol = protocol.VERSION
    with pytest.raises(CtapError) as e:
        client.ctap2.make_credential(args, navigation=Nav.NONE, will_fail=True)
    assert e.value.code == CtapError.ERR.PIN_AUTH_INVALID

    # ... and a makeCredential token can't be used for getAssertion
    t = ctap2_get_assertion(client)
    rp_id = t.args.rp["id"]
    client_data_hash = generate_random_bytes(32)
    allow_list = [{"id": t.credential_data.credential_id, "type": "public-key"}]
    token = get_token(client, protocol, PERM.MAKE_CREDENTIAL, rp_id)
    with pytest.raises(CtapError) as e:
        client.ctap2.get_assertion(
            rp_id, client_data_hash, allow_list,
            pin_uv_param=protocol().authenticate(token, client_data_hash),
            pin_uv_protocol=protocol.VERSION,
            navigation=Nav.NONE, will_fail=True)
    assert e.value.code == CtapError.ERR.PIN_AUTH_INVALID


@pytest.mark.parametrize("protocol", PROTOCOLS, ids=protocol_id)
def test_puat_bad_pin_uv_param(client, protocol):
    args = generate_make_credentials_params(client)
    token = get_token(client, protocol, PERM.MAKE_CREDENTIAL, args.rp["id"])

    # Authenticating something else than the clientDataHash
    args.pin_uv_param = protocol().authenticate(token, generate_random_bytes(32))
    args.pin_uv_protocol = protocol.VERSION
    with pytest.raises(CtapError) as e:
        client.ctap2.make_credential(args, navigation=Nav.NONE, will_fail=True)
    assert e.value.code == CtapError.ERR.PIN_AUTH_INVALID

    # Wrong length
    args.pin_uv_param = protocol().authenticate(token, args.client_data_hash)[:-1]
    with pytest.raises(CtapError) as e:
        client.ctap2.make_credential(args, navigation=Nav.NONE, will_fail=True)
    assert e.value.code == CtapError.ERR.PIN_AUTH_INVALID


def test_puat_wrong_protocol_for_token(client):
    # Token issued with protocol 2, used with protocol 1
    args = generate_make_credentials_params(client)
    token = get_token(client, PinProtocolV2, PERM.MAKE_CREDENTIAL, args.rp["id"])
    args.pin_uv_param = PinProtocolV1().authenticate(token, args.client_data_hash)
    args.pin_uv_protocol = PinProtocolV1.VERSION
    with pytest.raises(CtapError) as e:
        client.ctap2.make_credential(args, navigation=Nav.NONE, will_fail=True)
    assert e.value.code == CtapError.ERR.PIN_AUTH_INVALID


def test_puat_no_token(client):
    # A pinUvAuthParam while no token was ever issued
    protocol = PinProtocolV2
    args = generate_make_credentials_params(
        client, pin_uv_param=generate_random_bytes(protocol.VERSION * 16))
    args.pin_uv_protocol = protocol.VERSION
    with pytest.raises(CtapError) as e:
        client.ctap2.make_credential(args, navigation=Nav.NONE, will_fail=True)
    assert e.value.code == CtapError.ERR.PIN_AUTH_INVALID


def test_puat_missing_protocol(client):
    args = generate_make_credentials_params(client, pin_uv_param=generate_random_bytes(32))
    args.pin_uv_protocol = None
    with pytest.raises(CtapError) as e:
        client.ctap2.make_credential(args, navigation=Nav.NONE, will_fail=True)
    assert e.value.code == CtapError.ERR.MISSING_PARAMETER


def test_puat_zero_length_pin_uv_param(client):
    # DEVIATION from FIDO2.1 spec: If platform sends zero length pinUvAuthParam,
    # authenticator needs to wait for user touch and then returns [...]
    # Impact is minor because the user has still manually unlocked its device.
    # Built-in UV is available, so the answer is PIN_INVALID.
    args = generate_make_credentials_params(client, pin_uv_param=b"")
    with pytest.raises(CtapError) as e:
        client.ctap2.make_credential(args, navigation=Nav.NONE, will_fail=True)
    assert e.value.code == CtapError.ERR.PIN_INVALID

    t = ctap2_get_assertion(client)
    client_data_hash = generate_random_bytes(32)
    allow_list = [{"id": t.credential_data.credential_id, "type": "public-key"}]
    with pytest.raises(CtapError) as e:
        client.ctap2.get_assertion(t.args.rp["id"], client_data_hash, allow_list,
                                   pin_uv_param=b"",
                                   pin_uv_protocol=client.client_pin.protocol.VERSION,
                                   navigation=Nav.NONE, will_fail=True)
    assert e.value.code == CtapError.ERR.PIN_INVALID


def test_puat_get_token_errors(client):
    protocol = PinProtocolV2

    # No permissions
    with pytest.raises(CtapError) as e:
        raw_get_uv_token(client, protocol, permissions=0, permissions_rpid="example.com")
    assert e.value.code == CtapError.ERR.INVALID_PARAMETER

    # Missing permissions
    with pytest.raises(CtapError) as e:
        raw_get_uv_token(client, protocol, permissions_rpid="example.com")
    assert e.value.code == CtapError.ERR.MISSING_PARAMETER

    # mc / ga without RP ID
    with pytest.raises(CtapError) as e:
        raw_get_uv_token(client, protocol, permissions=PERM.MAKE_CREDENTIAL)
    assert e.value.code == CtapError.ERR.MISSING_PARAMETER

    # Permissions that are not implemented
    for permission in [PERM.CREDENTIAL_MGMT, PERM.BIO_ENROLL, PERM.LARGE_BLOB_WRITE,
                       PERM.AUTHENTICATOR_CFG, PERM.MAKE_CREDENTIAL | PERM.CREDENTIAL_MGMT]:
        with pytest.raises(CtapError) as e:
            raw_get_uv_token(client, protocol, permissions=permission,
                             permissions_rpid="example.com")
        assert e.value.code == CtapError.ERR.UNAUTHORIZED_PERMISSION


@pytest.mark.parametrize("protocol", PROTOCOLS, ids=protocol_id)
def test_puat_uv_option_still_works(client, protocol):
    # The legacy way of asking for UV, without any token
    args = generate_make_credentials_params(client, uv=True)
    attestation = client.ctap2.make_credential(args)
    assert uv_flag(attestation.auth_data)


def test_puat_hmac_secret_matches_uv_option(client):
    """
    The hmac-secret output of a credential only depends on whether the user was verified, not on
    how: the "uv" option or a pinUvAuthParam give the same output, protocol 1 or 2.
    """
    args = generate_make_credentials_params(client, extensions={"hmac-secret": True})
    attestation = client.ctap2.make_credential(args)
    assert attestation.auth_data.extensions["hmac-secret"]
    rp_id = args.rp["id"]

    credential_data = AttestedCredentialData(attestation.auth_data.credential_data)
    allow_list = [{"id": credential_data.credential_id, "type": "public-key"}]
    salt = generate_random_bytes(32)

    def get_secret(protocol, use_token):
        hmac_ext = HmacSecretExtension(client.ctap2, pin_protocol=protocol())
        extensions = {"hmac-secret": hmac_ext.process_get_input({"hmacGetSecret": {"salt1": salt}})}
        client_data_hash = generate_random_bytes(32)
        kwargs = {}
        if use_token:
            token = get_token(client, protocol, PERM.GET_ASSERTION, rp_id)
            kwargs["pin_uv_param"] = protocol().authenticate(token, client_data_hash)
            kwargs["pin_uv_protocol"] = protocol.VERSION
        else:
            kwargs["options"] = {"uv": True}
        assertion = client.ctap2.get_assertion(rp_id, client_data_hash, allow_list,
                                               extensions=extensions, **kwargs)
        assert uv_flag(assertion.auth_data)
        return hmac_ext.process_get_output(assertion)["hmacGetSecret"]["output1"]

    reference = get_secret(PinProtocolV1, use_token=False)
    assert get_secret(PinProtocolV2, use_token=False) == reference
    assert get_secret(PinProtocolV1, use_token=True) == reference
    assert get_secret(PinProtocolV2, use_token=True) == reference


@pytest.mark.skip_endpoint("NFC", reason="CTAP2 reset is not available on NFC - 0x27")
def test_puat_invalidated_by_reset(client):
    protocol = PinProtocolV2
    args = generate_make_credentials_params(client)
    token = get_token(client, protocol, PERM.MAKE_CREDENTIAL, args.rp["id"])

    client.ctap2.reset()

    args.pin_uv_param = protocol().authenticate(token, args.client_data_hash)
    args.pin_uv_protocol = protocol.VERSION
    with pytest.raises(CtapError) as e:
        client.ctap2.make_credential(args, navigation=Nav.NONE, will_fail=True)
    assert e.value.code == CtapError.ERR.PIN_AUTH_INVALID
