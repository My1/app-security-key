"""
New CTAP2 credentials never report a signature counter: it is always 0, at registration and in
every later assertion. (Credentials created before this feature, handle version 1, keep using the
global counter; they can't be created by this app anymore, so they are not covered here.)
"""
from fido2.webauthn import AttestedCredentialData

from ..utils import generate_random_bytes, generate_make_credentials_params, ctap2_get_assertion


def credential_allow_list(t):
    return [{"id": t.credential_data.credential_id, "type": "public-key"}]


def test_zero_counter_non_resident(client):
    t = ctap2_get_assertion(client)
    assert t.attestation.auth_data.counter == 0

    for _ in range(3):
        client_data_hash = generate_random_bytes(32)
        assertion = client.ctap2.get_assertion(t.args.rp["id"], client_data_hash,
                                               credential_allow_list(t))
        assertion.verify(client_data_hash, t.credential_data.public_key)
        assert assertion.auth_data.counter == 0


def test_zero_counter_resident(client):
    client.enable_rk_option()

    t = ctap2_get_assertion(client, rk=True)
    assert t.attestation.auth_data.counter == 0

    # The flag is in both the full credential stored in NVM and in the credId sent to the platform
    for _ in range(2):
        client_data_hash = generate_random_bytes(32)
        assertion = client.ctap2.get_assertion(t.args.rp["id"], client_data_hash,
                                               credential_allow_list(t))
        assertion.verify(client_data_hash, t.credential_data.public_key)
        assert assertion.auth_data.counter == 0


def test_zero_counter_ignores_other_credentials(client):
    # Credentials are independent: a second one is also created with a zero counter
    first = ctap2_get_assertion(client)
    args = generate_make_credentials_params(client)
    attestation = client.ctap2.make_credential(args)
    assert attestation.auth_data.counter == 0
    assert first.attestation.auth_data.counter == 0
    credential = AttestedCredentialData(attestation.auth_data.credential_data)

    client_data_hash = generate_random_bytes(32)
    assertion = client.ctap2.get_assertion(
        args.rp["id"], client_data_hash,
        [{"id": credential.credential_id, "type": "public-key"}])
    assert assertion.auth_data.counter == 0
