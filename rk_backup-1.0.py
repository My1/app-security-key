#!/usr/bin/env python3
"""
Back up and restore the resident credentials (passkeys) of the Ledger Security Key app.

Needs python-fido2 (1.x) over USB, the app open, resident keys enabled in its settings.
Every run asks you to approve "Manage saved accounts?" on the device.

    rk_backup.py backup  FILE           write every resident credential to FILE (JSON)
    rk_backup.py list    FILE           show what a backup contains (device not needed)
    rk_backup.py check   FILE           tell which credentials of FILE belong to this device and
                                        which are missing on it (stores nothing)
    rk_backup.py restore FILE           put the credentials of FILE back on the device
    rk_backup.py restore FILE --dry-run only show what would be restored
    rk_backup.py backup FILE --rp example.com    only one RP (plain RP ID, or --rp-hash)
    rk_backup.py --device N ...         pick the Nth FIDO device (default 0)

What a backup holds: for each credential what a standard credential management enumeration
reports: RP ID hash (and RP ID when the device knows it), credential id, user id and name, and the
key algorithm. No private key: the keys are derived by the device from its seed and the credential
nonce, so a backup only works on a device with the same seed (the credential id is authenticated
by the device on restore, anything else is refused), and it is not a way to clone a key. It does
contain the list of your accounts in clear: keep the file private.

Which device a backup belongs to: the file holds the backup ID of its device, 8 hex digits shown
on the device (next to the version on the Nanos, in the app info on the Flex / Stax) and derived
from its seed. "list" shows the one of a file, so a backup can be matched by eye or by searching
the files for it. "check" and "restore" compare it with the device first. Backups made before the
firmware had a backup ID don't have one; "check" asks the device about every credential anyway.

Restoring a backup of another seed changes nothing: the device refuses every credential (and the
script stops at the first one). Restoring onto the right device only adds what is missing, so
trying is safe.

The backup also holds each credential's public key: after "restore" (and in "check", for the
credentials already on the device) the script compares them with the keys the device reports, so a
restored credential is shown to be exactly the original one, not just one the device accepts.

A backup made with an older firmware has no backup ID: "backup" again to get one, the new file
holds the same credentials.

Restoring skips what is already there (same credential), and never replaces a credential of
a user that already has one for the same RP. A credential fails with "key store full" when the
device has no free slot left.
"""
import argparse
import base64
import hashlib
import json
import sys
import time

from fido2 import cbor
from fido2.ctap import CtapError

# Vendor command of the app (resident credential backup ID and restore), its subcommands,
# parameters and response
VENDOR_RK = 0x50
RESTORE = 0x01
P_RP_ID_HASH, P_CRED_ID, P_USER_ID, P_USER_NAME, P_RP_ID, P_ALG = 0x01, 0x42, 0x44, 0x45, 0x46, 0x47
R_RESULT = 0x45
# Vendor subcommand: the backup ID (8 hex digits identifying the seed, also shown on the device)
BACKUP_ID, R_BACKUP_ID = 0x02, 0x46
RESULTS = {0: "restored", 1: "already there", 2: "skipped (that user already has a credential)",
           3: "missing, would be restored"}
P_CHECK = 0x48
# Keys of the standard enumeration responses
RP, RP_ID_HASH, USER, CREDENTIAL_ID, PUBLIC_KEY = 3, 4, 6, 7, 8

FORMAT = "ledger-security-key-rk-backup"


def b64(data):
    return base64.b64encode(data).decode()


def describe(record):
    rp = record.get("rp_id") or (record["rp_id_hash"][:16] + "... (hash only)")
    return f"{rp}  {record.get('user_name') or record['user_id'][:16]}"


RESTORE_OPTION = "ledgerMy1RkRestore"


def open_cm(args, need_restore=False):
    from fido2.ctap2 import Ctap2
    from fido2.ctap2.pin import ClientPin
    from fido2.hid import CtapHidDevice

    devices = list(CtapHidDevice.list_devices())
    if not devices:
        sys.exit("No FIDO device found over USB")
    if len(devices) > 1:
        print(f"{len(devices)} FIDO devices found, using #{args.device}", file=sys.stderr)
    ctap = Ctap2(devices[args.device])

    # What the device says it can do, before asking for anything on its screen
    options = ctap.info.options
    if not options.get("rk"):
        sys.exit("Resident keys are disabled in the app settings: turn them on first")
    if not options.get("credMgmt"):
        sys.exit("This device has no credential management (an app built without it?)")
    if need_restore and RESTORE_OPTION not in options:
        sys.exit("This firmware has no restore support")
    if need_restore and not options[RESTORE_OPTION]:
        sys.exit("Restore is not available right now (resident keys disabled?)")

    pin = ClientPin(ctap)
    print("Confirm 'Manage saved accounts?' on the device...", file=sys.stderr)
    try:
        token = pin.get_uv_token(ClientPin.PERMISSION.CREDENTIAL_MGMT)
    except CtapError as e:
        if e.code == CtapError.ERR.OPERATION_DENIED:
            sys.exit("Account management was denied on the device")
        sys.exit(f"No credential management token: {e} (resident keys enabled in the settings?)")

    def call(sub_command, params):
        message = bytes([sub_command]) + (cbor.encode(params) if params is not None else b"")
        # Vendor command, shaped like authenticatorCredentialManagement
        request = {1: sub_command, 3: pin.protocol.VERSION,
                   4: pin.protocol.authenticate(token, message)}
        if params is not None:
            request[2] = params
        return ctap.send_cbor(VENDOR_RK, request)

    return ctap, call, pin, token


def device_backup_id(call):
    """The backup ID of the device, None if its firmware has none."""
    try:
        return call(BACKUP_ID, None)[R_BACKUP_ID]
    except CtapError as e:
        if e.code in (CtapError.ERR.INVALID_SUBCOMMAND, CtapError.ERR.INVALID_COMMAND):
            return None
        raise


def do_backup(args):
    from fido2.ctap2.credman import CredentialManagement

    ctap, call, pin, token = open_cm(args)
    cm = CredentialManagement(ctap, pin.protocol, token)
    wanted = None
    if args.rp:
        wanted = hashlib.sha256(args.rp.encode()).digest()
    elif args.rp_hash:
        wanted = bytes.fromhex(args.rp_hash)

    metadata = cm.get_metadata()
    print(f"The device reports {metadata[1]} resident credential(s), room for {metadata[2]} more",
          file=sys.stderr)

    records = []
    try:
        rps = cm.enumerate_rps()
    except CtapError as e:
        if e.code == CtapError.ERR.NO_CREDENTIALS:
            rps = []
        else:
            sys.exit(f"Listing the RPs failed: {e}")
    print(f"{len(rps)} RP(s) listed", file=sys.stderr)
    for rp in rps:
        rp_hash = rp[RP_ID_HASH]
        if wanted is not None and rp_hash != wanted:
            continue
        rp_id = rp[RP]["id"] if RP in rp else None
        try:
            creds = cm.enumerate_creds(rp_hash)
        except CtapError as e:
            print(f"Listing the credentials of {rp_hash.hex()[:16]}... failed: {e}",
                  file=sys.stderr)
            continue
        for cred in creds:
            user = cred[USER]
            records.append({
                "rp_id": rp_id,
                "rp_id_hash": rp_hash.hex(),
                "credential_id": b64(cred[CREDENTIAL_ID]["id"]),
                "user_id": user["id"].hex(),
                "user_name": user.get("name"),
                "alg": cred[PUBLIC_KEY][3],
                # COSE public key (CBOR, base64), to check after a restore that the device
                # signs with exactly the original key
                "public_key": b64(cbor.encode(dict(cred[PUBLIC_KEY]))),
            })

    backup_id = device_backup_id(call)
    backup = {"format": FORMAT, "version": 2, "backup_id": backup_id,
              "created": int(time.time()), "credentials": records}
    with open(args.file, "w") as f:
        json.dump(backup, f, indent=2)
    print(f"{len(records)} credential(s) saved to {args.file}"
          f" (backup ID {backup_id or 'unknown: firmware without one'})")
    for r in records:
        print("  ", describe(r))


def load(path):
    with open(path) as f:
        backup = json.load(f)
    if backup.get("format") != FORMAT or backup.get("version") != 2:
        sys.exit(f"{path} is not a backup of this tool")
    return backup.get("backup_id"), backup["credentials"]


def do_list(args):
    backup_id, records = load(args.file)
    print(f"Backup ID {backup_id or 'unknown'}, {len(records)} credential(s):")
    for r in records:
        print("  ", describe(r))


def verify_public_keys(cm, records):
    """Compares the public keys of the backup with the ones the device reports now for the same
    credentials. Returns (matching, different, not compared)."""
    by_rp = {}
    for r in records:
        if r.get("public_key"):
            by_rp.setdefault(r["rp_id_hash"], []).append(r)
    same = different = 0
    for rp_hash, rp_records in by_rp.items():
        try:
            creds = cm.enumerate_creds(bytes.fromhex(rp_hash))
        except CtapError as e:
            print(f"  listing {rp_hash[:16]}... failed: {e}", file=sys.stderr)
            continue
        device_keys = {b64(c[CREDENTIAL_ID]["id"]): cbor.encode(dict(c[PUBLIC_KEY]))
                       for c in creds}
        for r in rp_records:
            device_key = device_keys.get(r["credential_id"])
            if device_key is None:
                continue  # not on the device (refused, skipped, missing in a check)
            if device_key == base64.b64decode(r["public_key"]):
                same += 1
            else:
                different += 1
                print(f"  {describe(r)}: DIFFERENT public key than at backup time")
    return same, different, len(records) - same - different


def do_restore(args):
    file_id, records = load(args.file)
    if args.dry_run:
        print(f"Would restore {len(records)} credential(s):")
        for r in records:
            print("  ", describe(r))
        return

    ctap, call, pin, token = open_cm(args, need_restore=True)
    device_id = device_backup_id(call)
    if file_id and device_id:
        if file_id != device_id:
            message = (f"This backup is from the device with backup ID {file_id}, "
                       f"this one is {device_id}.")
            if not args.keep_going:
                sys.exit(f"{message} Nothing done. (--keep-going tries anyway)")
            print(message, file=sys.stderr)
        else:
            print(f"Backup ID {device_id}: the backup is from this device", file=sys.stderr)
    failed = matched = 0
    for r in records:
        params = {
            P_RP_ID_HASH: bytes.fromhex(r["rp_id_hash"]),
            P_CRED_ID: base64.b64decode(r["credential_id"]),
            P_USER_ID: bytes.fromhex(r["user_id"]),
            P_ALG: r["alg"],
        }
        if r.get("rp_id"):
            params[P_RP_ID] = r["rp_id"]
        if r.get("user_name"):
            params[P_USER_NAME] = r["user_name"]
        if args.command == "check":
            params[P_CHECK] = 1
        try:
            result = RESULTS.get(call(RESTORE, params)[R_RESULT], "?")
            matched += 1
        except CtapError as e:
            if e.code in (CtapError.ERR.INVALID_SUBCOMMAND, CtapError.ERR.INVALID_COMMAND):
                sys.exit("This firmware has no restore support (or an older version of it: "
                         "update the app)")
            if args.command == "check" and e.code == CtapError.ERR.INVALID_CREDENTIAL:
                failed += 1
                print(f"  {describe(r)}: not from this device")
                continue
            if (e.code == CtapError.ERR.INVALID_CREDENTIAL and matched == 0 and
                    not args.keep_going):
                # Nothing has matched so far: almost certainly a backup of another seed. The
                # device refuses those credentials anyway, nothing was changed.
                sys.exit(f"  {describe(r)}: refused, not created by this device.\n"
                         f"This backup most likely belongs to a device with another seed: "
                         f"nothing was restored. (--keep-going tries every credential anyway)")
            failed += 1
            result = f"FAILED: {e}"
            if e.code == CtapError.ERR.INVALID_CREDENTIAL:
                result += " (not created by this device, or damaged)"
            elif e.code == CtapError.ERR.KEY_STORE_FULL:
                result += " (no free slot left)"
        print(f"  {describe(r)}: {result}")
    if args.command == "check" and matched == 0:
        sys.exit(f"None of the {len(records)} credential(s) belongs to this device "
                 f"(a backup of another seed)")

    # The credentials now on the device must have the public keys they had at backup time
    different = 0
    if any(r.get("public_key") for r in records) and matched:
        from fido2.ctap2.credman import CredentialManagement

        same, different, other = verify_public_keys(
            CredentialManagement(ctap, pin.protocol, token), records)
        print(f"Public keys: {same} identical to the backup" +
              (f", {different} DIFFERENT" if different else "") +
              (f", {other} not on the device or without a key in the file" if other else ""))
    elif matched:
        print("Public keys: not compared (backup made without them, back up again to add them)")

    if args.command == "check":
        print(f"{matched} of {len(records)} credential(s) belong to this device" +
              (f", {failed} do not" if failed else ""))
        if different:
            sys.exit(1)
        return
    if failed or different:
        sys.exit(f"{failed} credential(s) could not be restored" +
                 (f", {different} with a different public key" if different else ""))


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("command", choices=["backup", "list", "check", "restore"])
    parser.add_argument("file")
    parser.add_argument("--device", type=int, default=0, help="index of the FIDO device")
    parser.add_argument("--rp", help="backup: only this RP ID (plain)")
    parser.add_argument("--rp-hash", help="backup: only this RP ID hash (hex)")
    parser.add_argument("--dry-run", action="store_true", help="restore: don't touch the device")
    parser.add_argument("--keep-going", action="store_true",
                        help="restore: don't stop when the first credential is from another seed")
    args = parser.parse_args()
    {"backup": do_backup, "list": do_list, "check": do_restore,
     "restore": do_restore}[args.command](args)


if __name__ == "__main__":
    main()
