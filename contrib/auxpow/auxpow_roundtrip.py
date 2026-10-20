#!/usr/bin/env python3
# Live regtest round-trip for merge-mining: createauxblock -> build a valid
# AuxPoW (acting as the parent SHA-256 pool) -> submitauxblock -> chain extends.
# Exercises the real RPCs + full validation with a real clock.
import json, subprocess, hashlib, struct, sys

D = "/tmp/pbaux"
CLI = ["/opt/perbug/build/bin/perbug-cli", "-regtest", "-datadir=" + D]

def cli(*args):
    out = subprocess.run(CLI + list(args), capture_output=True, text=True)
    if out.returncode != 0:
        raise SystemExit("cli %s failed: %s" % (args, out.stderr.strip()))
    return out.stdout.strip()

def dsha(b): return hashlib.sha256(hashlib.sha256(b).digest()).digest()
def varint(n): return bytes([n]) if n < 0xfd else b'\xfd' + struct.pack('<H', n)

def compact_to_target(bits):
    exp = bits >> 24
    mant = bits & 0x007fffff
    return mant * (1 << (8 * (exp - 3))) if exp > 3 else mant >> (8 * (3 - exp))

MAGIC = bytes([0xfa, 0xbe, ord('m'), ord('m')])

def build_coinbase(aux_hash_hex):
    # scriptSig = MAGIC + root(display-order bytes) + size(LE32=1) + nonce(LE32=0)
    root = bytes.fromhex(aux_hash_hex)          # display order == CAuxPow's reversed root
    script = MAGIC + root + struct.pack('<I', 1) + struct.pack('<I', 0)
    ser = struct.pack('<i', 2)                  # version 2 (CMutableTransaction default)
    ser += varint(1)                            # vin count
    ser += b'\x00' * 32 + struct.pack('<I', 0xffffffff)   # prevout null
    ser += varint(len(script)) + script         # scriptSig
    ser += struct.pack('<I', 0xffffffff)         # sequence
    ser += varint(1)                            # vout count
    ser += struct.pack('<q', 0)                  # value 0
    ser += varint(0)                            # empty scriptPubKey
    ser += struct.pack('<I', 0)                  # locktime
    return ser, dsha(ser)                        # (serialized, txid internal bytes)

def build_parent(merkle_root_internal, target):
    nonce = 0
    while True:
        hdr = struct.pack('<i', 1) + b'\x00'*32 + merkle_root_internal + struct.pack('<III', 0, 0, nonce)
        h = dsha(hdr)
        if int.from_bytes(h, 'little') <= target:
            return hdr, nonce
        nonce += 1
        if nonce > 2_000_000:
            raise SystemExit("could not solve parent PoW")

def build_auxpow(aux_hash_hex, bits):
    cb_ser, txid = build_coinbase(aux_hash_hex)
    target = compact_to_target(bits)
    parent_hdr, nonce = build_parent(txid, target)
    ap  = cb_ser
    ap += b'\x00' * 32            # hashBlock (unused)
    ap += varint(0)              # vMerkleBranch
    ap += struct.pack('<i', 0)   # nIndex
    ap += varint(0)              # vChainMerkleBranch
    ap += struct.pack('<i', 0)   # nChainIndex
    ap += parent_hdr
    return ap.hex(), nonce

def main():
    cli("createwallet", "w")
    addr = cli("getnewaddress")
    cli("generatetoaddress", "20", addr)
    before = int(cli("getblockcount"))
    aux = json.loads(cli("createauxblock", addr))
    print("createauxblock -> hash=%s bits=%s chainid=%s" % (aux["hash"][:16]+"...", aux["bits"], aux["chainid"]))
    bits = int(aux["bits"], 16)
    auxpow_hex, nonce = build_auxpow(aux["hash"], bits)
    print("built auxpow (parent nonce=%d, %d bytes)" % (nonce, len(auxpow_hex)//2))
    res = cli("submitauxblock", aux["hash"], auxpow_hex)
    after = int(cli("getblockcount"))
    print("submitauxblock -> %s ; height %d -> %d" % (res, before, after))
    if res.strip() == "true" and after == before + 1:
        print("AUXPOW ROUND-TRIP: PASS")
    else:
        print("AUXPOW ROUND-TRIP: FAIL"); sys.exit(1)

main()
