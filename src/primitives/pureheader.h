// Copyright (c) 2014-2024 Daniel Kraft
// Copyright (c) 2025 The Perbug developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_PRIMITIVES_PUREHEADER_H
#define BITCOIN_PRIMITIVES_PUREHEADER_H

#include <serialize.h>
#include <uint256.h>
#include <util/time.h>

#include <cassert>

/**
 * A block header without the AuxPoW section. This is the "pure" 80-byte header
 * that is hashed for proof-of-work and, when merge-mining, committed to inside
 * the parent chain's coinbase. The AuxPoW metadata lives in CBlockHeader, which
 * derives from this class.
 *
 * The block version doubles as the merge-mining tag (Namecoin/Dogecoin scheme):
 *   bits  0.. 7  base version (soft-fork era)
 *   bit   8      AuxPoW flag (this block carries a parent-chain proof)
 *   bits 16..31  chain id (which aux chain this block belongs to)
 */
class CPureBlockHeader
{
public:
    // Flag in the version that marks a block as carrying an AuxPoW proof.
    static const int32_t VERSION_AUXPOW = (1 << 8);
    // Multiplier for the chain id in the version (chain id starts at bit 16).
    static const int32_t VERSION_CHAIN_START = (1 << 16);

    // header
    int32_t nVersion;
    uint256 hashPrevBlock;
    uint256 hashMerkleRoot;
    uint32_t nTime;
    uint32_t nBits;
    uint32_t nNonce;

    CPureBlockHeader()
    {
        SetNull();
    }

    SERIALIZE_METHODS(CPureBlockHeader, obj) { READWRITE(obj.nVersion, obj.hashPrevBlock, obj.hashMerkleRoot, obj.nTime, obj.nBits, obj.nNonce); }

    void SetNull()
    {
        nVersion = 0;
        hashPrevBlock.SetNull();
        hashMerkleRoot.SetNull();
        nTime = 0;
        nBits = 0;
        nNonce = 0;
    }

    bool IsNull() const
    {
        return (nBits == 0);
    }

    uint256 GetHash() const;

    int64_t GetBlockTime() const
    {
        return (int64_t)nTime;
    }

    NodeSeconds Time() const
    {
        return NodeSeconds{std::chrono::seconds{nTime}};
    }

    /* ---- Version / chain-id helpers (merge-mining) ---- */

    /** Low-bits "base" version, stripped of chain id and the AuxPoW flag. */
    inline int32_t GetBaseVersion() const
    {
        return GetBaseVersion(nVersion);
    }
    static inline int32_t GetBaseVersion(int32_t ver)
    {
        return ver % VERSION_AUXPOW;
    }

    /** Set the base version while keeping (or assigning) a chain id. Must not be
     *  called on a header that already has the AuxPoW flag set. */
    inline void SetBaseVersion(int32_t nBaseVersion, int32_t nChainId)
    {
        assert(nBaseVersion >= 0 && nBaseVersion < VERSION_AUXPOW);
        assert(!IsAuxpow());
        nVersion = nBaseVersion | (nChainId * VERSION_CHAIN_START);
    }

    inline int32_t GetChainId() const
    {
        return nVersion >> 16;
    }

    inline void SetChainId(int32_t chainId)
    {
        nVersion %= VERSION_CHAIN_START;
        nVersion |= chainId * VERSION_CHAIN_START;
    }

    /** True if this header carries an AuxPoW proof. */
    inline bool IsAuxpow() const
    {
        return nVersion & VERSION_AUXPOW;
    }

    inline void SetAuxpowVersion(bool auxpow)
    {
        if (auxpow)
            nVersion |= VERSION_AUXPOW;
        else
            nVersion &= ~VERSION_AUXPOW;
    }

    /** Legacy (pre-fork, un-tagged) block version. */
    inline bool IsLegacy() const
    {
        return nVersion == 1;
    }
};

#endif // BITCOIN_PRIMITIVES_PUREHEADER_H
