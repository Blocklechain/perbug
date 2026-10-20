// Copyright (c) 2009-2014 The Bitcoin developers
// Copyright (c) 2014-2024 Daniel Kraft
// Copyright (c) 2025 The Perbug developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <auxpow.h>

#include <consensus/params.h>
#include <hash.h>
#include <logging.h>
#include <primitives/transaction.h>
#include <script/script.h>
#include <uint256.h>

#include <algorithm>

namespace {
inline bool AuxErr(const char* msg)
{
    LogDebug(BCLog::VALIDATION, "AuxPow check failed: %s\n", msg);
    return false;
}
inline uint256 HashPair(const uint256& a, const uint256& b)
{
    return (HashWriter{} << a << b).GetHash();
}
inline uint32_t ReadLE32(std::vector<unsigned char>::const_iterator pc)
{
    return static_cast<uint32_t>(pc[0])
         | (static_cast<uint32_t>(pc[1]) << 8)
         | (static_cast<uint32_t>(pc[2]) << 16)
         | (static_cast<uint32_t>(pc[3]) << 24);
}
} // namespace

uint256 CheckMerkleBranch(uint256 hash, const std::vector<uint256>& vMerkleBranch, int nIndex)
{
    if (nIndex == -1) return uint256();
    for (const uint256& otherside : vMerkleBranch) {
        if (nIndex & 1)
            hash = HashPair(otherside, hash);
        else
            hash = HashPair(hash, otherside);
        nIndex >>= 1;
    }
    return hash;
}

int GetExpectedAuxPoWIndex(uint32_t nNonce, int nChainId, unsigned h)
{
    // Choose a pseudo-random slot for this chain in the aux merkle tree, so a
    // single parent coinbase can't commit the same chain at every slot.
    uint32_t rand = nNonce;
    rand = rand * 1103515245 + 12345;
    rand += static_cast<uint32_t>(nChainId);
    rand = rand * 1103515245 + 12345;
    return rand % (1u << h);
}

bool CAuxPow::check(const uint256& hashAuxBlock, int nChainId, const Consensus::Params& params) const
{
    if (nIndex != 0)
        return AuxErr("coinbase transaction not at index 0");
    if (!coinbaseTx || coinbaseTx->vin.empty())
        return AuxErr("parent coinbase missing");
    if (params.fStrictChainId && parentBlock.GetChainId() == nChainId)
        return AuxErr("parent block has our chain id");
    if (vChainMerkleBranch.size() > 30)
        return AuxErr("chain merkle branch too long");

    // 1) The aux (this chain's) block hash must hash up the chain merkle branch
    //    to a root that is embedded in the parent coinbase scriptSig.
    const uint256 nRootHash = CheckMerkleBranch(hashAuxBlock, vChainMerkleBranch, nChainIndex);
    std::vector<unsigned char> vchRootHash(nRootHash.begin(), nRootHash.end());
    std::reverse(vchRootHash.begin(), vchRootHash.end()); // stored byte-reversed

    // 2) The coinbase tx must hash up its own merkle branch to the parent
    //    block's merkle root (i.e. it really is in the parent block).
    if (CheckMerkleBranch(coinbaseTx->GetHash(), vMerkleBranch, nIndex) != parentBlock.hashMerkleRoot)
        return AuxErr("coinbase merkle branch does not lead to parent merkle root");

    const CScript& script = coinbaseTx->vin[0].scriptSig;
    const std::vector<unsigned char> vScript(script.begin(), script.end());

    // Locate the merged-mining header and the chain merkle root in the scriptSig.
    auto pcHead = std::search(vScript.begin(), vScript.end(),
                              std::begin(pchMergedMiningHeader), std::end(pchMergedMiningHeader));
    auto pc = std::search(vScript.begin(), vScript.end(),
                          vchRootHash.begin(), vchRootHash.end());
    if (pc == vScript.end())
        return AuxErr("chain merkle root not found in parent coinbase");

    if (pcHead != vScript.end()) {
        // The header must be unique and immediately precede the root.
        if (std::search(pcHead + 1, vScript.end(),
                        std::begin(pchMergedMiningHeader), std::end(pchMergedMiningHeader)) != vScript.end())
            return AuxErr("multiple merged-mining headers in parent coinbase");
        if (pcHead + sizeof(pchMergedMiningHeader) != pc)
            return AuxErr("merged-mining header is not just before the chain merkle root");
    } else {
        // Without a header, the root must appear within the first 20 bytes.
        if (pc - vScript.begin() > 20)
            return AuxErr("chain merkle root must be in the first 20 bytes");
    }

    // After the root: merkle-tree size (LE32) then merkle nonce (LE32).
    pc += vchRootHash.size();
    if (vScript.end() - pc < 8)
        return AuxErr("missing chain merkle tree size and nonce");

    const uint32_t nSize = ReadLE32(pc);
    const unsigned merkleHeight = vChainMerkleBranch.size();
    if (nSize != (1u << merkleHeight))
        return AuxErr("merkle tree size does not match chain merkle branch length");

    const uint32_t nNonce = ReadLE32(pc + 4);
    if (nChainIndex != GetExpectedAuxPoWIndex(nNonce, nChainId, merkleHeight))
        return AuxErr("wrong chain merkle index");

    return true;
}
