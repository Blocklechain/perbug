// Copyright (c) 2009-2014 The Bitcoin developers
// Copyright (c) 2014-2024 Daniel Kraft
// Copyright (c) 2025 The Perbug developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_AUXPOW_H
#define BITCOIN_AUXPOW_H

#include <consensus/params.h>
#include <primitives/pureheader.h>
#include <primitives/transaction.h>
#include <serialize.h>
#include <uint256.h>

#include <vector>

class CBlockHeader;

/** Merged-mining header magic bytes placed in the parent coinbase scriptSig. */
static const unsigned char pchMergedMiningHeader[] = {0xfa, 0xbe, 'm', 'm'};

/**
 * Merge-mining proof (Namecoin/Dogecoin AuxPoW format). It proves that this
 * chain's block hash was committed to inside a parent-chain block's coinbase,
 * and that the parent block's proof-of-work meets this chain's target.
 *
 * Wire layout (compatible with existing merge-mining pools):
 *   coinbaseTx  : the parent-chain coinbase transaction
 *   hashBlock   : parent block hash (legacy CMerkleTx field, unused on check)
 *   vMerkleBranch : branch tying coinbaseTx into parentBlock.hashMerkleRoot
 *   nIndex      : coinbase position in the parent block (always 0)
 *   vChainMerkleBranch : branch tying this chain's hash into the aux merkle root
 *   nChainIndex : this chain's slot in the aux merkle tree
 *   parentBlock : the parent block header (carries the PoW)
 */
class CAuxPow
{
public:
    CTransactionRef coinbaseTx;
    uint256 hashBlock;
    std::vector<uint256> vMerkleBranch;
    int nIndex{0};
    std::vector<uint256> vChainMerkleBranch;
    int nChainIndex{0};
    CPureBlockHeader parentBlock;

    CAuxPow() = default;
    explicit CAuxPow(CTransactionRef tx) : coinbaseTx(std::move(tx)) {}

    SERIALIZE_METHODS(CAuxPow, obj)
    {
        // The coinbase is serialised WITHOUT witness: its txid (non-witness
        // hash) is what the parent block's merkle tree commits to.
        READWRITE(TX_NO_WITNESS(obj.coinbaseTx));
        READWRITE(obj.hashBlock);
        READWRITE(obj.vMerkleBranch);
        READWRITE(obj.nIndex);
        READWRITE(obj.vChainMerkleBranch);
        READWRITE(obj.nChainIndex);
        READWRITE(obj.parentBlock);
    }

    /**
     * Verify the proof for the given aux block hash and chain id.
     * @param hashAuxBlock  the hash of THIS chain's block header being checked
     * @param nChainId      this chain's id (from the block version)
     * @param params        consensus params
     * @return true iff the proof is structurally valid (PoW is checked separately)
     */
    bool check(const uint256& hashAuxBlock, int nChainId, const Consensus::Params& params) const;

    /** The parent block's PoW hash (what must satisfy this chain's nBits). */
    const CPureBlockHeader& getParentBlock() const { return parentBlock; }
};

/** Compute a merkle root from a leaf, a branch and a side-index bitmask. */
uint256 CheckMerkleBranch(uint256 hash, const std::vector<uint256>& vMerkleBranch, int nIndex);

/** Build the expected chain-merkle-tree index for a chain id + merkle nonce. */
int GetExpectedAuxPoWIndex(uint32_t nNonce, int nChainId, unsigned h);

using CAuxPowPtr = std::shared_ptr<CAuxPow>;

#endif // BITCOIN_AUXPOW_H
