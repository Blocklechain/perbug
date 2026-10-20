// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <pow.h>

#include <arith_uint256.h>
#include <chain.h>
#include <primitives/block.h>
#include <uint256.h>
#include <util/check.h>

#include <algorithm>

unsigned int GetNextWorkRequired(const CBlockIndex* pindexLast, const CBlockHeader *pblock, const Consensus::Params& params)
{
    assert(pindexLast != nullptr);
    unsigned int nProofOfWorkLimit = UintToArith256(params.powLimit).GetCompact();

    // LWMA per-block retarget hard fork: once active, recompute every block.
    if (params.nLwmaHeight > 0 && pindexLast->nHeight + 1 >= params.nLwmaHeight) {
        return LwmaGetNextWorkRequired(pindexLast, params);
    }

    // Only change once per difficulty adjustment interval
    if ((pindexLast->nHeight+1) % params.DifficultyAdjustmentInterval() != 0)
    {
        if (params.fPowAllowMinDifficultyBlocks)
        {
            // Special difficulty rule for testnet:
            // If the new block's timestamp is more than 2* 10 minutes
            // then it MUST be a min-difficulty block.
            if (pblock->GetBlockTime() > pindexLast->GetBlockTime() + params.nPowTargetSpacing*2)
                return nProofOfWorkLimit;
            else
            {
                // Return the last non-special-min-difficulty-rules-block
                const CBlockIndex* pindex = pindexLast;
                while (pindex->pprev && pindex->nHeight % params.DifficultyAdjustmentInterval() != 0 && pindex->nBits == nProofOfWorkLimit)
                    pindex = pindex->pprev;
                return pindex->nBits;
            }
        }
        return pindexLast->nBits;
    }

    // Go back by what we want to be 14 days worth of blocks
    int nHeightFirst = pindexLast->nHeight - (params.DifficultyAdjustmentInterval()-1);
    assert(nHeightFirst >= 0);
    const CBlockIndex* pindexFirst = pindexLast->GetAncestor(nHeightFirst);
    assert(pindexFirst);

    return CalculateNextWorkRequired(pindexLast, pindexFirst->GetBlockTime(), params);
}

unsigned int CalculateNextWorkRequired(const CBlockIndex* pindexLast, int64_t nFirstBlockTime, const Consensus::Params& params)
{
    if (params.fPowNoRetargeting)
        return pindexLast->nBits;

    // Limit adjustment step
    int64_t nActualTimespan = pindexLast->GetBlockTime() - nFirstBlockTime;
    if (nActualTimespan < params.nPowTargetTimespan/4)
        nActualTimespan = params.nPowTargetTimespan/4;
    if (nActualTimespan > params.nPowTargetTimespan*4)
        nActualTimespan = params.nPowTargetTimespan*4;

    // Retarget
    const arith_uint256 bnPowLimit = UintToArith256(params.powLimit);
    arith_uint256 bnNew;

    // Special difficulty rule for Testnet4
    if (params.enforce_BIP94) {
        // Here we use the first block of the difficulty period. This way
        // the real difficulty is always preserved in the first block as
        // it is not allowed to use the min-difficulty exception.
        int nHeightFirst = pindexLast->nHeight - (params.DifficultyAdjustmentInterval()-1);
        const CBlockIndex* pindexFirst = pindexLast->GetAncestor(nHeightFirst);
        bnNew.SetCompact(pindexFirst->nBits);
    } else {
        bnNew.SetCompact(pindexLast->nBits);
    }

    bnNew *= nActualTimespan;
    bnNew /= params.nPowTargetTimespan;

    if (bnNew > bnPowLimit)
        bnNew = bnPowLimit;

    return bnNew.GetCompact();
}

// Check that on difficulty adjustments, the new difficulty does not increase
// or decrease beyond the permitted limits.
bool PermittedDifficultyTransition(const Consensus::Params& params, int64_t height, uint32_t old_nbits, uint32_t new_nbits)
{
    if (params.fPowAllowMinDifficultyBlocks) return true;

    // Post-LWMA the difficulty legitimately changes every block; the exact
    // value is still enforced by GetNextWorkRequired in ContextualCheckBlockHeader.
    if (params.nLwmaHeight > 0 && height >= params.nLwmaHeight) return true;

    if (height % params.DifficultyAdjustmentInterval() == 0) {
        int64_t smallest_timespan = params.nPowTargetTimespan/4;
        int64_t largest_timespan = params.nPowTargetTimespan*4;

        const arith_uint256 pow_limit = UintToArith256(params.powLimit);
        arith_uint256 observed_new_target;
        observed_new_target.SetCompact(new_nbits);

        // Calculate the largest difficulty value possible:
        arith_uint256 largest_difficulty_target;
        largest_difficulty_target.SetCompact(old_nbits);
        largest_difficulty_target *= largest_timespan;
        largest_difficulty_target /= params.nPowTargetTimespan;

        if (largest_difficulty_target > pow_limit) {
            largest_difficulty_target = pow_limit;
        }

        // Round and then compare this new calculated value to what is
        // observed.
        arith_uint256 maximum_new_target;
        maximum_new_target.SetCompact(largest_difficulty_target.GetCompact());
        if (maximum_new_target < observed_new_target) return false;

        // Calculate the smallest difficulty value possible:
        arith_uint256 smallest_difficulty_target;
        smallest_difficulty_target.SetCompact(old_nbits);
        smallest_difficulty_target *= smallest_timespan;
        smallest_difficulty_target /= params.nPowTargetTimespan;

        if (smallest_difficulty_target > pow_limit) {
            smallest_difficulty_target = pow_limit;
        }

        // Round and then compare this new calculated value to what is
        // observed.
        arith_uint256 minimum_new_target;
        minimum_new_target.SetCompact(smallest_difficulty_target.GetCompact());
        if (minimum_new_target > observed_new_target) return false;
    } else if (old_nbits != new_nbits) {
        return false;
    }
    return true;
}

// Bypasses the actual proof of work check during fuzz testing with a simplified validation checking whether
// the most significant bit of the last byte of the hash is set.
bool CheckProofOfWork(uint256 hash, unsigned int nBits, const Consensus::Params& params)
{
    if (EnableFuzzDeterminism()) return (hash.data()[31] & 0x80) == 0;
    return CheckProofOfWorkImpl(hash, nBits, params);
}

std::optional<arith_uint256> DeriveTarget(unsigned int nBits, const uint256 pow_limit)
{
    bool fNegative;
    bool fOverflow;
    arith_uint256 bnTarget;

    bnTarget.SetCompact(nBits, &fNegative, &fOverflow);

    // Check range
    if (fNegative || bnTarget == 0 || fOverflow || bnTarget > UintToArith256(pow_limit))
        return {};

    return bnTarget;
}

// Zawy LWMA-1 per-block difficulty. Averages the target over the last N blocks,
// weighting recent solvetimes more heavily, so difficulty tracks real hashrate
// within ~N blocks and the chain recovers on its own when miners come and go.
// Active from params.nLwmaHeight. For the first N blocks after the fork there is
// no full post-fork window and the pre-fork difficulty may be stuck very high,
// so we reset to the minimum (powLimit) to unstick the chain immediately; LWMA
// then climbs back to the real level over the next N blocks.
unsigned int LwmaGetNextWorkRequired(const CBlockIndex* pindexLast, const Consensus::Params& params)
{
    const int64_t T = params.nPowTargetSpacing;
    const int64_t N = params.nLwmaAveragingWindow;
    const int64_t k = N * (N + 1) * T / 2;
    const int height = pindexLast->nHeight + 1;
    const arith_uint256 powLimit = UintToArith256(params.powLimit);

    if (height < params.nLwmaHeight + N) {
        // Restart from a realistic difficulty (powLimit / nLwmaStartDifficulty),
        // never easier than diff-1, so the chain unsticks at once without
        // handing the fork-height miner a flood of near-free blocks.
        arith_uint256 startTarget = powLimit / std::max<int64_t>(1, params.nLwmaStartDifficulty);
        if (startTarget > powLimit) startTarget = powLimit;
        return startTarget.GetCompact();
    }

    arith_uint256 sumTarget(0);
    int64_t t = 0, j = 0;

    const CBlockIndex* blockPreviousTimestamp = pindexLast->GetAncestor(pindexLast->nHeight - N);
    int64_t previousTimestamp = blockPreviousTimestamp->GetBlockTime();

    for (int64_t i = pindexLast->nHeight - N + 1; i <= pindexLast->nHeight; i++) {
        const CBlockIndex* block = pindexLast->GetAncestor(i);
        int64_t thisTimestamp = (block->GetBlockTime() > previousTimestamp)
            ? block->GetBlockTime() : previousTimestamp + 1;
        int64_t solvetime = std::min<int64_t>(6 * T, thisTimestamp - previousTimestamp);
        previousTimestamp = thisTimestamp;
        j++;
        t += solvetime * j;
        arith_uint256 target;
        target.SetCompact(block->nBits);
        sumTarget += target / (k * N);   // pre-scaled to avoid 256-bit overflow
    }
    // Clamp the weighted-solvetime sum so one step can't raise difficulty > ~100x.
    if (t < k / 100) t = k / 100;
    arith_uint256 nextTarget = sumTarget * t;
    if (nextTarget > powLimit) nextTarget = powLimit;
    return nextTarget.GetCompact();
}


bool CheckProofOfWork(const CBlockHeader& block, const Consensus::Params& params)
{
    // Merge-mined block: the work lives on the parent chain, which must commit
    // this block's hash (via auxpow->check) and itself meet our nBits target.
    if (block.IsAuxpow()) {
        if (!block.auxpow) return false;
        if (!block.auxpow->check(block.GetHash(), block.GetChainId(), params)) return false;
        return CheckProofOfWork(block.auxpow->getParentBlock().GetHash(), block.nBits, params);
    }
    return CheckProofOfWork(block.GetHash(), block.nBits, params);
}

bool CheckProofOfWorkImpl(uint256 hash, unsigned int nBits, const Consensus::Params& params)
{
    auto bnTarget{DeriveTarget(nBits, params.powLimit)};
    if (!bnTarget) return false;

    // Check proof of work matches claimed amount
    if (UintToArith256(hash) > bnTarget)
        return false;

    return true;
}
