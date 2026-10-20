// Copyright (c) 2025 The Perbug developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <auxpow.h>

#include <chainparams.h>
#include <primitives/transaction.h>
#include <script/script.h>
#include <test/util/setup_common.h>
#include <uint256.h>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(auxpow_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(auxpow_check_accepts_valid_and_rejects_tampered)
{
    const auto params = CreateChainParams(*m_node.args, ChainType::REGTEST);
    const Consensus::Params& c = params->GetConsensus();
    const int chainId = c.nAuxpowChainId;

    const uint256 hashAux{"00000000000000000000000000000000000000000000000000000000beefcafe"};
    const uint256 other{"00000000000000000000000000000000000000000000000000000000deadbeef"};

    // A freshly built proof for hashAux must validate.
    auto ap = CreateAuxPow(hashAux);
    BOOST_CHECK(ap->check(hashAux, chainId, c));

    // The same proof must NOT validate for a different aux block hash.
    BOOST_CHECK(!ap->check(other, chainId, c));

    // Stripping the merged-mining commitment from the parent coinbase must fail.
    auto apStripped = CreateAuxPow(hashAux);
    CMutableTransaction cb(*apStripped->coinbaseTx);
    cb.vin[0].scriptSig = CScript();
    apStripped->coinbaseTx = MakeTransactionRef(std::move(cb));
    BOOST_CHECK(!apStripped->check(hashAux, chainId, c));

    // Corrupting the parent merkle root (so the coinbase branch no longer leads
    // to it) must fail.
    auto apBadRoot = CreateAuxPow(hashAux);
    apBadRoot->parentBlock.hashMerkleRoot = other;
    BOOST_CHECK(!apBadRoot->check(hashAux, chainId, c));

    // A coinbase not at index 0 must fail.
    auto apBadIndex = CreateAuxPow(hashAux);
    apBadIndex->nIndex = 1;
    BOOST_CHECK(!apBadIndex->check(hashAux, chainId, c));
}

BOOST_AUTO_TEST_CASE(merkle_branch_roundtrip)
{
    // An empty branch is the identity (root == leaf).
    const uint256 leaf{"0000000000000000000000000000000000000000000000000000000000000abc"};
    BOOST_CHECK(CheckMerkleBranch(leaf, {}, 0) == leaf);
}

BOOST_AUTO_TEST_SUITE_END()
