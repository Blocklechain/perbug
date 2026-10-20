// Copyright (c) 2014-2024 Daniel Kraft
// Copyright (c) 2025 The Perbug developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <primitives/pureheader.h>

#include <hash.h>

uint256 CPureBlockHeader::GetHash() const
{
    return (HashWriter{} << *this).GetHash();
}
