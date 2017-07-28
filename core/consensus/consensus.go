// Copyright (C) 2017, Beijing Bochen Technology Co.,Ltd.  All rights reserved.
//
// This file is part of L0
//
// The L0 is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The L0 is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package consensus

import "github.com/bocheninc/L0/core/types"

//BroadcastConsensus Define consensus data for broadcast
type BroadcastConsensus struct {
	To      string
	Payload []byte
}

//CommittedTxs Consensus output object
type CommittedTxs struct {
	Skip         bool
	IsLocalChain bool
	SeqNo        uint64
	Time         uint32
	Transactions []*types.Transaction
}

// OutputTxs Consensus output object
type OutputTxs struct {
	Outputs []*CommittedTxs
	Height  uint32
}

// Consenter Interface for plugin consenser
type Consenter interface {
	Start()
	Stop()
	Quorum() int
	RecvConsensus([]byte)
	BroadcastConsensusChannel() <-chan *BroadcastConsensus
	CommittedTxsChannel() <-chan *OutputTxs
}

// ITxPool Interface for tx containter, input
type ITxPool interface {
	FetchGroupingTxsInTxPool(groupingNum, maxSizeInGrouping int) []types.Transactions
}

// BlockchainInfo information of block chain
type BlockchainInfo struct {
	LastSeqNo uint64
	Height    uint32
}

// IStack Interface for other function for plugin consenser
type IStack interface {
	VerifyTxsInConsensus(txs []*types.Transaction, primary bool) bool
	GetBlockchainInfo() *BlockchainInfo
	ITxPool
}
