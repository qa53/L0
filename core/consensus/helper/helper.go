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

package helper

import (
	"github.com/bocheninc/L0/core/consensus"
	"github.com/bocheninc/L0/core/types"
)

// NewStack Create Stack instance
func NewStack() *Stack {
	return &Stack{}
}

// Stack Implenment consensus.IStack
type Stack struct {
}

// GetBlockchainInfo Implenment consensus.IStack
func (stack *Stack) GetBlockchainInfo() *consensus.BlockchainInfo {
	return &consensus.BlockchainInfo{}
}

// VerifyTxsInConsensus Implenment consensus.IStack
func (stack *Stack) VerifyTxsInConsensus(txs []*types.Transaction, primary bool) bool {
	return true
}

// FetchGroupingTxsInTxPool  Implenment consensus.IStack
func (stack *Stack) FetchGroupingTxsInTxPool(groupingNum, maxSizeInGrouping int) []types.Transactions {
	return nil
}
