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

package noops

import (
	"time"

	"encoding/json"

	"github.com/bocheninc/L0/components/log"
	"github.com/bocheninc/L0/core/consensus"
)

// NewNoops Create Noops
func NewNoops(options *Options, stack consensus.IStack) *Noops {
	noops := &Noops{
		options: options,
		stack:   stack,
	}
	if noops.options.CommitTxChanSize < options.BlockSize {
		noops.options.CommitTxChanSize = options.BlockSize
	}
	noops.committedTxsChan = make(chan *consensus.OutputTxs, noops.options.CommittedTxsChanSize)
	noops.broadcastChan = make(chan *consensus.BroadcastConsensus, noops.options.BroadcastChanSize)
	noops.blockTimer = time.NewTimer(noops.options.BlockInterval)
	noops.blockTimer.Stop()
	noops.seqNo = noops.stack.GetBlockchainInfo().LastSeqNo
	noops.height = noops.stack.GetBlockchainInfo().Height
	return noops
}

// Noops Define Noops
type Noops struct {
	options          *Options
	stack            consensus.IStack
	committedTxsChan chan *consensus.OutputTxs
	broadcastChan    chan *consensus.BroadcastConsensus
	blockTimer       *time.Timer
	seqNo            uint64
	height           uint32
	exit             chan struct{}
}

func (noops *Noops) String() string {
	bytes, _ := json.Marshal(noops.options)
	return string(bytes)
}

// IsRunning Noops consenter serverice already started
func (noops *Noops) IsRunning() bool {
	return noops.exit != nil
}

// Start Start consenter serverice of Noops
func (noops *Noops) Start() {
	if noops.IsRunning() {
		return
	}
	noops.exit = make(chan struct{})
	noops.blockTimer = time.NewTimer(noops.options.BlockInterval)
	for {
		select {
		case <-noops.exit:
			noops.exit = nil
			return
		case <-noops.blockTimer.C:
			noops.processBlock()
		}
	}
}

func (noops *Noops) processBlock() {
	noops.blockTimer.Stop()

	txss := noops.stack.FetchGroupingTxsInTxPool(noops.options.BlockSize, 1)
	if len(txss) != 2 {
		return
	}
	txs := txss[1]
	pass := noops.stack.VerifyTxsInConsensus(txs, true)
	if !pass {
		return
	}
	noops.seqNo++
	log.Infof("Noops write block (%d transactions)  %d", len(txs), noops.seqNo)
	outputs := []*consensus.CommittedTxs{}
	outputs = append(outputs, &consensus.CommittedTxs{Skip: false, Time: uint32(time.Now().Unix()), Transactions: txs, SeqNo: noops.seqNo})
	noops.height++
	noops.committedTxsChan <- &consensus.OutputTxs{Outputs: outputs, Height: noops.height}

	noops.blockTimer = time.NewTimer(noops.options.BlockInterval)
}

// Stop Stop consenter serverice of Noops
func (noops *Noops) Stop() {
	if noops.IsRunning() {
		close(noops.exit)
	}
}

// Quorum num of quorum
func (noops *Noops) Quorum() int {
	return 1
}

// RecvConsensus Receive consensus data
func (noops *Noops) RecvConsensus(payload []byte) {
	//noops.broadcastChan<-
}

// BroadcastConsensusChannel Broadcast consensus data
func (noops *Noops) BroadcastConsensusChannel() <-chan *consensus.BroadcastConsensus {
	return noops.broadcastChan
}

// CommittedTxsChannel Commit block data
func (noops *Noops) CommittedTxsChannel() <-chan *consensus.OutputTxs {
	return noops.committedTxsChan
}
