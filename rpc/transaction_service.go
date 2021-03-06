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

package rpc

import (
	"errors"
	"math/big"
	"time"

	"github.com/bocheninc/L0/components/crypto"
	"github.com/bocheninc/L0/components/utils"
	"github.com/bocheninc/L0/core/accounts"
	"github.com/bocheninc/L0/core/coordinate"
	"github.com/bocheninc/L0/core/params"
	"github.com/bocheninc/L0/core/types"
)

type IBroadcast interface {
	Relay(inv types.IInventory)
	QueryContract(tx *types.Transaction) ([]byte, error)
}

type Transaction struct {
	pmHander IBroadcast
}

type TransactionCreateArgs struct {
	FromChain string
	ToChain   string
	Recipient string
	Nonce     uint32
	Amount    int64
	Fee       int64
	TxType    uint32
	PayLoad   *PayLoad
}

type PayLoad struct {
	ContractCode   string
	ContractAddr   string
	ContractParams []string
}

type ContractQueryArgs struct {
	ContractAddr   string
	ContractParams []string
}

func NewTransaction(pmHandler IBroadcast) *Transaction {
	return &Transaction{pmHander: pmHandler}
}

func (t *Transaction) Create(args *TransactionCreateArgs, reply *string) error {
	fromChain := coordinate.HexToChainCoordinate(args.FromChain)
	toChain := coordinate.HexToChainCoordinate(args.ToChain)
	nonce := args.Nonce
	recipient := accounts.HexToAddress(args.Recipient)
	sender := accounts.Address{}
	amount := big.NewInt(args.Amount)
	fee := big.NewInt(args.Fee)
	tx := types.NewTransaction(fromChain, toChain, args.TxType, nonce, sender, recipient, amount, fee, utils.CurrentTimestamp())

	if args.PayLoad != nil {
		contractSpec := new(types.ContractSpec)
		contractSpec.ContractCode = utils.HexToBytes(args.PayLoad.ContractCode)
		contractSpec.ContractAddr = utils.HexToBytes(args.PayLoad.ContractAddr)
		contractSpec.ContractParams = args.PayLoad.ContractParams
		tx.WithPayload(utils.Serialize(contractSpec))
	}
	*reply = utils.BytesToHex(tx.Serialize())
	return nil
}

type BroadcastReply struct {
	ContractAddr    *string     `json:"contractAddr"`
	TransactionHash crypto.Hash `json:"transactionHash"`
}

func (t *Transaction) Broadcast(txHex string, reply *BroadcastReply) error {
	if len(txHex) < 1 {
		return errors.New("Invalid Params: len(txSerializeData) must be >0 ")
	}

	tx := new(types.Transaction)
	tx.Deserialize(utils.HexToBytes(txHex))

	if tx.Amount().Sign() < 0 {
		return errors.New("Invalid Amount in Tx, Amount must be >0")
	}

	if tx.Fee() == nil || tx.Fee().Sign() < 0 {
		return errors.New("Invalid Fee in Tx, Fee must be >0")
	}

	_, err := tx.Verfiy()
	if err != nil {
		return errors.New("Invalid Tx, varify the signature of Tx failed")
	}

	t.pmHander.Relay(tx)

	if len(tx.Payload) != 0 {
		contractSpec := new(types.ContractSpec)
		utils.Deserialize(tx.Payload, contractSpec)
		contractAddr := utils.BytesToHex(contractSpec.ContractAddr)
		*reply = BroadcastReply{ContractAddr: &contractAddr, TransactionHash: tx.Hash()}
		return nil
	}
	*reply = BroadcastReply{TransactionHash: tx.Hash()}

	return nil
}

//Query contract query
func (t *Transaction) Query(args *ContractQueryArgs, reply *string) error {

	if len(args.ContractAddr) == 0 {
		return errors.New("contract address is illegal")
	}

	if args.ContractAddr[0:2] == "0x" {
		args.ContractAddr = args.ContractAddr[2:]
	}
	contractAddress := utils.HexToBytes(args.ContractAddr)
	if len(contractAddress) != 20 && len(contractAddress) != 22 {
		return errors.New("contract address is illegal")
	}

	contractSpec := new(types.ContractSpec)
	contractSpec.ContractCode = []byte("")
	contractSpec.ContractAddr = contractAddress
	contractSpec.ContractParams = args.ContractParams
	tx := types.NewTransaction(
		coordinate.NewChainCoordinate(params.ChainID),
		coordinate.NewChainCoordinate(params.ChainID),
		types.TypeContractQuery,
		uint32(0),
		accounts.Address{},
		accounts.NewAddress(contractSpec.ContractAddr),
		big.NewInt(0),
		big.NewInt(0),
		uint32(time.Now().Unix()),
	)
	tx.Payload = utils.Serialize(contractSpec)

	result, err := t.pmHander.QueryContract(tx)
	if err != nil {
		return err
	}

	*reply = string(result)

	return nil

}
