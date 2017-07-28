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

package p2p

import (
	"fmt"
	"io"

	"github.com/bocheninc/L0/components/crypto"
	"github.com/bocheninc/L0/components/utils"
)

// Msg on network
type Msg struct {
	// Magic 	uint32
	Cmd      uint8
	Payload  []byte
	CheckSum [4]byte
}

// SecMsg on network
type SecMsg struct {
	Cert  []byte
	Nonce uint32
}

const (
	pingMsg = iota + 1
	pongMsg
	handshakeMsg
	handshakeAckMsg
	getPeersMsg
	peersMsg
)

var (
	msgMap = map[uint8]string{
		pingMsg:     "ping",
		pongMsg:     "pong",
		getPeersMsg: "getpeers",
		peersMsg:    "peers",
	}

	maxMsgSize  uint64 = 1024 * 1024 * 100
	nilCheckSum        = crypto.Sha256(nil)
)

// MsgReadWriter is the interface that groups the p2p message Read and Write methods.
type MsgReadWriter interface {
	MsgReader
	MsgWriter
}

// MsgReader is the interface p2p message Read  methods.
type MsgReader interface {
	ReadMsg() (Msg, error)
}

// MsgWriter is the interface that the p2p message Write methods.
type MsgWriter interface {
	WriteMsg(msg Msg) (int, error)
}

// Serialize serializes message to bytes
func (m *Msg) Serialize() []byte {
	return utils.Serialize(*m)
}

// Deserialize deserialize bytes to message
func (m *Msg) Deserialize(data []byte) {
	utils.Deserialize(data, m)
}

// String returns the string format of the msg
func (m *Msg) String() string {
	return fmt.Sprintf("msg cmd = %d; checksum=%0x", m.Cmd, m.CheckSum)
}

// Read decodes message from the reader
func (m *Msg) read(r io.Reader) (int, error) {
	l, err := utils.ReadVarInt(r)
	if err != nil {
		return 0, err
	}

	if l > maxMsgSize {
		return 0, fmt.Errorf("message too big")
	}

	buf := make([]byte, l)
	n, err := io.ReadFull(r, buf)

	if n != int(l) {
		return n, err
	}
	m.Deserialize(buf)
	return n, err
}

// write encodes msg to the writer
func (m *Msg) write(w io.Writer) (int, error) {
	data := m.Serialize()
	data = append(utils.VarInt(uint64(len(data))), data...)
	return w.Write(data)
}

// NewMsg New Message used by msgType chainId and payload
func NewMsg(msgType uint8, payload []byte) *Msg {
	msg := &Msg{
		Cmd:     msgType,
		Payload: payload,
	}
	h := crypto.Sha256(payload)
	copy(msg.CheckSum[:], h[0:4])
	return msg
}

// SendMessage sends message to other node
func SendMessage(w io.Writer, msg *Msg) (int, error) {
	return msg.write(w)
}

// NewSecMsg new sec message used by cert and nonce
func NewSecMsg(cert []byte, nonce uint32) *SecMsg {
	secMsg := &SecMsg{
		Cert:  cert,
		Nonce: nonce,
	}
	return secMsg
}

// Serialize serializes sec message to bytes
func (m *SecMsg) Serialize() []byte {
	return utils.Serialize(*m)
}

// Deserialize deserialize bytes to sec message
func (m *SecMsg) Deserialize(data []byte) {
	utils.Deserialize(data, m)
}

// Read decodes sec message from the reader
func (m *SecMsg) read(r io.Reader) (int, error) {
	l, err := utils.ReadVarInt(r)
	if err != nil {
		return 0, err
	}

	if l > maxMsgSize {
		return 0, fmt.Errorf("message too big")
	}

	buf := make([]byte, l)
	n, err := io.ReadFull(r, buf)

	if n != int(l) {
		return n, err
	}
	m.Deserialize(buf)
	return n, err
}

// write encodes sec msg to the writer
func (m *SecMsg) write(w io.Writer) (int, error) {
	data := m.Serialize()
	data = append(utils.VarInt(uint64(len(data))), data...)
	return w.Write(data)
}

// SendSecMessage sends sec message to other node
func SendSecMessage(w io.Writer, secMsg *SecMsg) (int, error) {
	return secMsg.write(w)
}

// SendSignMessage sends sign to other node
func SendSign(w io.Writer, sign []byte) (int, error) {
	sign = append(utils.VarInt(uint64(len(sign))), sign...)
	return w.Write(sign)
}

// RecvSign receives sign from other node
func RecvSign(r io.Reader) ([]byte, int, error) {
	l, err := utils.ReadVarInt(r)
	if err != nil {
		return nil, 0, err
	}

	if l > maxMsgSize {
		return nil, 0, fmt.Errorf("message too big")
	}

	buf := make([]byte, l)
	n, err := io.ReadFull(r, buf)

	return buf, n, err
}
