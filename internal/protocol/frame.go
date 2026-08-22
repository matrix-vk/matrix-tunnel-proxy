// Package protocol defines the encrypted tunnel's application-level framing.
package protocol

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"time"
)

const (
	Version        byte = 1
	headerSize          = 12
	MaxPayloadSize      = 1 << 20 // 1 MiB; larger data is split into frames.
)

type Type byte

const (
	Hello Type = iota + 1
	Config
	ConfigAck
	Ping
	Pong
	OpenStream
	Data
	CloseStream
	Revoke
	Error
	OpenDatagram
	HelloAck
)

type Frame struct {
	Type     Type
	Flags    uint16
	StreamID uint32
	Payload  []byte
}

// WriteFrameWithDeadline prevents a half-open or back-pressured tunnel from
// blocking all future heartbeat and reconnect activity indefinitely.
func WriteFrameWithDeadline(connection net.Conn, frame Frame, timeout time.Duration) error {
	if timeout <= 0 {
		return frame.Write(connection)
	}
	if err := connection.SetWriteDeadline(time.Now().Add(timeout)); err != nil {
		return err
	}
	err := frame.Write(connection)
	clearErr := connection.SetWriteDeadline(time.Time{})
	if err != nil {
		return err
	}
	return clearErr
}

func (frame Frame) Write(writer io.Writer) error {
	if len(frame.Payload) > MaxPayloadSize {
		return fmt.Errorf("payload exceeds %d bytes", MaxPayloadSize)
	}
	header := make([]byte, headerSize)
	header[0] = Version
	header[1] = byte(frame.Type)
	binary.BigEndian.PutUint16(header[2:4], frame.Flags)
	binary.BigEndian.PutUint32(header[4:8], frame.StreamID)
	binary.BigEndian.PutUint32(header[8:12], uint32(len(frame.Payload)))
	if _, err := writer.Write(header); err != nil {
		return err
	}
	_, err := writer.Write(frame.Payload)
	return err
}

func ReadFrame(reader io.Reader) (Frame, error) {
	header := make([]byte, headerSize)
	if _, err := io.ReadFull(reader, header); err != nil {
		return Frame{}, err
	}
	if header[0] != Version {
		return Frame{}, fmt.Errorf("unsupported protocol version %d", header[0])
	}
	messageType := Type(header[1])
	if !messageType.valid() {
		return Frame{}, fmt.Errorf("unknown message type %d", messageType)
	}
	payloadLength := binary.BigEndian.Uint32(header[8:12])
	if payloadLength > MaxPayloadSize {
		return Frame{}, errors.New("payload exceeds maximum frame size")
	}
	payload := make([]byte, payloadLength)
	if _, err := io.ReadFull(reader, payload); err != nil {
		return Frame{}, err
	}
	return Frame{Type: messageType, Flags: binary.BigEndian.Uint16(header[2:4]), StreamID: binary.BigEndian.Uint32(header[4:8]), Payload: payload}, nil
}

func (messageType Type) valid() bool {
	return messageType >= Hello && messageType <= HelloAck
}
