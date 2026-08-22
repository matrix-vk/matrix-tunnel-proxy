package protocol

import (
	"bytes"
	"net"
	"testing"
	"time"
)

func TestFrameRoundTrip(t *testing.T) {
	for _, messageType := range []Type{HelloAck, OpenStream, OpenDatagram} {
		want := Frame{Type: messageType, Flags: 1, StreamID: 42, Payload: []byte("mapping=mapping_01")}
		var buffer bytes.Buffer
		if err := want.Write(&buffer); err != nil {
			t.Fatalf("write frame: %v", err)
		}
		got, err := ReadFrame(&buffer)
		if err != nil {
			t.Fatalf("read frame: %v", err)
		}
		if got.Type != want.Type || got.Flags != want.Flags || got.StreamID != want.StreamID || !bytes.Equal(got.Payload, want.Payload) {
			t.Fatalf("unexpected frame: %#v", got)
		}
	}
}

func TestWriteFrameWithDeadlineUnblocksStalledTunnel(t *testing.T) {
	writer, reader := net.Pipe()
	defer writer.Close()
	defer reader.Close()
	started := time.Now()
	err := WriteFrameWithDeadline(writer, Frame{Type: Ping}, 25*time.Millisecond)
	if err == nil {
		t.Fatal("stalled tunnel write did not time out")
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("stalled tunnel write took %s", elapsed)
	}
}
