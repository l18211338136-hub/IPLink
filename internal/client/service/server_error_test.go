package service

import (
	"strings"
	"testing"

	"iplink/internal/protocol/codec"
	"iplink/internal/protocol/message"
	"iplink/pkg/protocol"
)

func TestServerErrorFromFrame(t *testing.T) {
	t.Run("error frame converts to ServerError", func(t *testing.T) {
		f, err := codec.EncodeJSON(protocol.MsgError, 7, 1, message.ErrorMsg{
			Code:    protocol.ErrPeerNotFound,
			Message: "target peer not online: peer-x",
		})
		if err != nil {
			t.Fatal(err)
		}
		got := serverErrorFromFrame(f)
		se, ok := got.(*ServerError)
		if !ok {
			t.Fatalf("got %T, want *ServerError", got)
		}
		if se.Code != protocol.ErrPeerNotFound {
			t.Fatalf("code = %d, want %d", se.Code, protocol.ErrPeerNotFound)
		}
		if se.Message != "target peer not online: peer-x" {
			t.Fatalf("message = %q", se.Message)
		}
		if !strings.Contains(se.Error(), "target peer not online") || !strings.Contains(se.Error(), "4001") {
			t.Fatalf("Error() = %q, want code and message", se.Error())
		}
	})

	t.Run("non-error frame returns nil", func(t *testing.T) {
		f, err := codec.EncodeJSON(protocol.MsgPeerListResp, 1, 1, message.PeerListResp{})
		if err != nil {
			t.Fatal(err)
		}
		if got := serverErrorFromFrame(f); got != nil {
			t.Fatalf("got %v, want nil", got)
		}
	})
}
