package relay

import (
	"testing"
)

func TestNewClient(t *testing.T) {
	client := NewClient(
		"wss://example.com/relay",
		"network-id",
		"network-secret",
		"public-key",
	)

	if client == nil {
		t.Fatal("NewClient returned nil")
	}

	// Check send channel buffer size
	if cap(client.sendCh) != 1000 {
		t.Errorf("sendCh capacity: got %d, want 1000", cap(client.sendCh))
	}
}

func TestJoinEndpoints(t *testing.T) {
	tests := []struct {
		name      string
		endpoints []string
		want      string
	}{
		{"empty", []string{}, ""},
		{"single", []string{"1.2.3.4:51820"}, "1.2.3.4:51820"},
		{"multiple", []string{"1.2.3.4:51820", "5.6.7.8:51820"}, "1.2.3.4:51820,5.6.7.8:51820"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := joinEndpoints(tt.endpoints)
			if got != tt.want {
				t.Errorf("joinEndpoints(): got %s, want %s", got, tt.want)
			}
		})
	}
}

func TestSplitEndpoints(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{"empty", "", nil},
		{"single", "1.2.3.4:51820", []string{"1.2.3.4:51820"}},
		{"multiple", "1.2.3.4:51820,5.6.7.8:51820", []string{"1.2.3.4:51820", "5.6.7.8:51820"}},
		{"with empty", "1.2.3.4:51820,,5.6.7.8:51820", []string{"1.2.3.4:51820", "5.6.7.8:51820"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := splitEndpoints(tt.input)
			if len(got) != len(tt.want) {
				t.Errorf("splitEndpoints() length: got %d, want %d", len(got), len(tt.want))
				return
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("splitEndpoints()[%d]: got %s, want %s", i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestIsConnectedDefault(t *testing.T) {
	client := NewClient("wss://example.com", "net", "secret", "pubkey")

	// Not connected by default
	if client.IsConnected() {
		t.Error("Client should not be connected by default")
	}
}

func TestSetHandlers(t *testing.T) {
	client := NewClient("wss://example.com", "net", "secret", "pubkey")

	// Set data handler
	client.SetDataHandler(func(from string, data []byte) {
		// callback placeholder
	})

	if client.onData == nil {
		t.Error("onData should be set")
	}

	// Set punch handler
	client.SetPunchHandler(func(from string, endpoints []string) {
		// callback placeholder
	})

	if client.onPunch == nil {
		t.Error("onPunch should be set")
	}

	// Set disconnect handler
	client.SetDisconnectHandler(func() {
		// callback placeholder
	})

	if client.onDisconnect == nil {
		t.Error("onDisconnect should be set")
	}
}

func TestEnableAutoReconnect(t *testing.T) {
	client := NewClient("wss://example.com", "net", "secret", "pubkey")

	// Disabled by default
	if client.autoReconnect {
		t.Error("autoReconnect should be false by default")
	}

	// Enable
	client.EnableAutoReconnect(true)
	if !client.autoReconnect {
		t.Error("autoReconnect should be true after enable")
	}

	// Disable
	client.EnableAutoReconnect(false)
	if client.autoReconnect {
		t.Error("autoReconnect should be false after disable")
	}
}

func TestMessageTypes(t *testing.T) {
	// Verify message type constants
	tests := []struct {
		msgType MessageType
		want    string
	}{
		{MsgTypeAuth, "auth"},
		{MsgTypeData, "data"},
		{MsgTypePing, "ping"},
		{MsgTypePong, "pong"},
		{MsgTypeError, "error"},
		{MsgTypePunch, "punch"},
		{MsgTypePunchAck, "punch_ack"},
	}

	for _, tt := range tests {
		if string(tt.msgType) != tt.want {
			t.Errorf("MessageType: got %s, want %s", tt.msgType, tt.want)
		}
	}
}

func TestRelayMessageStruct(t *testing.T) {
	msg := RelayMessage{
		Type:          MsgTypeData,
		NetworkID:     "net-123",
		NetworkSecret: "secret",
		PublicKey:     "pubkey",
		To:            "recipient",
		From:          "sender",
		Payload:       "SGVsbG8=", // base64 "Hello"
		Endpoints:     "1.2.3.4:51820,5.6.7.8:51820",
	}

	if msg.Type != MsgTypeData {
		t.Errorf("Type: got %s, want data", msg.Type)
	}
	if msg.To != "recipient" {
		t.Errorf("To: got %s, want recipient", msg.To)
	}
}

func TestRequestPunchNotConnected(t *testing.T) {
	client := NewClient("wss://example.com", "net", "secret", "pubkey")

	err := client.RequestPunch("target", []string{"1.2.3.4:51820"})
	if err == nil {
		t.Error("RequestPunch should fail when not connected")
	}
}

func TestSendNotConnected(t *testing.T) {
	client := NewClient("wss://example.com", "net", "secret", "pubkey")

	err := client.Send("target", []byte("hello"))
	if err == nil {
		t.Error("Send should fail when not connected")
	}
}
