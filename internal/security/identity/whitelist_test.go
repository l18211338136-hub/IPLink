package identity

import "testing"

func TestTargetValidator(t *testing.T) {
	v, err := NewTargetValidator(nil)
	if err != nil {
		t.Fatalf("NewTargetValidator default: %v", err)
	}
	if err := v.Allow("127.0.0.1:8080"); err != nil {
		t.Fatalf("expected loopback to be allowed: %v", err)
	}
	if err := v.Allow("192.168.1.10:22"); err == nil {
		t.Fatal("expected non-loopback to be denied by default policy")
	}

	cidrVal, err := NewTargetValidator([]string{"10.0.0.0/24:80", "127.0.0.1:*"})
	if err != nil {
		t.Fatalf("NewTargetValidator CIDR: %v", err)
	}
	if err := cidrVal.Allow("10.0.0.42:80"); err != nil {
		t.Fatalf("expected CIDR match: %v", err)
	}
	if err := cidrVal.Allow("10.0.0.42:81"); err == nil {
		t.Fatal("expected port mismatch to be denied")
	}
}
