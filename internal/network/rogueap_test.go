package network

import (
	"testing"
)

func TestDefaultRogueAPConfig(t *testing.T) {
	cfg := DefaultRogueAPConfig()

	if cfg.SSID != "Free_WiFi" {
		t.Errorf("expected SSID Free_WiFi, got %s", cfg.SSID)
	}
	if cfg.Channel != 6 {
		t.Errorf("expected channel 6, got %d", cfg.Channel)
	}
	if cfg.GatewayIP != "192.168.4.1" {
		t.Errorf("expected gateway 192.168.4.1, got %s", cfg.GatewayIP)
	}
	if cfg.Subnet != "192.168.4.0/24" {
		t.Errorf("expected subnet 192.168.4.0/24, got %s", cfg.Subnet)
	}
	if cfg.DHCPStart != "192.168.4.10" {
		t.Errorf("expected DHCP start 192.168.4.10, got %s", cfg.DHCPStart)
	}
	if cfg.DHCPEnd != "192.168.4.250" {
		t.Errorf("expected DHCP end 192.168.4.250, got %s", cfg.DHCPEnd)
	}
	if cfg.Band != "2g" {
		t.Errorf("expected band 2g, got %s", cfg.Band)
	}
}

func TestCheckDependencies(t *testing.T) {
	// checkDependencies should not panic even if tools are missing
	err := checkDependencies()
	// We can't assert success since tools may not be installed in CI
	// Just verify it doesn't panic
	_ = err
}

func TestRogueAPConfigDefaults(t *testing.T) {
	cfg := RogueAPConfig{
		SSID:    "TestNet",
		Password: "secret",
		Channel: 11,
	}

	if cfg.SSID != "TestNet" {
		t.Errorf("expected SSID TestNet, got %s", cfg.SSID)
	}
	if cfg.Password != "secret" {
		t.Errorf("expected Password secret, got %s", cfg.Password)
	}
	if cfg.Channel != 11 {
		t.Errorf("expected Channel 11, got %d", cfg.Channel)
	}
}
