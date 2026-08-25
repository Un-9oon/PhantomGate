#compdef phantomgate

_phantomgate() {
    local -a commands
    _arguments \
        '--domain[Phishing domain name]:domain:_domains' \
        '--phishlet[Phishlet to activate]:phishlet:_files -g "*.yml"' \
        '--phishlet-dir[Directory containing phishlet YAML files]:directory:_directories' \
        '--config[Path to config file]:file:_files' \
        '--listen[IP to bind listeners on]:ip_address' \
        '--https-port[HTTPS listener port]:port' \
        '--http-port[HTTP redirect listener port]:port' \
        '--admin-port[Operator dashboard port]:port' \
        '--admin-pass[Operator dashboard password]:password' \
        '--cert[TLS certificate file (PEM)]:file:_files -g "*.pem"' \
        '--key[TLS private key file (PEM)]:file:_files -g "*.pem"' \
        '--store[Path to data store file]:file:_files' \
        '--list[List available phishlets and exit]' \
        '--lure[Create a lure URL for the specified victim info]:info' \
        '--intercept[Enable DNS interception mode]' \
        '--wizard[Launch interactive wizard for LAN interception setup]' \
        '--iface[Network interface for interception]:interface:_net_interfaces' \
        '--gateway[Gateway IP for ARP poisoning]:ip_address' \
        '--victim-ip[Comma-separated victim IPs]:ips' \
        '--poison-domain[Comma-separated domains to poison]:domains' \
        '--rogue-ap[Create a rogue WiFi access point]' \
        '--ap-ssid[SSID for the rogue AP]:ssid' \
        '--ap-pass[WPA2 password for rogue AP]:password' \
        '--ap-channel[WiFi channel for rogue AP]:channel' \
        '--ap-iface[WiFi interface for AP]:interface:_net_interfaces' \
        '--use-ca[Generate dynamic TLS certificates signed by a local CA]' \
        '--captive-portal[Enable captive portal for CA cert distribution]' \
        '--version[Print version and exit]' \
        '--generate-completions[Generate shell completion script]:shell:(bash zsh fish)' \
        '--dry-run[Test configuration without binding ports]' \
        '--json-log[Enable JSON structured logging]' \
        '--help[Show help]' && return 0
}

_phantomgate "$@"
