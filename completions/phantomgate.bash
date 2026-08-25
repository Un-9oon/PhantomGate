# PhantomGate bash completion
_phantomgate() {
    local cur prev opts
    COMPREPLY=()
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"

    opts="--domain --phishlet --phishlet-dir --config --listen --https-port --http-port --admin-port --admin-pass --cert --key --store --list --lure --intercept --wizard --iface --gateway --victim-ip --poison-domain --rogue-ap --ap-ssid --ap-pass --ap-channel --ap-iface --use-ca --captive-portal --version --generate-completions --dry-run --json-log --help"

    if [[ ${cur} == -* ]]; then
        COMPREPLY=( $(compgen -W "${opts}" -- ${cur}) )
        return 0
    fi

    case "${prev}" in
        --phishlet)
            local phishlets=$(ls /usr/share/phantomgate/phishlets/*.yml 2>/dev/null | xargs -I{} basename {} .yml | tr '\n' ' ')
            COMPREPLY=( $(compgen -W "${phishlets}" -- ${cur}) )
            return 0
            ;;
        --phishlet-dir)
            COMPREPLY=( $(compgen -d -- ${cur}) )
            return 0
            ;;
        --config)
            COMPREPLY=( $(compgen -f -- ${cur}) )
            return 0
            ;;
        --cert|--key|--store)
            COMPREPLY=( $(compgen -f -- ${cur}) )
            return 0
            ;;
        --iface)
            local ifaces=$(ip -o link show | awk -F': ' '{print $2}' | tr '\n' ' ')
            COMPREPLY=( $(compgen -W "${ifaces}" -- ${cur}) )
            return 0
            ;;
    esac
}

complete -F _phantomgate phantomgate
