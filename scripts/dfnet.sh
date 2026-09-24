#!/usr/bin/env bash
# Compatibility syntax only: all operations run through the Rust backend.
set -euo pipefail

if [[ "${1:-}" == "mac-restore" ]]; then
    shift
    exec dfnet restore "$@"
fi

# Older df-net examples used positional hotspot configuration.
if [[ "${1:-}" == "hotspot" && "${2:-}" == "start" && -n "${3:-}" && "${3:-}" != -* ]]; then
    shift 2
    args=(hotspot start --iface "$1")
    shift
    if [[ $# -gt 0 && "$1" != -* ]]; then
        args+=(--ssid "$1")
        shift
    fi
    if [[ $# -gt 0 && "$1" != -* ]]; then
        args+=(--password "$1")
        shift
    fi
    exec dfnet "${args[@]}" "$@"
fi

if [[ "${1:-}" == "hotspot" && "${2:-}" == "stop" && -n "${3:-}" && "${3:-}" != -* ]]; then
    shift 2
    iface="$1"
    shift
    exec dfnet hotspot stop --iface "$iface" "$@"
fi

if [[ "${1:-}" == "route" && -n "${3:-}" && "${3:-}" != -* ]]; then
    action="$2"
    ap="$3"
    shift 3
    args=(route "$action" --ap "$ap")
    if [[ $# -gt 0 && "$1" != -* ]]; then
        args+=(--uplink "$1")
        shift
    fi
    exec dfnet "${args[@]}" "$@"
fi

exec dfnet "$@"
