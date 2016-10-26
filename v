#! /bin/bash
if [ $# -ne 1 ]; then
    echo Usage: $0 "<filename.aes>" >&2
    exit 1
fi

N=$(bcs -cd "$1")
if [ -n "$N" ]; then
    trap "rm -f '$N'" EXIT
    e_open "$N" 2>/dev/null
    sleep 3
fi
