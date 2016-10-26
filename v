#! /bin/bash
echo $(date) $0 "$@" >>/tmp/bcsv.log

if [ $# -ne 1 ]; then
    echo Usage: $0 "<filename.aes>" >&2
    exit 1
fi

N=$($HOME/bin/bcs -cd "$1")
if [ -n "$N" ]; then
    trap "rm -f '$N'" EXIT
    $HOME/bin/e_open "$N" 2>/dev/null
    sleep 3
fi
