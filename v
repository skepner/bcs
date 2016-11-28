#! /bin/bash
echo $(date) $0 "$@" >>/tmp/bcsv.log

if [ $# -eq 1 ]; then
    N=$($HOME/bin/bcs -cd "$1")
    if [ -n "$N" ]; then
        trap "rm -f '$N'" EXIT
        $HOME/bin/e_open "$N" 2>/dev/null
        sleep 3
    fi
elif [ $# -eq 2 ]; then
    if [ -d "$2" ]; then
        $HOME/bin/bcs -cd "$1" "$2"/$(basename "$1" .aes)
    else
        $HOME/bin/bcs -cd "$1" "$2"
    fi
else
    echo Usage: $0 "<filename.aes> [<output>]" >&2
    exit 1
fi
