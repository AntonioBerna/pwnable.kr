#!/bin/sh

if [ -z "$1" ]; then
    echo "Usage: $0 <game-name>"
    exit 1
fi

connect_to_game() {
    local game_name=$1
    local user_name=$2
    local port=$3

    echo "Connecting to $game_name"
    ssh ${user_name}@pwnable.kr -p${port}
}

case "$1" in
    fd)
        connect_to_game "fd" "fd" 2222
        ;;
    col)
        connect_to_game "col" "col" 2222
        ;;

    # ... add more games here ...
    
    *)
        echo "Error: unknown game '$1'"
        exit 1
        ;;
esac
