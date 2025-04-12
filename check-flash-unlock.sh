#!/bin/bash

LOCK_FILE="/tmp/flash_auth_unlocked"
TTY=$(tty)

# Для всех TTY кроме tty2
if [[ "$TTY" != /dev/tty2 ]]; then
    if [ ! -f "$LOCK_FILE" ]; then
        echo "ОШИБКА: Сначала выполните разблокировку в tty2!" >&2
        logger -t flash_auth "Попытка входа без разблокировки на tty2"
        exit 1
    fi
    
    LOCK_AGE=$(($(date +%s) - $(stat -c %Y "$LOCK_FILE" 2>/dev/null || echo 0)))
    if [ $LOCK_AGE -gt 300 ]; then
        echo "ОШИБКА: Сессия разблокировки истекла (5 минут)" >&2
        rm -f "$LOCK_FILE"
        logger -t flash_auth "Время разблокировки истекло"
        exit 1
    fi
fi

exit 0
