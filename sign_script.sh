#!/bin/bash

CHALLENGE_FILE="$1"
SIGNATURE_FILE="$2"
PRIVATE_KEY="/media/user/AUTH_FLASH/auth_private.key"
LOG="/var/log/flash_auth.log"

# Ждём появления challenge (макс. 5 секунд)
for i in {1..5}; do
    if [ -f "$CHALLENGE_FILE" ]; then
        break
    fi
    sleep 1
done

if [ ! -f "$CHALLENGE_FILE" ]; then
    echo "[$(date)] Ошибка: файл $CHALLENGE_FILE не найден" >> "$LOG"
    exit 1
fi

if [ ! -f "$PRIVATE_KEY" ]; then
    echo "[$(date)] Ошибка: приватный ключ не найден" >> "$LOG"
    exit 1
fi

# Определяем способ ввода пароля
if [ -n "$DISPLAY" ]; then
    PASSWORD=$(zenity --entry --title="Аутентификация" --text="Введите пароль:" --hide-text 2>/dev/null)
else
    echo "Введите пароль для аутентификации: " > /dev/tty
    stty -echo
    read -r PASSWORD < /dev/tty
    stty echo
    echo "" > /dev/tty
fi

if [ -z "$PASSWORD" ]; then
    echo "[$(date)] Отменено пользователем" >> "$LOG"
    exit 1
fi

# Подписываем challenge
if ! printf "%s" "$PASSWORD" | openssl pkeyutl -sign \
    -inkey "$PRIVATE_KEY" \
    -passin stdin \
    -rawin -in "$CHALLENGE_FILE" -out "$SIGNATURE_FILE" 2>> "$LOG"; then
    echo "[$(date)] Ошибка подписания (пароль или ключ неверны)" >> "$LOG"
    exit 1
fi

echo "[$(date)] Подпись успешно создана" >> "$LOG"
exit 0
