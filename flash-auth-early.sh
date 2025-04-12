#!/bin/bash

TTY=/dev/tty2
LOCK_FILE="/tmp/flash_auth_unlocked"
CHALLENGE_FILE="/tmp/auth_challenge"
SIGNATURE_FILE="/tmp/auth_signature"

# Генерация challenge
head -c 32 /dev/urandom > "$CHALLENGE_FILE"

# Функция для безопасной передачи пароля
function sign_with_password() {
    # Создаем временный файл для пароля
    local passfile=$(mktemp)
    echo -n "$1" > "$passfile"
    chmod 600 "$passfile"
    
    # Подписываем с передачей пароля через файл
    openssl pkeyutl -sign \
        -inkey /media/user/AUTH_FLASH/auth_private.key \
        -passin "file:$passfile" \
        -rawin \
        -in "$CHALLENGE_FILE" \
        -out "$SIGNATURE_FILE" 2>/dev/null
    
    local result=$?
    rm -f "$passfile"
    return $result
}

# Основной цикл
for attempt in {1..3}; do
    # Запрос пароля
    echo -n "[$attempt/3] Введите пароль: " > "$TTY"
    stty -echo
    read -r PASSWORD < "$TTY"
    stty echo
    echo > "$TTY"  # Добавляем перевод строки

    # Пытаемся подписать
    if sign_with_password "$PASSWORD"; then
        if [ -s "$SIGNATURE_FILE" ]; then
            touch "$LOCK_FILE"
            chmod 600 "$LOCK_FILE"
            echo "УСПЕХ: Ключ разблокирован!" > "$TTY"
            exit 0
        fi
    fi
    
    echo "ОШИБКА: Неверный пароль" > "$TTY"
done

echo "БЛОКИРОВКА: Превышено число попыток" > "$TTY"
exit 1
