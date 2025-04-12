# Имя итогового модуля
TARGET = pam_flash_auth.so

# Исходники и объектные файлы
SRC = flash_auth_pam.c
OBJ = flash_auth_pam.o

# Путь установки PAM-модулей (для большинства 64-битных систем)
PAM_DIR = /lib/x86_64-linux-gnu/security

# Флаги компиляции
CFLAGS = -fPIC -fno-stack-protector -Wall
LDFLAGS = -shared
LIBS = -lpam -lsodium

.PHONY: all install clean

# Компиляция по умолчанию
all: $(TARGET)

$(TARGET): $(OBJ)
	$(CC) $(LDFLAGS) -o $@ $^ $(LIBS)

$(OBJ): $(SRC)
	$(CC) $(CFLAGS) -c $< -o $@

# Установка модуля в системный каталог
install: $(TARGET)
	sudo cp $(TARGET) $(PAM_DIR)/
	sudo chmod 644 $(PAM_DIR)/$(TARGET)
	@echo "Installed to $(PAM_DIR)/$(TARGET)"

# Очистка временных файлов
clean:
	rm -f $(OBJ) $(TARGET)

