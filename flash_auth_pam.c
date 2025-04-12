#define _GNU_SOURCE
#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libudev.h>
#include <unistd.h>
#include <sys/types.h>
#include <pwd.h>
#include <sys/stat.h>
#include <syslog.h>
#include <sodium.h>
#include <sys/random.h>
#include <linux/random.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <signal.h>
#include <time.h>
#include <errno.h>

#define DEBUG_LOG(fmt, ...) pam_syslog(pamh, LOG_DEBUG, "PAM_DEBUG: " fmt, ##__VA_ARGS__)
#define SAFE_FREE(ptr) do { if (ptr) { free(ptr); ptr = NULL; } } while (0)

typedef struct {
    char *vendor_id;
    char *product_id;
    char *serial;
    char *username;
    char *private_key_path;
    char *public_key_path;
    char *sign_script_path;
    char *algorithm;
    int challenge_timeout;
    int max_attempts;
    char *mount_point;
    char *log_path;
} config_t;

#define CONFIG_FILE "/etc/flash_auth/flash_auth.conf"
#define CHALLENGE_FILE "/tmp/challenge.bin"
#define SIGNATURE_FILE "/tmp/signature.bin"
#define DEFAULT_ALGORITHM "ed25519"

static void log_message(pam_handle_t *pamh, const char *path, const char *msg) {
    if (!msg) return;
    
    FILE *log = fopen(path ? path : "/var/log/flash_auth.log", "a");
    if (log) {
        time_t now = time(NULL);
        struct tm *tm_info = localtime(&now);
        char buffer[64];
        strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", tm_info);
        fprintf(log, "[%s] %s\n", buffer, msg);
        fclose(log);
    }
    pam_syslog(pamh, LOG_INFO, "%s", msg);
}

static void free_config(config_t *cfg) {
    if (!cfg) return;
    
    SAFE_FREE(cfg->vendor_id);
    SAFE_FREE(cfg->product_id);
    SAFE_FREE(cfg->serial);
    SAFE_FREE(cfg->username);
    SAFE_FREE(cfg->private_key_path);
    SAFE_FREE(cfg->public_key_path);
    SAFE_FREE(cfg->sign_script_path);
    SAFE_FREE(cfg->algorithm);
    SAFE_FREE(cfg->mount_point);
    SAFE_FREE(cfg->log_path);
//    memset(cfg, 0, sizeof(config_t));
}

static int read_config(pam_handle_t *pamh, const char *filename, config_t *cfg) {
    if (!filename || !cfg) {
        DEBUG_LOG("Invalid arguments to read_config");
        return -1;
    }

    FILE *file = fopen(filename, "r");
    if (!file) {
        DEBUG_LOG("Cannot open config file %s: %s", filename, strerror(errno));
        return -1;
    }

    char line[256];
    while (fgets(line, sizeof(line), file)) {
        // Убираем перевод строки
        line[strcspn(line, "\r\n")] = '\0';

        // Пропускаем пустые строки и комментарии
        char *start = line;
        while (*start == ' ' || *start == '\t') start++;
        if (*start == '\0' || *start == '#') continue;

        // Ищем разделитель '='
        char *eq = strchr(start, '=');
        if (!eq) continue;

        *eq = '\0';
        char *key = start;
        char *value = eq + 1;

        // Удаляем пробелы с конца ключа
        char *key_end = key + strlen(key) - 1;
        while (key_end > key && (*key_end == ' ' || *key_end == '\t')) *key_end-- = '\0';

        // Удаляем пробелы и кавычки с начала значения
        while (*value == ' ' || *value == '\t') value++;
        if (*value == '"') {
            value++;
            char *v_end = strrchr(value, '"');
            if (v_end) *v_end = '\0';
        }

        // Определяем, куда записывать значение
        char **target = NULL;
        if (strcmp(key, "VENDOR_ID") == 0) target = &cfg->vendor_id;
        else if (strcmp(key, "PRODUCT_ID") == 0) target = &cfg->product_id;
        else if (strcmp(key, "SERIAL") == 0) target = &cfg->serial;
        else if (strcmp(key, "USERNAME") == 0) target = &cfg->username;
        else if (strcmp(key, "PRIVATE_KEY_PATH") == 0) target = &cfg->private_key_path;
        else if (strcmp(key, "PUBLIC_KEY_PATH") == 0) target = &cfg->public_key_path;
        else if (strcmp(key, "SIGN_SCRIPT_PATH") == 0) target = &cfg->sign_script_path;
        else if (strcmp(key, "ALGORITHM") == 0) target = &cfg->algorithm;
        else if (strcmp(key, "MOUNT_POINT") == 0) target = &cfg->mount_point;
        else if (strcmp(key, "LOG_PATH") == 0) target = &cfg->log_path;
        else if (strcmp(key, "CHALLENGE_TIMEOUT") == 0) cfg->challenge_timeout = atoi(value);
        else if (strcmp(key, "MAX_ATTEMPTS") == 0) cfg->max_attempts = atoi(value);

        if (target) {
            SAFE_FREE(*target);
            *target = strdup(value);
            if (!*target) {
                DEBUG_LOG("Memory allocation failed for %s", key);
                fclose(file);
                return -1;
            }
        }
    }

    fclose(file);

    // Значения по умолчанию
    if (!cfg->algorithm) {
        cfg->algorithm = strdup(DEFAULT_ALGORITHM);
        if (!cfg->algorithm) return -1;
    }
    if (cfg->challenge_timeout <= 0) cfg->challenge_timeout = 10;
    if (cfg->max_attempts <= 0) cfg->max_attempts = 3;
    if (!cfg->log_path) {
        cfg->log_path = strdup("/var/log/flash_auth.log");
        if (!cfg->log_path) return -1;
    }

    return 0;
}


static int verify_signature(pam_handle_t *pamh, const config_t *cfg) {
    // Проверка на наличие конфигурации и публичного ключа
    if (!cfg || !cfg->public_key_path) {
        DEBUG_LOG("Invalid config in verify_signature");
        return 0;
    }

    // Объявление переменных для challenge, подписи и публичного ключа
    unsigned char challenge[32];
    unsigned char signature[64];
    unsigned char public_key[32];

    // Чтение challenge файла
    int fd = open(CHALLENGE_FILE, O_RDONLY);
    if (fd == -1 || read(fd, challenge, sizeof(challenge)) != sizeof(challenge)) {
        DEBUG_LOG("Failed to read challenge file: %s", strerror(errno));
        if (fd != -1) close(fd);
        return 0;
    }
    close(fd);

    // Чтение файла подписи
    fd = open(SIGNATURE_FILE, O_RDONLY);
    if (fd == -1 || read(fd, signature, sizeof(signature)) != sizeof(signature)) {
        DEBUG_LOG("Failed to read signature file: %s", strerror(errno));
        if (fd != -1) close(fd);
        return 0;
    }
    close(fd);

    // Чтение публичного ключа
    fd = open(cfg->public_key_path, O_RDONLY);
    if (fd == -1 || read(fd, public_key, sizeof(public_key)) != sizeof(public_key)) {
        DEBUG_LOG("Failed to read public key: %s", strerror(errno));
        if (fd != -1) close(fd);
        return 0;
    }
    close(fd);

    // Инициализация библиотеки libsodium для криптографических операций
    if (sodium_init() < 0) {
        DEBUG_LOG("Libsodium initialization failed");
        return 0;
    }

    // Проверка подписи
    return crypto_sign_verify_detached(signature, challenge, sizeof(challenge), public_key) == 0;
}

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    DEBUG_LOG("Authentication started");
    
    config_t cfg = {0};
    int retval = PAM_AUTH_ERR;

    if (sodium_init() < 0) {
        DEBUG_LOG("Libsodium init failed");
        return PAM_AUTH_ERR;
    }

    // Чтение конфигурации
    if (read_config(pamh, CONFIG_FILE, &cfg) != 0) {
        DEBUG_LOG("Config read error");
        goto cleanup;
    }
    
    // Получение имени пользователя
    const char *username = NULL;
    if ((retval = pam_get_user(pamh, &username, NULL)) != PAM_SUCCESS) {
        DEBUG_LOG("Cannot get username");
        goto cleanup;
    }
    
    if (!username) {
        DEBUG_LOG("pam_get_user returned success but username is NULL");
         goto cleanup;
    }
    
    DEBUG_LOG("Got username: %s", username);

    // Сравнение с допустимым пользователем из конфигурации	
    if (!cfg.username) {
        DEBUG_LOG("No USERNAME in config");
        goto cleanup;
    }
    
    if (strcmp(username, cfg.username) != 0) {
        DEBUG_LOG("Username mismatch: got '%s', expected '%s'", username, cfg.username);
        goto cleanup;
    }

    // Проверка путей к ключу и скрипту
//    if (!username || !cfg.username || strcmp(username, cfg.username) != 0) {
//        DEBUG_LOG("Username mismatch");
//        goto cleanup;
//    }
    
    if (!cfg.sign_script_path || !cfg.private_key_path) {
        DEBUG_LOG("Script path or private key path is NULL");
        goto cleanup;
    }


    umask(077);
    unsigned char challenge[32];
    int fd = open(CHALLENGE_FILE, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd == -1) {
        DEBUG_LOG("Cannot create challenge file: %s", strerror(errno));
        goto cleanup;
    }

    if (getrandom(challenge, sizeof(challenge), GRND_NONBLOCK) != sizeof(challenge)) {
        DEBUG_LOG("Challenge generation failed");
        close(fd);
        goto cleanup;
    }

    if (write(fd, challenge, sizeof(challenge)) != sizeof(challenge)) {
        DEBUG_LOG("Challenge write failed");
        close(fd);
        goto cleanup;
    }
    close(fd);

    if (chmod(CHALLENGE_FILE, 0644) == -1) {
        DEBUG_LOG("Challenge file chmod failed");
        goto cleanup;
    }

    // int attempts = 0;
    // while (attempts < cfg.max_attempts) {
    //     pid_t pid = fork();
    //     if (pid == 0) {
    //         execl(cfg.sign_script_path, cfg.sign_script_path, 
    //              CHALLENGE_FILE, SIGNATURE_FILE, cfg.private_key_path, NULL);
    //         _exit(1);
    //     } else if (pid > 0) {
    //         int status;
    //         waitpid(pid, &status, 0);
            
    //         if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
    //             break;
    //         }
            
    //         attempts++;
    //         if (attempts < cfg.max_attempts) sleep(cfg.challenge_timeout);
    //     } else {
    //         DEBUG_LOG("Fork failed");
    //         break;
    //     }
    // }

    pid_t pid = fork();
    if (pid == 0) {
        // Дочерний процесс: запускаем скрипт проверки
        execl(cfg.sign_script_path, cfg.sign_script_path,
              CHALLENGE_FILE, SIGNATURE_FILE, cfg.private_key_path, NULL);
        _exit(1);  // Если execl не сработал
    } else if (pid > 0) {
        // Родительский процесс: ждём завершения
        int status;
        waitpid(pid, &status, 0);
        
        if (waitpid(pid, &status, 0) == -1) {
            DEBUG_LOG("waitpid failed: %s", strerror(errno));
            goto cleanup;
        }

        if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
            // Успех (скрипт вернул 0)
            DEBUG_LOG("Authentication successful");
        } else {
            // Неудача (скрипт вернул не 0 или завершился аварийно)
            DEBUG_LOG("Authentication failed");
        }
    } else {
        // Ошибка fork()
        DEBUG_LOG("Fork failed");
    }

//    if (attempts >= cfg.max_attempts) {
//        DEBUG_LOG("Max authentication attempts reached");
//        goto cleanup;
//    }

    if (verify_signature(pamh, &cfg)) {
        retval = PAM_SUCCESS;
    } else {
        DEBUG_LOG("Signature verification failed");
    }

cleanup:
    if (access(CHALLENGE_FILE, F_OK) == 0) unlink(CHALLENGE_FILE);
    if (access(SIGNATURE_FILE, F_OK) == 0) unlink(SIGNATURE_FILE);

    free_config(&cfg);
    return retval;
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    return PAM_SUCCESS;
}
