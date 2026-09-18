.SILENT:
CC = x86_64-w64-mingw32-gcc
CFLAGS = -Wall -Iinclude -g3 
FINAL_FLAGS = -lkernel32 -luser32 -lpsapi
LUAFLAGS = -static -Llib -llua 

GANCHO = gancho.exe
DLL = injection.dll

SRC_DIR = src
OBJ_DIR = build

MAIN_OBJ = $(OBJ_DIR)/gancho.o $(OBJ_DIR)/dlllist.o $(OBJ_DIR)/hde64.o
DLL_OBJS = $(OBJ_DIR)/injection.o 

# Regra padrão
all: setup_lua $(GANCHO) $(DLL)

setup_lua:
	@if [ ! -f "lib/liblua.a" ]; then \
		echo "[!] liblua.a não encontrada. Compilando Lua..."; \
		bash lua/build_lua.sh; \
	else \
		echo "[!] liblua.a já já pronta. Pulando compilação."; \
	fi

$(GANCHO): $(MAIN_OBJ)
	$(CC) $(MAIN_OBJ) -o $(GANCHO) $(FINAL_FLAGS)

$(DLL): $(DLL_OBJS)
	@echo "[+] Compilando DLL com Lua"
	$(CC) $(DLL_OBJS) -shared -o $(DLL) $(LUAFLAGS)

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c
	@echo "[+] Gerando arquivos objeto $< -> $@"
	@mkdir -p $(OBJ_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	@echo "[-] Limpando arquivos. a liblua.a não é excluída por aqui."
	rm -rf $(OBJ_DIR) $(GANCHO) $(DLL)

.PHONY: all clean setup_lua