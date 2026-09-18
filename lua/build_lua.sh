#!/bin/bash

# Caminhos baseados na estrutura acima
LUA_SRC_DIR="lua-5.4.6"
ROOT_DIR=".." # Raiz do projeto GANCHO

echo "[+] Entrando na pasta fonte da Lua..."
cd $(dirname $0)/$LUA_SRC_DIR/src || exit

echo "[+] Compilando Lua para Windows x64 (Static)..."
# Compila cada .c para um .o usando seu cross-compiler
x86_64-w64-mingw32-gcc -O2 -c *.c -DLUA_BUILD_AS_DLL

echo "[+] Criando liblua.a..."
x86_64-w64-mingw32-ar rcu liblua.a *.o
x86_64-w64-mingw32-ranlib liblua.a

echo "[+] Organizando arquivos na estrutura do projeto..."
mkdir -p $ROOT_DIR/lib
mkdir -p $ROOT_DIR/include

# Move a biblioteca e copia os headers
cp liblua.a $ROOT_DIR/lib/
cp lua.h luaconf.h lualib.h lauxlib.h lua.hpp $ROOT_DIR/include/

echo "[+] Sucesso! Headers em /include e liblua.a em /lib."