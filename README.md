# G.A.N.C.H.O.

Generic API Native Custom Hook Operator.

Esse é o meu trabalho de diplomação da faculdade. A ideia é pegar um processo Windows qualquer, injetar
uma DLL nele, e a partir dali interceptar chamadas de API sem precisar do código-fonte do binário alvo.
Depois de interceptada, a chamada é passada pra dentro de um script Lua, então dá pra decidir o que fazer
com ela (logar, alterar o retorno, bloquear, etc) sem recompilar nada em C.

Testei em cima do Notepad++, que era o processo que eu tinha disponível pra validar o comportamento.

## Como funciona

O fluxo é:

1. `gancho.exe` abre o processo alvo (`OpenDebugProcess`, hoje hardcoded pro Notepad++) e injeta a
   `injection.dll` nele via `CreateRemoteThread` + `LoadLibraryA`.
2. Depois de injetada, preciso achar os endereços das funções que quero enganchar. Não uso nenhuma lib
   pronta pra isso: leio o PEB remoto do processo (via `NtQueryInformationProcess`), percorro a
   `PEB_LDR_DATA` pra listar as DLLs carregadas, e faço o parsing manual do Export Directory de cada uma
   (`IMAGE_EXPORT_DIRECTORY`) pra montar minha própria tabela de símbolos exportados. Isso está em
   `dlllist.c`.
3. Com o endereço da função alvo em mãos (ex: `CreateFileW`), o hook é um inline hook clássico: escrevo
   um `jmp` absoluto (`FF 25 00000000` + endereço de 64 bits) nos primeiros bytes da função. O problema
   é que não dá pra sobrescrever 14 bytes de qualquer jeito, porque isso pode cortar uma instrução no
   meio. Pra resolver, uso o **HDE64** (Hacker Disassembler Engine, crédito no fim do README) pra
   desmontar instrução por instrução até acumular pelo menos 14 bytes, e só então sei o tamanho exato do
   espaço que posso usar com segurança.
4. Os bytes originais retirados dali não são descartados: monto um **trampoline** com eles em uma página
   de memória alocada perto da função original (`AllocNear`, pra manter os deslocamentos relativos
   dentro do alcance de 32 bits), corrijo qualquer instrução que dependia de endereçamento relativo a RIP
   (`call`, `jmp`, acesso a dado via `[rip+disp32]`, etc — é a parte de `CreateTrampoline` que mexe com
   `F_RELATIVE` e `F_MODRM`) e, no final desse trampoline, coloco um `jmp` de volta pro ponto exato onde
   a função original continuaria executando. Isso é o que permite a função seguir funcionando
   normalmente depois que o hook termina.
5. A execução não vai direto pra função de hook: tem um `stub` no meio (`CreateStubProxy`). Esse stub é
   um trecho de shellcode x64 escrito à mão que salva os 4 primeiros argumentos (RCX/RDX/R8/R9,
   respeitando o shadow space da convenção de chamada do Windows x64), chama a função de hook em C,
   restaura os argumentos originais e só depois pula pro trampoline. Sem isso os registradores dos
   argumentos originais seriam destruídos e a função real quebraria.
6. A função de hook em C (dentro da DLL injetada) sobe uma instância de Lua na primeira vez que é
   chamada (procura por `lua54.dll`, `lua53.dll` etc já carregadas no processo, ou tenta carregar do
   disco) e chama a função `OnHookTrigger` definida em `hook.lua`, passando o nome do evento e os
   argumentos relevantes em uma tabela Lua. Isso é o que permite trocar a lógica do hook sem recompilar
   o projeto inteiro toda vez.

No `hook.lua` de exemplo tem 4 handlers: `CreateFileW` (loga qual arquivo está sendo aberto e com que
permissão), `DispatchMessageW` (troca a tecla digitada por "G", pra demonstrar que dá pra alterar o
comportamento do processo em tempo real e não só observar), `SetWindowTextW` (intercepta e reescreve o
título da janela) e `WriteFile` (varre o conteúdo sendo escrito atrás de strings sensíveis, como uma
espécie de DLP artesanal).

## Build

Precisa do `mingw-w64` (desenvolvo em Linux e cross-compilo pra Windows x64):

```bash
make
```

Na primeira vez ele baixa e compila a Lua estática sozinho (roda `lua/build_lua.sh`, que compila a
5.4.6 e coloca o `liblua.a` e os headers nas pastas certas). Depois disso só gera `gancho.exe` e
`injection.dll`.

Rodar (no Windows, precisa dos dois arquivos na mesma pasta):

```
gancho.exe
```

Ele abre o Notepad++, injeta a DLL e aplica os 4 hooks. Para encerrar, `Ctrl+C`.

## Limitações conhecidas

- O processo alvo e as funções enganchadas estão hardcoded no `main()`. Ainda não é um framework
  genérico de linha de comando, é uma prova de conceito da arquitetura.
- Testado apenas em binários x64 sem nenhum tipo de proteção anti-hooking/anti-debug. Contra um EDR de
  verdade isso não sobrevive.
- O `AllocNear` varre memória livre num range de ±1GB do endereço alvo pra caber um `jmp` que, no fim,
  acabou virando um `jmp [rip+0]` absoluto de 64 bits (não precisaria mais ser "perto" tecnicamente).
  Ficou assim porque a estratégia de hook mudou no meio do desenvolvimento e essa parte não foi
  simplificada depois.
- `WriteFile` hookado sempre retorna `FALSE` pro chamador original (assim como os outros hooks void), ou
  seja, a chamada real "some" pro caller sempre que o retorno correto não é repassado. Pra virar algo
  usável em produção isso precisaria propagar o resultado real do trampoline de volta.

## Créditos

- [HDE64 (Hacker Disassembler Engine)](https://www.reverse-engineering.info/) de Vyacheslav Patkov — usado
  para determinar o tamanho das instruções na hora de montar o trampoline, em vez de escrever um
  disassembler x86-64 completo só para essa parte.
- Lua 5.4, como motor de scripting embutido.
