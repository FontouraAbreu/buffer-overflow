# buffer-overflow

My buffer overflow attack for the Computational Security in UFPR
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

### Objetivo

Para explorar o buffer overflow e abrir uma shell, iremos seguir os seguintes passos:

1. descobrir o endereço do do buffer
2. descobrir o endereço do registrador de retorno
3. descobrir a distancia entre o buffer e o registrador de retorno
4. preencher o buffer com o shellcode, um padding caso necessário, e o endereço de retorno

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

podemos conferir o valor das variáveis `pass` e `buff` utilizando:

```gdb
(gdb) info locals
```

Para descobrirmos o endereço do buffer podemos fazer:

```gdb
(gdb) p &buff
$2 = (char (*)[9]) 0x7fffffffdc83
```

Assim o endereço do buffer é `0x7fffffffdc83`

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

### Descobrindo a distancia entre o buffer e o registrador de retorno

Para descobrirmos a distancia entre o buffer e o registrador de retorno, basta subtrair os dois endereços:

```gdb
(gdb) p 0x7fffffffdc98 - 0x7fffffffdc83
$6 = 21
```

Assim a distancia entre o buffer e o registrador de retorno é `21` bytes.

### Preenchendo o buffer

## Autores

- Vinícius Fontoura de Abreu (GRR20206873)
- Guiusepe Oneda Dal Pai ()
