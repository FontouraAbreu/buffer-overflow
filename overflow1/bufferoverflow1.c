#include <stdio.h>
#include <string.h>

int main() {
	/* buffer de 9 posições guarda uma string de 8 bytes + o \0 */
	char buff[9];
	int pass = 0;

	printf("\nDigite a senha: ");
	gets(buff);

	if(strcmp(buff, "admin123")) {
		printf ("\n[!] Errou...\n");
	} else {
		printf ("\n[+] Senha correta!\n");
		pass = 1;
	}

	if(pass) {
		printf ("\n*** Parabéns, você entrou no sistema! ***\n");
	}

	return 0;
}
