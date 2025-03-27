# Chave Simétrica
Bank <-> MITM <-> ATM

O MITM vê comunicação encriptada de ambos os lados. Portanto eavesdropping é impossível.
Mas pode realizar um "replay attack". Previne-se com nonce.


1. ATM envia account + card-file ao BANK
	New Account:	atm -c <card-file> -a <account> -n <balance>
	Deposit:		atm -c <card-file> -a <account> -d <amount>
	Widthraw:		atm -c <card-file> -a <account> -w <amount>
	Get:			atm -c <card-file> -a <account> -g
2. BANK responde com

auth file tem a chave publica do banco

atm(do cliente) fornece o id (da conta)

banco reponde com segredo associado
