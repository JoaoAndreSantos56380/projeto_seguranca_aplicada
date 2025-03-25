cada bank/atm tem um par de chaves publica e privada;
o atm e que se identifica;
autenticacao mutua;
esquema de encrypt then authenticate;
eliptic curve diffie hellman para troca de chaves para gerar chave de sessao?





banco gera ficheiro
envia para o atm pelo trusted channel (atm le a chave do ficheiro. Ou recebe atraves de PKI, ou seja, criamos uma classe que serve de autenticador. em vez do certificado ser self-signed seria assinado pela autoridade que ambos reconhecem. para isso precisariamos de ter uma truststore com a chave publica da autoridade para podermos verificar que o certificado e valido)

---autenticacao-----
atm gera nonce w cifra com a chave simetrica partilhada.

banco recebe, decifra e envia outro nonce cifrado e o nonce que recebeu

atm verifica o nonce que enviou e envia o nonce cifrado que recebeu

banco verifica que recebeu o nonce que enviou

---Diffie–Hellman–Merkle para gerar chave simetrica de sessao-----




layer 1 (MITM) -> encriptacao(com chave assimetrica)
layer 2 (MITM) -> nonce(evitar replay attacks)
layer 3 (MITM) -> autenticidade(com hmac, para impedir "tampering")
layer 4 ->

