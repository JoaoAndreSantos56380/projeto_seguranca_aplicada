cada bank/atm tem um par de chaves publica e privada;
o atm e que se identifica;
autenticacao mutua;
esquema de encrypt then authenticate;
eliptic curve diffie hellman para troca de chaves para gerar chave de sessao?


podemos ler o authfile do disco
autenticar apenas o atm


banco gera ficheiro
envia para o atm pelo trusted channel (atm le a chave do ficheiro. Ou recebe atraves de PKI, ou seja, criamos uma classe que serve de autenticador. em vez do certificado ser self-signed seria assinado pela autoridade que ambos reconhecem. para isso precisariamos de ter uma truststore com a chave publica da autoridade para podermos verificar que o certificado e valido)

authfile: chave simetrica e sequence number inicial

---autenticacao-----

atm: pede identificador (pergnta quem é) cifrado com a chave simetrica

banco: id_x:segredo_do_id_x

	identifica cada atm e impede personificacao



banco envia E_s(nonce_banco:timestamp_1)

atm decifra e envia E_s(nonce_banco:timestamp_2:nonce_atm)

banco decifra e envia E_s(nonce_atm:timestamp_3)

atm decifra, verifica e envia identificacao

---dh-------
geramos uma chave de sessao para cada comunicacao entre atm e banco
------------------------alternativa de autenticacao--------------------















atm manda ola e cifra a sua chave publica com a partilhada

banco recebe a publica e decifra, adiciona a sua truststore, envia a sua publica cifrada com nonce assinado com a sua privada

atm verifica assinatura e envia o nonce que recebeu assinado e gera outro cifrado com a publica do banco

banco verfica assinatura do atm e envia nonce assinado com a sua privada

atm verifica assinatura

(com objetivo de impedir que um man in the middle altere a chave publica que vai para a truststore)


banco responde com (nonce + timestamp) cifrado com a chave partilhada



banco recebe e gera nonce e cifra com a chave simetrica partilhada.

atm recebe, decifra e envia outro nonce cifrado e o nonce que recebeu

banco verifica o nonce que enviou e envia o nonce cifrado que recebeu

banco verifica que recebeu o nonce que enviou

---Diffie–Hellman–Merkle para gerar chave simetrica de sessao-----




layer 1 (MITM) -> encriptacao(com chave assimetrica)
layer 2 (MITM) -> nonce(evitar replay attacks)
layer 3 (MITM) -> integridade(com hmac, para impedir "tampering")
layer 4 ->

---------------------------------------------------------------------------------------------------

cada peer (banco e clientes) tem uma keystore e truststore

no inicio da execucao de cada peer geramos um par de chaves rsa e guardamos na truststore do banco

atm gera nonce


