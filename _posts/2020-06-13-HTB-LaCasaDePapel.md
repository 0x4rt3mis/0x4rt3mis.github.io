---
title: "Hack The Box - LaCasaDePapel"
tags: [Linux,Easy,Pspy,Web,Proxychain,FTP]
categories: HackTheBox
---

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-lacasadepapel/L_inicial.png)

Link: <https://www.hackthebox.eu/home/machines/profile/181>

# Enumeração

## Primeiro passo é rodar o nmap contra a máquina, para verificar quais portas estão abertas e quais serviços estão sendo disponibilizados pelas portas.

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-lacasadepapel/L_nmap.png)

### Explicação de cada parâmetro do Nmap

> -sC --> Rodar alguns scripts padrão em cada porta

> -sV --> Levantar qual serviço está rodando na porta

> -Pn --> Já considera o host ativo

### Verificamos que temos 4 portas abertas

> Porta 21 -> Vsftdp 2.3.4

> Porta 22 -> SSH

> Portas 80 e 443 -> Servidor Web

## Enumeração das portas 80 e 443

Abrindo a página verificamos o que tem nela (Porta 80)

Solicita pra abrir um QR code, estranho

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-lacasadepapel/L_web.png)

Abrindo a página verificamos o que tem nela (Porta 443)

Solicita certificado pra poder abrir... ai começamos a ver que precisaremos gerar um certificado

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-lacasadepapel/L_web1.png)

## Enumeração Vsftp 2.3.4

Encontramos um exploit que realmente da certo, pq já fiz em outras máquinas

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-lacasadepapel/L_ftp.png)

### Exploração pelo Metasploit Framework

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-lacasadepapel/L_msf.png)

> use exploit/unix/ftp/vsftpd_234_backdoor

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-lacasadepapel/L_msf1.png)

Estranho não? Aqui aparece que a porta 6200 não parece ter um shell.

Esse que é o problema de quem só sabe usar a ferramenta e não sabe o por que ela funciona...

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-lacasadepapel/L_msf2.png)

Vamos explicar como que acontece a exploração desse vulnerabilidade, e o que está acontecendo na porta 6200

### Explicação Vsftp 2.3.4 Backdoor

Encontramos esse blog que explica direitinho o que está acontecendo

> https://subscription.packtpub.com/book/networking_and_servers/9781786463166/1/ch01lvl1sec18/vulnerability-analysis-of-vsftpd-2-3-4-backdoor

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-lacasadepapel/L_exp.png)

Traduzindo

`Se o usuário tiver no nome um smile :) vai ativar um shell na porta 6200 [Isso esta explicado no código do blog acima, o 0x3a é igual a : e o 0x29 é igual a ) ]
Vamos tirar a PoC disso`

1º Passo é testar se a porta 6200 está aberta, vai aparecer fechada pq não demos o triger ainda do backdoor

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-lacasadepapel/L_exp1.png)

2º Tentamos logar no vsftpd 2.3.4 com um usuário sem o :) pra ver o comportamento

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-lacasadepapel/L_exp2.png)

3º Tentamos novamente nos conectar na porta 6200 e não da certo ainda

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-lacasadepapel/L_exp3.png)

4º Agora tentamos colocar um :) no user e ver o que acontece com a porta 6200

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-lacasadepapel/L_exp4.png)

5º Habilitar o backdoor na porta 6200, isso é o que metasploit framework faz

Só que nesse caso, não é um shell normal, /bin/bash da vida, por isso o Metasploit Framework não deu certo

Verificamos o que é esse psy shell, ele é um shell php

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-lacasadepapel/L_exp5.png)

### Enumerando PsyShell

Verificamos o que é esse Psy Shell, ele se trata de um shell php

Como demonstrado no site do criador da ferramenta

> https://psysh.org/

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-lacasadepapel/L_psy.png)

### Enumeração do sistema

Uma vez que temos um "shell" válido, vamos tentar rodar alguns comandos, o primeiro deles é o `system()` e o `shell_exec()`. Ambos são comandos em php pra executar comandos do sistema. Se conseguirmos executá-los podemos ter um shell interativo melhor

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-lacasadepapel/L_psy1.png)

Ambas funções não estão habilitadas nesse shell php

Então vamos utilizar o `scandir()` que é igual ao `ls` do bash

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-lacasadepapel/L_psy2.png)

Esse deu certo, então começamos a enumerar as pastas do sistema até encontrar dentro da pasta `/home/nairobi` um `ca.key` que possivelmente é um certificado SSL que podemos utilizar para entrar no website da porta 443

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-lacasadepapel/L_psy3.png)

### Encontramos um ca.crt (Certificado)

Com a função `file_get_contents()` lemos o conteúdo do arquivo e realmente verificamos que é uma chave

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-lacasadepapel/L_psy4.png)

Passamos ela pra nossa máquina pra melhor trabalhar

Arrumamos ela pra ficar mais legível e usável (dentro do VI)

> :%s/\\n/\n/g

> :%s/ //g

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-lacasadepapel/L_vi.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-lacasadepapel/L_vi1.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-lacasadepapel/L_vi2.png)

Obs: Também poderiamos identificar esse certificado pelo comando `ls` do php

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-lacasadepapel/L_ls.png)

Bom, lembrando bem eu tive problemas de certificado no HTTPS do site. Agora eu encontrei um ca.crt, interessante... Será que não conseguimos gerar um certificado válido?

#### Comparando o certificado do site com o que nós encontramos no PsyShell

1º Devemos extrair o certificado da página https, para isso clicamos no *Cadeado* e vamos em *Security*

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-lacasadepapel/L_cert.png)

2º Clicamos em *View Certificate* - *Details* - Clicamos no *lacasadepapel.htb* e clicamos em *Export*

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-lacasadepapel/L_cert1.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-lacasadepapel/L_cert2.png)

3º Verificamos se os dois são iguais

`openssl pkey -in ca.crt -pubout`

`openssl x509 -in lacasadepapel_htb.crt -pubkey -noout`

`openssl x509 -in lacasadepapel_htb.crt -pubkey -noout | md5sum; \ openssl pkey -in ca.key -pubout | md5sum`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-lacasadepapel/L_cert3.png)

## Gerando um certificado

A partir do momento verificamos que uma serve para autenticar a outra, ou seja podemos "simular" uma chave válida pra entrar na àrea restrita do site

1º Vamos gerar um cliente a partir do que temos, primeiro devemos criar a chave do cliente

> openssl genrsa -out client.key 4096

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-lacasadepapel/L_c.png)

2º Agora vamos criar a chave do cliente

`Geramos uma chave CSR para uma chave KEY já existente`

> openssl req -new -key client.key -out client.csr

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-lacasadepapel/L_c1.png)

3º Atribuir ela a chave que pegamos no site (validar)

`Então, geramos um certificado auto assinado a partir de um CRT (que peguei no site) e um CSR (que eu criei)`

> openssl x509 -req -in client.csr -CA lacasadepapel_htb.crt -CAkey ca.key -set_serial 5555 -extensions client -days 6666 -outform PEM -out client.cer 

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-lacasadepapel/L_c3.png)

4º O firefox não lê esse tipo de chave criada (*.cer) devemos converter ela para *.p12

> openssl pkcs12 -export -inkey client.key -in client.cer -out client.p12

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-lacasadepapel/L_c2.png)

Obs: https://phoenixnap.com/kb/openssl-tutorial-ssl-certificates-private-keys-csrs (Fica a dica para leitura, muito bom, explica direitinho o que está acontecendo)

## Instalando o certificado auto assinado no Firefox

Bom, agora que já criamos nosso próprio certificado a partir do que pegamos no site e do psy shell, iremos colocar ele no Firefox pra podermos abrir a página https da máquina corretamente

Esse client.p12 é a combinação do client.key e do client.cer, e o client.cer é a versão cer do client.csr
Agora devemos adicionar essa chave no firefox para podermos acessar a página

Abrimos as configurações do Firefox e pesquisamos por `cert`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-lacasadepapel/L_f.png)

Clicamos em `Your Certificates`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-lacasadepapel/L_f1.png)

Clicamos em `Import` e importamos o arquivo *.p12*

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-lacasadepapel/L_f2.png)

Ai é só atualizar a página e aceitar o certificado

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-lacasadepapel/L_f3.png)

Sucesso! Temos acesso à parte que não tinhamos

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-lacasadepapel/L_f4.png)

# Exploração LFI

Após realizarmos vários testes no diretórios, descobrimos que conseguimos acessar outros diretórios, como por exemplo o ".."

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-lacasadepapel/L_a.png)

Entramos dentro da pasta ".ssh"

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-lacasadepapel/L_a1.png)

Após verificarmos como funciona o link dos sites para baixar os episódios, vemos que eles estão encodados em base64, então se encodarmos algum arquivo que queremos acessar no servidor em base64 e enviarmos a requisição, vamos ter acesso a ele, como por exemplo ao id_rsa que vemos na imagem acima

Como por exemplo:

> https://10.10.10.131/file/U0VBU09OLTEvMDEuYXZp

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-lacasadepapel/L_a2.png)

> https://10.10.10.131/file/U0VBU09OLTEvMDIuYXZp

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-lacasadepapel/L_a3.png)

Passamos pra base64 o caminho do id_rsa (quero a chave ssh daquela pasta .ssh)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-lacasadepapel/L_a4.png)

Agora baixamos o id_rsa do servidor

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-lacasadepapel/L_a5.png)

## Login SSH

Logamos via SSH no servidor

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-lacasadepapel/L_a6.png)

## Outro modo de conseguir a conexão SSH

Bom, irei demonstrar outro modo pra conseguir acesso à página sem ser pela Chave SSL, é interessante pois vou fazer um SSH Proxy Socks na máquina

1º Passo Verificamos na pasta home da dali que tem o `authorized_keys` (isso ainda com o Psy Shell)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-lacasadepapel/L_b.png)

2º Passo Criamos uma chave ssh na nossa máquina

> ssh-keygen -f dali

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-lacasadepapel/L_b1.png)

3º Mandamos ela pra dentro do authorized_keys da dali

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-lacasadepapel/L_b2.png)

`file_put_contents('arquivo','o que vai ser inserido', FILE_APPEND)` é o comando em php (no shell php) para se escrever em algum arquivo

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-lacasadepapel/L_b3.png)

`file_get_contents(' . ')` é um "cat" para php

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-lacasadepapel/L_b4.png)

4º Passo login SSH

Logamos na máquina com o usuário dali

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-lacasadepapel/L_b5.png)

5º Passo Criação do Túnel SSH

> ssh -D1080 -i dali dali@10.10.10.131

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-lacasadepapel/L_b6.png)

Modificamos no proxychains

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-lacasadepapel/L_b7.png)

6º Nmap pra encontrar a porta SSL

> proxychains nmap -sT -Pn -n 127.0.0.1 2>/dev/null

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-lacasadepapel/L_b8.png)

7ª Adicionamos ao `FoxProxy` (Apenas pra facilitar)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-lacasadepapel/L_fox.png)

8º Acessamos 127.0.0.1:8000

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-lacasadepapel/L_b9.png)

Bom, a partir daqui já foi demonstrado acima, o procedimento é o mesmo uma vez que temos acesso à essa página

# Escalação de privilégio

## Rodando PSPY

Rodaremos o pspy nessa máquina pra verificar cronjobs que estejam sendo executados como root

> https://github.com/DominicBreuker/pspy

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-lacasadepapel/L_pspy.png)

Passamos pra máquina e executamos

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-lacasadepapel/L_pspy1.png)

Verificamos algo "estranho" nesse memcached.js

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-lacasadepapel/L_pspy2.png)

## Verificando memcached.js

Verificamos que a pasta que ele está tem SGID habilitado... estranho

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-lacasadepapel/L_mem.png)

Verificamos o que ele é. Vemos que ele está sendo executado como root, mas não podemos escrever nele

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-lacasadepapel/L_mem1.png)

## Escalando para root

Então movemos ele pra outro nome, escrevemos outro arquivo chamado memcached.ini com um shell reverso para nossa máquina

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-lacasadepapel/L_mem2.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-lacasadepapel/L_mem3.png)

Esperamos um pouco com um nc aberto, e recebemos a shell de root

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-lacasadepapel/L_mem4.png)

### Lendo flag de root e user

Então lemos as duas flags

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-lacasadepapel/L_root.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-lacasadepapel/L_user.png)