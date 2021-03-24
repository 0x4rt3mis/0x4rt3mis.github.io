---
title: "Hack The Box - Popcorn"
tags: [Linux,Medium,MOTD,Gobuster,DirtyCow,Torrent Hoster,RFI,Web Shell,BurpSuite,BurpSuite Repeater,Magic Number]
categories: HackTheBox OSWE OSCP
---

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-popcorn/P_inicial.png)

Link: <https://www.hackthebox.eu/home/machines/profile/4>

# Enumeração

## Primeiro passo é rodar o nmap contra a máquina, para verificar quais portas estão abertas e quais serviços estão sendo disponibilizados pelas portas.

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-popcorn/P_nmap.png)

### Explicação de cada parâmetro do Nmap

> -sC --> Rodar alguns scripts padrão em cada porta

> -sV --> Levantar qual serviço está rodando na porta

> -Pn --> Já considera o host ativo

### Verificamos que temos 3 portas abertas

> Porta 22 -> SSH

> Portas 80 -> Servidor Web

## Enumeração da porta 80

Abrindo a página verificamos o que tem nela (Porta 80)

Verificamos uma página inicial que diz que funciona

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-popcorn/P_web.png)

### Gobuster

Rodamos o gobuster na página pra verificar se encontramos algo de útil, uma vez que nos deu apenas a página padrão do apache e estamos sem rumo

> gobuster dir -u http://10.10.10.78 -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -t 50

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-popcorn/P_gobuster.png)

Explicação Gobuster

> dir -> Modo escaneamento de diretórios

> -u http://10.10.10.78 -> Url que vai ser escaneada

> -w -> A wordlist utilizada

> -t -> Aumentar o número de threads, pra ir mais rápido

#### /torrent 

Testamos entrar nesse */torrent* pra verificar o que tem nele

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-popcorn/P_t.png)

Pesquisamos por exploits para esse *Torrent Hoster*

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-popcorn/P_exp.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-popcorn/P_exp1.png)

> https://www.exploit-db.com/exploits/11746

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-popcorn/P_searchsploit.png)

Copiamos ele pra nossa pasta de trabalho da máquina e vemos como ele funciona

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-popcorn/P_searchsploit1.png)

Olhando pra ele, nós percebemos que podemos ganhar acesso ao sistema através de um php upload. Então vamos fazer como descrito no exploit

# Exploração do Torrent Hoster

1º Criação de login para podermos upar arquivos

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-popcorn/P_tor.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-popcorn/P_tor1.png)

2º Logamos e vamos até uploads

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-popcorn/P_tor2.png)

3º Upamos um .torrent qualquer da vida

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-popcorn/P_torrent.png)

4º Automaticamente ele redireciona para *My Torrents* clicamos em Edit This Torrent

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-popcorn/P_torrent2.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-popcorn/P_torrent3.png)

5º Tentamos upar uma imagem qualquer e mandamos a requisição para o *BurpSuite* pois fica melhor de trabalhar pois sabemos que é vulnerabilidade de upload

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-popcorn/P_tor3.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-popcorn/P_tor4.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-popcorn/P_tor5.png)

Mandamos pro *Repeater*

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-popcorn/P_tor6.png)

4º Modificamos a requisição, o corpo dela pra ser um cmd php para poder fazer o upload

Esse GIF89 que colocamos são os *Magic Numbers* de GIF, é pra aplicação PHP pensar que está sendo upado uma imagem

```
GIF89
<?php echo system($_REQUEST['cmd']); ?>
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-popcorn/P_tor7.png)

Modificamos no *BurpSuite*

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-popcorn/P_tor8.png)

Enviamos o arquivo

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-popcorn/P_tor9.png)

5º Ganhando RCE

Bom, uma vez upado nosso arquivo vamos até /upload e verificamos nosso arquivo upado

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-popcorn/P_tor10.png)

Testamos pra ver se temos RCE

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-popcorn/P_tor11.png)

6º Pegando um reverse shell

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-popcorn/P_tor12.png)

# Escalação de Privilégio

Uma vez com um shell válido na máquina, podemos iniciar a fase de escalação de privilégio

Iremos realizar a exploração de dois modos, uma delas é por Kernel a outra através de MOTD

## Exploração através do MOTD

Navegando através das pastas dos usuários da máquina encontramos dentro da pasta do George algo interessante

Verificmaos que o `MOTD` está habilitado

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-popcorn/P_priv.png)

Pesquimsamos por exploits para MOTD pelo searchsploit

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-popcorn/P_priv1.png)

Passamos ele para a máquina Popcorn

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-popcorn/P_priv2.png)

Executamos e ganhamos shell de root

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-popcorn/P_priv3.png)

## Exploração através de Kernel

Verificamos que ele tem uma versão antiga de Kernel

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-popcorn/P_kernel.png)

Procuramos por exploits para essa versão antiga

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-popcorn/P_kernel1.png)

> https://www.exploit-db.com/exploits/40839

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-popcorn/P_kernel2.png)

Verificamos que é vulnerável a Dirty Cow, passamos pra máquina Popocorn o exploit, compilamos e executamos

Ganhamos ROOT!

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-popcorn/P_kernel3.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-popcorn/P_kernel4.png)

### Pegamos a flag de user e root

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-popcorn/P_root.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-popcorn/P_user.png)