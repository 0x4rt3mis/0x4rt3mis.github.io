---
title: "Hack The Box - Writeup"
tags: [Linux,Easy,Web,PSPY,Linpeas]
categories: HackTheBox
---

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-writeup/Writeup_inicial.png)

Link: <https://www.hackthebox.eu/home/machines/profile/188>

# Enumeração

## Primeiro passo é rodar o nmap contra a máquina, para verificar quais portas estão abertas e quais serviços estão sendo disponibilizados pelas portas.

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-writeup/Writeup_nmap.png)

### Explicação de cada parâmetro do Nmap

> -sC --> Rodar alguns scripts padrão em cada porta

> -sV --> Levantar qual serviço está rodando na porta

> -Pn --> Já considera o host ativo

### Verificamos que temos 2 portas abertas no servidor

> Porta 22 -> Servidor SSH, dificilmente a exploração vai ser por aqui

> Porta 80 -> Servidor Web.

## Enumeração da porta 80

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-writeup/Writeup_web.png)

Veriricamos que tem um fail2ban configurado (Quer dizer que não podemos realizar ataques de força bruta, como por exemplo Wfuzz)

### Tentamos diretórios comuns

> /robots.txt

Encontramos um diretório "Desabilitado"

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-writeup/Writeup_web1.png)

Entramos na página /writeup

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-writeup/Writeup_web2.png)

No código fonte descobrimso que o site foi feito por um CMS

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-writeup/Writeup_web4.png)

> CMS Made Simple

# Exploração

#### Procuramos por exploits para CMS Made Simple

Tem uma porrada, mas não sabemos a versão que está rodando

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-writeup/Writeup_search.png)

##### Então vamos procurar a versão

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-writeup/Writeup_cms.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-writeup/Writeup_cms1.png)

#### Agora que já sabemos como ver a versão do CMS, vemos a que está instalada na máquina

> Version 2.2.9.1

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-writeup/Writeup_cms2.png)

### Pesquisamos novamente por exploits com a versão específica

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-writeup/Writeup_exp.png)

`Melhorou, não?!`

### Copiamos o exploit para nossa pasta de trabalho, vemos como ele funciona e executamos!

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-writeup/Writeup_exp1.png)

Consegumos a senha

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-writeup/Writeup_exp2.png)

> jkr:raykayjay9

### Como sabemos que tem SSH na máquina, tentamos logar

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-writeup/Writeup_exp3.png)

# Escalação de Privilégio

### Rodamos o `LinPeas` na máquina para procurar por pontos de escalação de privilégio

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-writeup/Writeup_lin.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-writeup/Writeup_lin1.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-writeup/Writeup_lin3.png)

#### Estranhamento verificamos que podemos escrever no PATH do usuário

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-writeup/Writeup_lin2.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-writeup/Writeup_path.png)

#### Mesmo assim não encontramos nada que possa ser útil de certo modo para escalação de privilégio, vamos tentar rodar o pspy na máquina para veriricar o que está sendo executado

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-writeup/Writeup_pspy.png)

#### Passamos pra máquina e executamos

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-writeup/Writeup_pspy1.png)

#### De cara rodando ele não encontramos nada, mas se tentarmos fazer outra conexão ssh para a máquina ele executa um processo que está no nosso path

##### `run-parts`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-writeup/Writeup_pspy2.png)

### Verificamos que o grupo `staff` o qual fazemos parte pode escrever nessa pasta que está no path do usuário

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-writeup/Writeup_id.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-writeup/Writeup_pspy3.png)

### Fazemos nosso exploit, criando um run-parts no path do usuário para enviar um shell pra mim

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-writeup/Writeup_run.png)

### Executo uma nova conexão ssh com um listener aberto e ganhamos shell de root

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-writeup/Writeup_shell.png)

### Pegamos as flags de user e root

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-writeup/Writeup_user.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-writeup/Writeup_root.png)
