---
title: "VulnHub - InfoSec Prep: OSCP"
tags: [Linux, Easy, Gobuster, Bash SUID, lxd, Linpeas]
categories: VulnHub OSCP
---

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-infosecprep/inicial.png)

Link: [GoldenEye1](https://www.vulnhub.com/entry/goldeneye-1,240/)

# Enumeração

## Primeiro passo é rodar o arp-scan para detectarmos os hosts

```bash
arp-scan -I eth1 192.168.56.0/24
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-infosecprep/arp.png)

## Segundo passo é rodar o nmap contra a máquina, para verificar quais portas estão abertas e quais serviços estão sendo disponibilizados pelas portas.

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-infosecprep/nmap.png)

Full ports scan

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-infosecprep/nmap1.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-infosecprep/nmap2.png)


### Explicação de cada parâmetro do Nmap

> -sC --> Rodar alguns scripts padrão em cada porta

> -sV --> Levantar qual serviço está rodando na porta

> -Pn --> Já considera o host ativo

> -T5 --> Modo insano

### Verificamos que temos 3 portas aberta no servidor

> Porta 80 -> Web

> Porta 22 -> SSH

> Porta 33060 -> MYSQL?!

## Enumeração da Porta 80

Entramos pra ver do que se trata o site

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-infosecprep/web.png)

Gobuster nele

```bash
gobuster dir -u http://192.168.56.122 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php -t 100
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-infosecprep/gobuster.png)

Vamos iniciar pel WordPress

### WordPress

```bash
wpscan --url http://192.168.56.122/ -e vt,tt,u,ap --api-token ....rIrG0sdZx4....
```

Explicação

```
-e --> Enumerar

vt,tt,u,ap --> Temas vulneráveis, timthumbs, usuários, todos os plugins (respectivamente)
```

Rodamos então

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-infosecprep/wp.png)

Encontramos um usuário e um tema desatualizado

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-infosecprep/wp1.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-infosecprep/wp2.png)

Nada de muito relevante... vamos prosseguir

Acessamos o robots.txt

### robots.txt

Opa, secret.txt, interessante

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-infosecprep/robots.png)

Verificamos então

Parece ser base64

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-infosecprep/secret.png)

Decodificamos e pelo que parece é uma chave ssh!

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-infosecprep/secret1.png)

Sim, temos a chave... falta o usuário agora...

Aqui está

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-infosecprep/user.png)

"oscp"

# oscp -> Root

Bom, vamos entrar na máquina e iniciar a escalação de privilégio

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-infosecprep/ssh.png)

Para enumeração rodamos o linpeas

[Linpeas](https://raw.githubusercontent.com/carlospolop/privilege-escalation-awesome-scripts-suite/master/linPEAS/linpeas.sh)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-infosecprep/lin.png)

Baixamos pra nossa máquina

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-infosecprep/lin1.png)

Rodamos no servidor

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-infosecprep/lin2.png)

Bom, encontramos o BASH com o SUID habilitado...

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-infosecprep/lin3.png)

Somos sudo... Fazemos parte do grupo lxd... interessante... temos bastante coisa pra explorar aqui

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-infosecprep/lin4.png)

## 1º Modo - bash

Primeiro modo que vamos tentar é através do bash

Verificando no [GTFobins](https://gtfobins.github.io/gtfobins/bash/) é simples...

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-infosecprep/gt.png)

Executamos

```bash
/bin/bash -p
```

Somos root!

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-infosecprep/bash.png)

Pegamos a flag

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-infosecprep/flag.png)

## 2º Modo - lxd

Referencias:

[FalconSPY](https://falconspy.medium.com/infosec-prep-oscp-vulnhubwalkthrough-a09519236025)

[TrenchesofIT](https://www.trenchesofit.com/2020/07/25/oscp-voucher-giveaway-vm-using-unintended/)

Outro modo de se escalar privilégio nessa máquinas é através das permissões que temos no grupo

Baixamos o alpine pra nossa Kali

```
git clone https://github.com/saghul/lxd-alpine-builder.git
cd lxd-alpine-builder/
./build-alpine

ls
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-infosecprep/lxd.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-infosecprep/lxd1.png)

Passamos pra máquina

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-infosecprep/lxd2.png)

Procuramos o binário que iremos executar, uma vez que não é o padrão do path

```bash
find / -name lxc > lxcsearch.txt 2>/dev/null
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-infosecprep/lxd3.png)

Importamos a imagem

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-infosecprep/lxd4.png)

Não deu! Então vamos baixar uma pronta já, pra facilitar o trabalho...

[Alpine](https://alpinelinux.org/downloads/)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-infosecprep/lxd5.png)

Jogamos pra máquina

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-infosecprep/lxd6.png)

Também não deu... não vou ficar debugando pq deu errado não... quando tiver mais tempo volto aqui e vejo...