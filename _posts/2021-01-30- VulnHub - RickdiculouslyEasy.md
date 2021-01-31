---
title: "VulnHub - RickdiculouslyEasy 1"
tags: [Linux, Easy, Gobuster, Wfuzz, BurpSuite, Hydra, Medusa, Sudo]
categories: VulnHub
---

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-rickdiculouslyeasy/inicial.png)

Link: [RickdiculouslyEasy](https://www.vulnhub.com/entry/rickdiculouslyeasy-1,207/)

# Enumeração

## Primeiro passo é rodar o arp-scan para detectarmos os hosts

```bash
arp-scan -I eth1 192.168.56.100/24
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-rickdiculouslyeasy/arp.png)

## Segundo passo é rodar o nmap contra a máquina, para verificar quais portas estão abertas e quais serviços estão sendo disponibilizados pelas portas.

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-rickdiculouslyeasy/nmap.png)

### Explicação de cada parâmetro do Nmap

> -sC --> Rodar alguns scripts padrão em cada porta

> -sV --> Levantar qual serviço está rodando na porta

> -Pn --> Já considera o host ativo

### Verificamos que temos 4 portas aberta no servidor

> Porta 21 -> FTP

> Porta 22 -> SSH

> Porta 80 -> Web

> Porta 9090 -> Web?!


## Enumeração da porta 9090

Assim que acessamos a página, achamos uma flag

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-rickdiculouslyeasy/flag3.png)

Tentamos rodar o gobuster, sem sucesso

```bash
gobuster dir -u http://192.168.56.115:9090 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 100
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-rickdiculouslyeasy/gobuster3.png)

Então, usamos o wfuzz

```bash
wfuzz -c --hh 41766,73,3410 -t 200 -w '/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt' -u 'http://192.168.56.115:9090/FUZZ'
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-rickdiculouslyeasy/wfuzz.png)

Bom, nada de útil...

## Enumeração da Porta 80

Primeira coisa é abrirmos a página web

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-rickdiculouslyeasy/web.png)

Rodamos o gobuster nela

```bash
gobuster dir -u http://192.168.56.115 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 100
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-rickdiculouslyeasy/gobuster.png)

Encontramos a página **/passwords**

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-rickdiculouslyeasy/gobuster1.png)

Encontramos a flag numero 2

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-rickdiculouslyeasy/flag2.png)

Acessamos o **passwords.html**

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-rickdiculouslyeasy/gobuster2.png)

Encontramos uma senha?!

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-rickdiculouslyeasy/passwordhtml.png)

Acessamos o **robots.txt** também

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-rickdiculouslyeasy/robots.png)

Acessamos o **cgi-bin**

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-rickdiculouslyeasy/trace.png)

Execução de comandos?

Bom, vamos jogar pro Burp pra melhor trabalhar

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-rickdiculouslyeasy/burp.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-rickdiculouslyeasy/burp1.png)

Repeater

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-rickdiculouslyeasy/burp2.png)

Simm! Temos RCE!

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-rickdiculouslyeasy/burp3.png)

Mas não conseguimos pegar um reverse shell.. possivelmente tem algum tipo de sanitização na página web que bloqueia alguns caracteres

Vamos prosseguir na emueração, que tal enumerarmos os usuário dessa máquina? Uma vez que temos uma senhas

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-rickdiculouslyeasy/tail.png)

```
RickSanchez:x:1000:1000::/home/RickSanchez:/bin/bash
Morty:x:1001:1001::/home/Morty:/bin/bash
Summer:x:1002:1002::/home/Summer:/bin/bash
```

Show, vamos seguir

## Enumeração da Porta 21

Tentamos login anonimo, conseguimos e baixamos a flag

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-rickdiculouslyeasy/ftp.png)

Mas vemos que não é possível vizualizar ela, isso é por causa que temos que mudar para modo binário o FTP, então acessamos novamente fazemos isso, baixamos a flag de novo e lemos ela

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-rickdiculouslyeasy/ftp1.png)

### Brute Force

Tentamos brute force com os usuário e a senha que temos

Com o Hydra

```bash
hydra -L users.txt -P senha.txt 192.168.56.115 ftp
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-rickdiculouslyeasy/hydra.png)

Com o Medusa (apenas para conhecimento)

```
for i in $(cat users.txt); do echo "$i:winter" >> credenciais.txt;done
for i in $(cat credenciais.txt); do echo 192.168.56.115:$i; done >> combo.txt
medusa -C combo.txt -M ftp 2> /dev/null
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-rickdiculouslyeasy/medusa.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-rickdiculouslyeasy/medusa1.png)

Tentamos logar no ssh com essas credenciais, e vemos que deu erro de certificado, mesmo a porta estando aberta, então temos que fazer mais alguma coisa pra realmente podermos acessar essa porta

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-rickdiculouslyeasy/ssh.png)

## Nmap Full Ports

Vamos fazer um nmap em todas as portas, pq aqui eu travei

Bacana... mais portas pra gente ver

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-rickdiculouslyeasy/FULL.png)

Enumeramos as novas portas

Encontramos mais uma flag!

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-rickdiculouslyeasy/full.png)

## Enumeração da Porta 60000

Opa, mais uma flag

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-rickdiculouslyeasy/flag5.png)

## Enumeração Porta 22222

Bacana... essa nos pareceu ser ssh, agora de verdade

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-rickdiculouslyeasy/ssh1.png)

Opa, mais uma flag

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-rickdiculouslyeasy/flag6.png)

# Summer -> RickSanchez

Bom, verificando nas pastas deles encontramos alguns arquivos que é interessante serem exfiltrados

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-rickdiculouslyeasy/exf.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-rickdiculouslyeasy/exf1.png)

Extraimos o zip

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-rickdiculouslyeasy/exf2.png)

Conseguimos outra flag

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-rickdiculouslyeasy/flag7.png)

Exfiltramos o outro arquivo que tinhamos visto, o **safe**

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-rickdiculouslyeasy/exf3.png)

Não conseguimos executar...

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-rickdiculouslyeasy/exf4.png)

Copiamos ele na máquina alvo para o diretório /tmp e damos permissão de execução pra ele

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-rickdiculouslyeasy/exf5.png)

A "dica" que recebemos foi na ultima flag, a string 131333, etão tentamos ela

Opa, outra flag! E a dica da senha do Rick

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-rickdiculouslyeasy/flag8.png)

Seguimos a dica

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-rickdiculouslyeasy/pass.png)

pass.py
```python
def main():
    LETTERS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    DIGITS = '0123456789'
    BAND_WORDS = ['The', 'Flesh', 'Curtains']
    with open('rickList.txt', 'w') as f:
        for letter in LETTERS:
            for digit in DIGITS:
                for word in BAND_WORDS:
                    f.write('{}{}{}\n'.format(letter, digit, word))
        f.flush()
if __name__ == '__main__':
    main()
```

Geramos a wordlist das senhas que vamos testar no brute force

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-rickdiculouslyeasy/pass1.png)

Agora fazemos o bruteforce, com o usuário RickSanchez (que pegamos no /etc/passwd)

```bash
hydra -l RickSanchez -P rickList.txt ssh://192.168.56.115 -s 22222
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-rickdiculouslyeasy/hydra1.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-rickdiculouslyeasy/hydra2.png)


Encontramos a senha dele... **RickSanchez:P7Curtains**

Acessamos via ssh

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-rickdiculouslyeasy/rick.png)

# RickSanchez -> Root

Agora vamos começar a enumeração da máquina para escalação de privilégio

Verificamos com o comando **sudo -l** que o usuário pode executar qualquer comando de root

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-rickdiculouslyeasy/sudo.png)

Viramos root

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-rickdiculouslyeasy/root.png)

Pegamos a flag que faltava!

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-rickdiculouslyeasy/flag9.png)