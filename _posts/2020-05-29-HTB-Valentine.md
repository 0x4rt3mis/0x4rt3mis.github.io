---
title: "Hack The Box - Valentine"
tags: [Linux,Easy,Heartbleed,Kernel,Wfuzz]
categories: HackTheBox OSCP
---

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-valentine/Valentine_inicial.png)

Link: <https://www.hackthebox.eu/home/machines/profile/127>

# Enumeração

## Primeiro passo é rodar o nmap contra a máquina, para verificar quais portas estão abertas e quais serviços estão sendo disponibilizados pelas portas.

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-valentine/Valentine_nmap.png)

### Explicação de cada parâmetro do Nmap

> -sC --> Rodar alguns scripts padrão em cada porta

> -sV --> Levantar qual serviço está rodando na porta

> -Pn --> Já considera o host ativo

### Verificamos que temos 3 portas abertas no servidor

> Porta 22 -> Servidor SSH, dificilmente a exploração vai ser por aqui

> Porta 80 e 443 -> Servidor Web

## Enumeração da porta 80

Vimos que é uma figura de uma mulher

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-valentine/Valentine_web.png)

### Rodamos o Wfuzz na máquina

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-valentine/Valentine_wfuzz.png)

### Verificamos o `encode` e `decode`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-valentine/Valentine_dec.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-valentine/Valentine_enc.png)

### Pelo nome da máquina, a imagem que aparece na porta 80, podemos inferir que seja HeartBleed, uma imagem que me ajudou a entender de maneira mais clara de como é o funcionamento dessa vulnerabilidade foi esse:

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-valentine/Valentine_img.png)

### Para comprovar que é vulnerável utilizaremos de um script do nmap

> nmap --script ssl-heartbleed 10.10.10.79

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-valentine/Valentine_vul.png)

### Encontramos o diretório `dev` e entramos nele

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-valentine/Valentine_web1.png)

#### Verificamos o arquivo hype, está em HEX devemos converter para ASCII

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-valentine/Valentine_hype.png)

### Passamos pra um arquivo e com o `xxd` fazemos a conversão

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-valentine/Valentine_xxd.png)

> xxd -r -p

> -r reverse / -p plaintext

### Vimos que é um chave ssh, só que ela está encryptada, temos dois caminhos aqui, podemos tentar quebrar essa criptografia dela com o john ou explorar o heartbleed na máquina pra ver se encontramos algo, vamos tentar explorar a máquina

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-valentine/Valentine_he.png)

#### O primeiro que pegamos está dando alguns erros, pelo que posso ver é do tamanho do payload, temos que diminuir, o servidor não está aceitando payloads tão grandes

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-valentine/Valentine_he1.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-valentine/Valentine_he2.png)

#### Conseguimos um base64 estranho

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-valentine/Valentine_hr4.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-valentine/Valentine_he3.png)


### Decodificamos e verificamos que parece ser uma senha

> heartbleedbelievethehype

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-valentine/Valentine_base64.png)

### Procuramos outro exploit só pra testar mesmo

#### Esse deve funcionar

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-valentine/Valentine_searchsploit.png)

> https://www.exploit-db.com/exploits/32745

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-valentine/Valentine_exploitdb.png)

#### Sucesso, também da certo

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-valentine/Valentine_exploitdb1.png)

# Exploração

### Logamos no ssh com essa senha que encontramos

Nota: não vamos fazer a quebra da chave ssh com pois a senha não vai estar em nenhuma wordlist conhecida

Logamos como `hype` pois a chave é pra hype_key, então inferimos que o usuário é hype

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-valentine/Valentine_ssh.png)

# Escalação de Privilégio

### Faremos de dois modos, o primeiro é o jeito "certo", rodando um script de enumeração o segundo é por Kernel

### Primeiro método: rodamos o LinEnum.sh

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-valentine/Valentine_lin.png)

### Verificamos que temos Tmux aberto nessa máquina

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-valentine/Valentine_tmux.png)

### Verificamos que está rodando como root

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-valentine/Valentine_tmux1.png)

### Entramos na seção de root

> tmux -S /.devs/dev_sess

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-valentine/Valentine_tmux2.png)

### Viramos root

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-valentine/Valentine_tmux3.png)

## Pegamos flag de user e root

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-valentine/Valentine_user.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-valentine/Valentine_root.png)

### Segundo método: Kernel

#### Com o `uname -a` verificamos que a versão do Kernel é bem antiga, então podemos utilizar por exemplo o Dirty Cow

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-valentine/Valentine_uname.png)

#### Pesquisamos por exploits no searchsploit

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-valentine/Valentine_searchsploit.png)

#### Utilizaremos primeiro esse que está grifado

#### Baixamos pra nossa máquina e compilamos

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-valentine/Valentine_dirty.png)

#### Enviamos pra máquina que será explorada, compilamos, executamos e ganhamos shell de root

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-valentine/Valentine_kernel3.png)

