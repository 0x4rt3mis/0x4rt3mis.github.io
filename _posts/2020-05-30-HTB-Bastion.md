---
title: "Hack The Box - Bastion"
tags: [Windows,Easy,Secretsdump,Impacket,Smbclient,Mount,Guestmount,SAM,Psexec,Smbmap]
categories: HackTheBox OSCP
---

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bastions/Bastion_inicial.png)

Link: <https://www.hackthebox.eu/home/machines/profile/186>

# Enumeração

## Primeiro passo é rodar o nmap contra a máquina, para verificar quais portas estão abertas e quais serviços estão sendo disponibilizados pelas portas.

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bastions/Bastion_nmap.png)

### Explicação de cada parâmetro do Nmap

> -sC --> Rodar alguns scripts padrão em cada porta

> -sV --> Levantar qual serviço está rodando na porta

> -Pn --> Já considera o host ativo

### Verificamos 4 portas abertas no servidor

> Porta 22 - SSH? Em uma máquina Windows... interessante

> Porta 135,139,445 - Todas relacionadas ao Samba

### Vamos começar a enumeração pela porta 445

> smbclient -L \\10.10.10.134

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bastions/Bastion_smb.png)

# Exploração / Escalação de Privilégio

### Muito interessante, verificamos que temos uma pasta `backups` que temos permissão... vamos montar ela então pra vasculhar!

> mount cifs 

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bastions/Bastion_mount.png)

### Poderiamos ter realizado essse procedimento com o smbclient

### Navegando nas pastas encontramos um note.txt

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bastions/Bastion_note.png)

Não é útil pra gente.

### Navegando um pouco mais encontramos vários arquivos *vhd*

> Arquivos .vhd são imagens de HD (opa, será que não teria uma credencial ai?!)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bastions/Bastion_vhd.png)

### Vamos montar eles! (Demora cerca de 5 min pra realizar a montagem)

> https://medium.com/@klockw3rk/mounting-vhd-file-on-kali-linux-through-remote-share-f2f9542c1f25

> guestmount --add 9b9cfbc4-369e-11e9-a17c-806e6f6e6963.vhd --inspector --ro -v /mnt/vhd

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bastions/Bastion_mount2.png)

### Após montado verificamos a pasta, encontramos um arquivo SAM (arquivos que guardam credenciais no Windows)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bastions/Bastion_sam.png)

### Com o `secretsdump.py` do Impacket nós extraímos hashes de usuários

> secretsdump.py -sam SAM -system SYSTEM local

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bastions/Bastion_dump.png)

#### Bom, já temos um login, poderíamos tentar executar um psexec, contudo não vai dar pois não tenho permissão de escrita nas pastas C$ e Admin$.

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bastions/Bastion_psexec.png)

### Lembra do SSH? Que tal tentarmos logar nele?

##### Primeira coisa é quebrar o hash, depois logar

> bureaulampje - L4mpje

Crackstation - https://crackstation.net/

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bastions/Bastion_hash.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bastions/Bastion_ssh.png)

### Verificamos dentro do ProgramFiles um programa instalado estranho, o `mRemonteNG`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bastions/Bastion_mremote.png)

#### Esse blog nos diz sobre a insegurança de utilizar o mRemoteNG

> http://hackersvanguard.com/mremoteng-insecure-password-storage/

> mRemoteNG salva as conexões e informações sobre credenciais no arquivo confCons.xml

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bastions/Bastion_conf.png)

> Username="Administrator" Domain="" Password="aEWNFV5uGcjUHF0uS17QTdT9kVqtKCPeoC0Nw5dmaPFjNQ2kt/zO5xDqE4HdVmHAowVRdC7emf7lWWA10dQKiw=="

### Ele está encriptado, então procuramos por uma ferramenta para realizar a decriptação dessa senha

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bastions/Bastion_decrypt.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bastions/Bastion_git.png)

> thXLHM96BeKL0ER2

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bastions/Bastion_senha.png)

### Verificamos com o `smbmap` se podemos utilizar o psexec

> Sim!! Podemos, uma vez que temos permissão para escrever nos diretórios C$ e ADMIN$

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bastions/Bastion_smbmap.png)

### Executamos o psexec e ganhamos root

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bastions/Bastion_psexec.png)

### Pegamos a flag de root e user

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bastions/Bastion_user.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-bastions/Bastion_root.png)