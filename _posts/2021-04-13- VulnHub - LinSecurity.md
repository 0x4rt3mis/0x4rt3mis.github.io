---
title: "VulnHub - LinSecurity"
tags: [Linux,Easy]
categories: VulnHub OSCP
---

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-linsecurity/inicial.png)

Link: [LinSecurity](https://www.vulnhub.com/entry/linsecurity-1,244/)

# Enumeração

## Primeiro passo é rodar o arp-scan para detectarmos os hosts

```bash
arp-scan -I eth1 192.168.56.0/24
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-linsecurity/arp.png)

## Segundo passo é rodar o nmap contra a máquina, para verificar quais portas estão abertas e quais serviços estão sendo disponibilizados pelas portas.

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-linsecurity/nmap.png)

Full ports scan

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-linsecurity/nmap1.png)

### Explicação de cada parâmetro do Nmap

> -sC --> Rodar alguns scripts padrão em cada porta

> -sV --> Levantar qual serviço está rodando na porta

> -Pn --> Já considera o host ativo

> -T5 --> Modo insano

### Verificamos que temos 7 portas abertas no servidor

> Porta 22 -> SSH

> Porta 111 -> RPC

> Portas 2049, 36239, 36361, 55973, 58967 -> NFS

## Enumeração da Porta 2049

Possivelmente temos que montar um servidor de NFS na exploração dessa máquina em particular

```bash
showmount -e 192.168.56.149
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-linsecurity/nfs.png)

Aqui montamos e não achamos nada

```bash
mkdir NFS
mount 192.168.56.149:/ ./NFS
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-linsecurity/nfs1.png)

## Enumeração SSH -> Root

Verificando na descrição da máquina no VulnHub encontramos algo interessante

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-linsecurity/ssh.png)

Entramos na máquina

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-linsecurity/ssh1.png)

Enumeramos os comandos do sudo

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-linsecurity/ssh2.png)

Viramos root!

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-linsecurity/ssh3.png)

Lemos a flag dentro do home da susan

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub/vulnhub-linsecurity/flag.png)