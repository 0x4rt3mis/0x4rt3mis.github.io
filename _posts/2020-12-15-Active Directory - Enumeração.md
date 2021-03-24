---
title: "Active Directory - Enumeração"
tags: [Windows,Active Directory]
categories: ActiveDirectory
---

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/active-enum/enum.jpeg.png)

# Considerações Iniciais

Agora vamos iniciar a enumeração de um Active Directory, que é o primeiro passo a ser realizado em qualquer atividade ofensiva.

A ferramenta que utilizarei para essa seção é o PowerView.ps1, um script escrito em PowerShell que possibilita a enumeraçã rápida e precisa de tudo (quase) que existe dentro do ambiente AD!

Link para download do Script

[PowerView](https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1)

E claro, obviamente, esconderei todas as menções para qual ambiente estou realizando a enumeração, aqui é apenas para fins didáticos!

# Domain Enumeration

Vamos iniciar e enumeração!

Logicamente após termos baixado o script devemos realizar a importação dele, com o comando `Import-Module PowerView.ps1`

## User Enumeration

O comando para realização da enumeração de usuários dentro de ambiente AD é

`Get-NetUser | select Name`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/active-enum/user.png)

E aqui são listados todos os usuários que estão cadastrados dentro do Active Directory.

## Group Enumeration

O comando para realização da enumeração de grupos dentro de ambiente AD é

`Get-NetGroup | select Name`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/active-enum/group.png)

E aqui estão todos os grupos dentro do AD.

## Enumeração de Computadores

Sim, isso mesmo, podemos vizualizar todos os computadores que estão cadastrados dentro do domínio!

O comando para isso é:

`Get-NetComputer | select Name`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/active-enum/computer.png)

A partir dai já começamos a ver quais são nossos possíveis alvos!

## Enumeração de Domain Admins

O comando para enumerarmos todos os Domains Admins é:

`Get-NetGroupMember "Domain Admins"`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/active-enum/da.png)

## Enumeração dos Shares

Também podemos verificar todos os shares disponíveis no AD, pastas que teremos acesso.

`Invoke-ShareFinder`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/active-enum/share.png)

## Enumeração de ACLs

ACLs são as permissões que eles tem dentro do AD, no caso cada Objeto

`Get-ObjectAcl -SamAccountName "Domain Admins"`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/active-enum/acl1.png)

Assim verificamos todas as ACLS de todos os grupos

`Get-ObjectAcl -SamAccountName "Domain Admins" -ResolveGUIDs`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/active-enum/acl2.png)

## Enumerçação dos OUs 

`Get-NetOU select | name`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/active-enum/ou.png)

## Enumeração dos Trusts do Domain em que estou

A ideia agora é enumerarmos os trusts que nosso domínio tem no FOREST

`Get-NetDomainTrust`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/active-enum/trust.png)

Com o `Get-NetForestDomain` nós verificamos todos os domínios no corrente forest, 

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/active-enum/trus_domaint.png)

Com o comando `Get-NetForestTrust` nós verificamos os trusts do nosso forest

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/active-enum/trust2.png)

Isso é importante pq com esse trust bidirecional nós podemos enumerar o outro domínio também (fora do nosso) no caso o que apareceu ali no comando acima

`Get-NetComputer -Domain dominio_que_aparece.local | select name`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/active-enum/trust3.png)

Essas são as máquinas acessíveis em outro forest através do trust que temos no nosso domain! Interessante!

## Enumeração de USER HUNTING

Com ele verificamos se em alguma máquina no domínio nós tem local admin access (MUITO BARULHENTO)

`Find-LocalAdminAccess`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/active-enum/admin.png)

Aqui não deu saida por que não tenho acesso administrativo em nenhuma máquina com meu usuário

Outra função muito importante é a Invoke-UserHunter, ela faz a mesma coisa que a Find-LocalAdminAccess

`Invoke-UserHunter`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/active-enum/admin1.png)

Aqui não deu saida por que não tenho acesso administrativo em nenhuma máquina com meu usuário

# Concluindo

Uma boa enumeração sempre é de extrema importância em qualquer ambiente que nos deparamos. Ela não termina por aqui, tem muito mais a ser explorado ainda, contudo para uma análize inicial.

## Resumindo

Resumindo o que foi feito, primeiro devemos ter a ferramenta PowerView (https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1), para podermos realizar a enumeração.

Comandos utilizados.

`Get-NetUser | select Name`
`Get-NetGroup | select Name`
`Get-NetComputer | select Name`
`Get-NetGroupMember "Domain Admins"`
`Invoke-ShareFinder`
`Get-ObjectAcl -SamAccountName "Domain Admins"`
`Get-ObjectAcl -SamAccountName "Domain Admins" -ResolveGUIDs`
`Get-NetOU select | name`
`Get-NetDomainTrust`
`Get-NetForestDomain`
`Get-NetForestTrust`
`Get-NetComputer -Domain dominio_que_aparece.local | select name`
`Find-LocalAdminAccess`
`Invoke-UserHunter`

Agora vamos para a enumeração de servidores MSSQL