---
title: "Active Directory - PSSession"
tags: [Windows,Active Directory]
categories: ActiveDirectory
---

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/active-enum/pssesion.png)

# Considerações Iniciais

Bom, agora vamos utilizar o `PSSession` para entar em outras seções e com isso explorar máquina também!

Mas o que é PSSESION?

*Especifica uma sessão do Windows PowerShell (PSSession) a ser usada para a sessão interativa. Esse parâmetro assume um objeto de sessão.*

Em outras palavras, uma nova seção, como se fosse um 'ssh'.

# Verificando Conectividade

Devemos verificar em quais máquinas temos acesso de administrator com o usuário corrente, pois somente nelas que iremos conseguir realizar o PPSession

O comando para testar conectividade é esse

```
$computers=( Get-WmiObject -Namespace root\directory\ldap -Class ds_computer | select  -ExpandProperty ds_cn)
foreach ($computer in $computers) { (Get-WmiObject Win32_ComputerSystem -ComputerName $computer ).Name }
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/active-enum/pssesion1.png)

# Entrando na Seção

Bom, agora que sabemos que temos conectividade, vamos testar a conexão e entrar na seção!

`Invoke-Command –Scriptblock {ipconfig} -ComputerName máquina_com_acesso`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/active-enum/pssesion2.png)

Criamos uma seção nova com o `New-PSSession`

`$sess = New-PSSession -ComputerName máquina_com_acesso`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/active-enum/pssesion3.png)

Ai está! Agora é só entrarmos na seção

`Enter-PSSession -Session $sess`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/active-enum/pssesion4.png)

Obs: Com o `-FilePath` podemos inserir scripts diretamente dentro da seção

Por exemplo:

`Invoke-Command -FilePath "C:\Users\script.ps1" -session $sess`

# Conclusão

Verificamos agora a utilidade do PSSession em um ambiente ofensivo, toda máquina que conseguirmos acesso de administrator estará habilitada o pssession remoto!

# Comandos Utilizados

```
$computers=( Get-WmiObject -Namespace root\directory\ldap -Class ds_computer | select  -ExpandProperty ds_cn)
foreach ($computer in $computers) { (Get-WmiObject Win32_ComputerSystem -ComputerName $computer ).Name }
```

`Invoke-Command –Scriptblock {ipconfig} -ComputerName máquina_com_acesso`

`$sess = New-PSSession -ComputerName máquina_com_acesso`

`Enter-PSSession -Session $sess`

`Invoke-Command -FilePath "C:\Users\script.ps1" -session $sess`