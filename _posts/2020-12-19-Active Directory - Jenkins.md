---
title: "Active Directory - Jenkins"
tags: [Windows,Active Directory]
categories: ActiveDirectory
---

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/active-enum/jenkins.png)

# Considerações Iniciais

Bom, agora vamos explorar o servidor do Jenkins que está na máquina de modo a conseguir acesso nela.

O que é `Jenkins`?

É uma ferramenta de integração contínua, automatizada, que traz diversos benefícios. A principal funcionalidade dela é construir o projeto por completo de forma automática, rodando os testes disponíveis, a fim de detectar antecipadamente os erros, reduzindo riscos.

# Realizando Port Scan

Não necessariamente precisamos realizar um port scan, tendo em vista o Jenkins funcionar nativamente na porta 8080, mas é o caso apenas para conhecimento

`8080 | % {echo ((new-object Net.Sockets.TcpClient).Connect("ip",$_)) "Port $_ is open!"} 2>$null`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/active-enum/jenkins1.png)

Ai se quisessemos um range de portas, seria 1..6000 por exemplo ao invés de 8080

# Acessando servidor Jenkins

Uma vez sabendo que está sendo rodado algo na porta 8080, vamos verificar se realmente é um servidor Jenkins

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/active-enum/jenkins2.png)

Sim, confirmamos que é um jenkins!

## BruteForce

Após enumerarmos um pouco encontramos diversos usuários, mas nenhum nós temos a senha, então vamos realizar um brute force pra podermos ter acesso ao painel de comandos do jenkins e assim ganhar RCE

O script utilizado é esse

[Brute Force Jenkins](https://github.com/chryzsh/JenkinsPasswordSpray)

Agora realizamos o Brute Force

`Invoke-JenkinsPasswordSpray -URL http://ip:8080 -UsernameFile .\users.txt -PasswordFile .\10k-worst-passwords.txt -ContinueOnSuccess $true -Force -Outfile .\sprayed-jenkins.txt`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/active-enum/jenkins3.png)

Bom, após um tempo conseguimos uma credencial!

## Logando na Aplicação

Com a credencial, logamos!

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/active-enum/jenkins4.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/active-enum/jenkins5.png)

## Ganhando RCE

Adicionamos um Job para execução de comandos

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/active-enum/jenkins6.png)

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

## Ganhando Reverse Shell

Executamos e ganhamos um reverse shell ao clicar em `Build Now` dentro do projeto que foi alterado!

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/active-enum/jenkins7.png)

# Conclusão

Vimos aqui uma maneira simples de conseguir acesso a uma máquina que está rodando um servidor Jenkins!

## Comandos Utilizados

`8080 | % {echo ((new-object Net.Sockets.TcpClient).Connect("ip",$_)) "Port $_ is open!"} 2>$null`

`Invoke-JenkinsPasswordSpray -URL http://ip:8080 -UsernameFile .\users.txt -PasswordFile .\10k-worst-passwords.txt -ContinueOnSuccess $true -Force -Outfile .\sprayed-jenkins.txt`

`powercat -l -v -p 443 -t 1000`