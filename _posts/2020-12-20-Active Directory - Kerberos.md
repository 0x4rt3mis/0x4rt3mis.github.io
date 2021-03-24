---
title: "Active Directory - Kerberos"
tags: [Windows,Active Directory]
categories: ActiveDirectory
---

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/active-enum/constrained.png)

# Considerações Iniciais

Agora vamos um pouco mais fundo na nossa exploração dentro do Active Directory, vamos brincar com o `Kerberos` que o servidor de autenticação do AD.

Logicamente minhas explicações vão ser bem simples e não esgotam todo o assunto, mas lhe dará uma base para estudos futuros

Aqui serão realizados os ataques de `Kerberoast`, `Constrained Delegation` e `Unconstrained Delegation`

## Como funciona o Kerberos?

Sempre que um usuário requisita o acesso a um serviço disponibilizado dentro do ambiente do Active Directory ele percorre esse caminho da figura abaixo

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/active-enum/kerberos.gif)

Que está "explicado" aqui:

Passo 1 -> O cliente solicita um TGT para o servidor do kerberos, o servidor checa o time stamp

Passo 2 -> o KDC (Key Distribution Center) manda um TGT, Ticket Grant Ticket, um ticket que garante acesso para um ticket que vai ser o TGS, ele é encriptado, assinado pelo hash do krbtgt (por isso quando pegamos o hash do krbtgt conseguimos controle sobre o AD)

Passo 3 -> O cliente manda o TGT de volta para o DC, para provar que o cliente tem um domain user logged in vaĺido. Me da um TGS já que sou eu mesmo, sou válido para todo o AD.

Passo 4 -> O KDC encripta o TGT, a unica validação que ele faz é se ele pode desincriptar o TGT com o hash do kerberos, então aqui é vulnerável, uma vez que conseguimos forjar um ticket qualquer com o hash do krbtgt podemos nos passar por qualquer um, pq ele vai validar o TGS e nos dar acesso a qualquer servidor/serviço que esteja dentro do AD!

Passo 5 -> o usuário se conecta ao serviço que ele requisitou, enviando o TGS que já foi validado

Passo 6 -> Ele fornece a autenticação, e da acesso ao serviço requisitado pelo cliente

O que me espanta mais é descobrir que `TODOS` os passos são vulneráveis e passíveis de algum tipo de exploração.

### Como assim todas vulneráveis?

Simmmmm, isso mesmo, todos os passos são passíveis de algum tipo de ataque, aqui vamos tentar explicar e explorar eles, logicamente não vai clarificar 100% dos conceitos, mas novamente, segue como base para estudos futuros, e por favor, caso tenha sugestões ou ache algum erro nas minhas explicações, me avise!

# Kerberoast

Esse "ataque" explora os passos `3` e `4`

No passo 3 o TGT, que foi apresentado pelo KDC/DC, podemos requisitar a autorização para qualquer serviço, uma vez que a única autenticação que ele faz é se ele pode desincriptar com o krbtgt hash

Requisitamos o ticket de um serviço que está sendo executado com *privilégios avançados*, vulgo SPN, `Service Principal Name`

Com o comando `Get-NetUser -SPN` verificamos quais usuários estão com essas permissões habilitadas, no caso em questão verificamos que o usuário `sqlreportuser` está como SPN

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/active-enum/spn.png)

Uma vez sabendo disso podemos requisitar o Ticket dele para nossa seção

`Request-SPN Ticket MSSQLSvc/xxxxxxxx`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/active-enum/spn1.png)

Verificamos que o Ticket foi injetado na nossa seção

`klist`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/active-enum/spn2.png)

Agora podemos exportar ele para quebrar a senha offline

`Invoke-Mimikatz -Command '"kerberos::list /export"'`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/active-enum/spn3.png)

Ele foi salvo para um arquivo `.kirbi`

Agora passamos ele para nossa Kali e com o utilitário Kirbi2John transformamos em um formato que pode ser lido pelo John

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/active-enum/spn4.png)

Agora quebramos a senha

`john --wordlist=./filtered_top_100k.txt ticket.hash`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/active-enum/spn5.png)

Esse foi o ataque conhecido como `Kerberoast`, agora vamos para um que é mais complexo que é o Delegation

# Delegation

A principal ideia desse ataque é entender a reutilização de credenciais que o Kerberos permite realizar.

Kerberos Delegation permite a reutilização de credenciais para acessar recursos em diferentes hosts, isso mesmo, reutilizar o ticket. Isso é muito útil quando falamos de serviços de diversas camadas ou aplicações onde o Double Hop do Kerberos é necessário, por exemplo, temos a situação que um usuário se autentica a um servidor web e o servidor web por sua vez faz a requisição para um banco de dados, o servidor web consegue simplesmente  acessar recursos (alguns) na database como se fosse o usuário e não como sendo o web server service account. E assim tendo o acesso que ele precisa ter no servidor remoto, percebe-se que é necessário o trusted for delegation para se realizar essa requisição como usuário.

Confuso ainda? Vamos tentar explicar melhor...

Mas, por que diabos isso foi implementado?

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/active-enum/diag.png)

1) Usuário da suas credenciais para o Domain Controler

2) O DC o devolve um TGT.

3) O usuário requisita o TGS para o servidor web.

4) O DC provê o TGS.

5) O usuário manda o TGT e o TGS do database server para o DC.

6) O servidor web (service account) se conecta à database como se usuário fosse.

Esse é o procedimento que sempre é feito quando nos autentiacamos no servidor. A ideia da exploração dessas fases é sempre o `IMPERSONIFICATION`, você se passar pelo usuário pra obter os acessos que teoricamente ele tem nas outras máquinas.

Temos dois tipos de Delegation, o Unconstrained e o Constrained, vamos agora passar pra explicação de cada um deles.

# Unconstrained Delegation

Os primeiros 4 passos, do diagrama anterior, são básicos, sempre vai ter, que é a criação/requisição do TGT e do TGS.

Como o Web Server tem Unconstrained permission, o DC coloca o TGS junto com o TGT (passo número 4 e 5 do diagrama anterior), o Web Server, que tem o unconstrained habilitado extrai o TGT do token e se autentica a quem ele quiser como o user que enviou

Podemos utilizar para escalação de privilégio, mas como? Se um Domain Admin se conectar a uma máqunina que tenha o Unconstrained Delegation habilitado, ele gerará um ticket na seção e nós poderemos extrair ele e reutilizar! Sim, reutilizar o ticket da seção na nossa seção, e sendo assim ter acesso à locais onde normalmente não teríamos.

## Verificando máquinas com `Unconstrained Delegation` habilitado

Para verificarmos quais máquina estão com o Unconstrained Delegation habilitado, devemos recorrer ao `PowerView.ps1` com o comando

`Get-NetComputer -Unconstrained`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/active-enum/UNC.png)

Aqui no caso eu escondi o nome das máquinas, e coloquei como sendo a ABC-UNC a máquina com o Unconstrained habilitado

Assim verificamos as máquinas que possuem, o DC sempre vai ter, é nativo dele essa permissão.

## Explorando Unconstrained Delegation

Para podermos explorar isso, devemos ter acesso a essa máquina, e acesso Administrativo, uma vez que iremos utilizar o `Mimikatz` para realizar a extração do ticket

Ao verificarmos a máquina que tem isso, e com acesso de administrator nela, exportamos os tickets

`Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "sekurlsa::tickets /export"'`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/active-enum/unc1.png)

Verificamos os tickets que foram exportados dentro da pasta e lá vemos que temos um que é de `Administrator` de outra máquina

ABC-ADMINPROD1 (Logicamente mudei os nomes pra não expor o servidor que estou fazendo isso)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/active-enum/unc2.png)

## Pass-The-Ticket

Agora realizamos o Pass-The-Ticket e reinjetamos esse ticket em nossa seção, tendo assim acesso ao servidor como Admin

`Invoke-Mimikatz -Command '"kerberos::ptt TICKET_QUE_FOI_VISTO"'`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/active-enum/unc3.png)

Pronto, ticket "reutilizado", agora temos acesso ao servidor normalmente

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/active-enum/unc4.png)

Esse é o Unconstrained Delegation, temos acesso praticamente total ao servidor.

A microsoft verificou que isso era muito perigoso (e com razão), ai implementou outro tipo de Delegation, a Constrained, que limita quais acessos o SPN vai ter na máquina.

# Constrained Delegation

Bom, verificando que isso era perigoso deixar habilitado o Unconstrained, a Microsoft criou o Constrained Delegation, onde apenas alguns serviços são disponibilizados, não o  acesso à máquina como era no Unconstrained. Aqui no caso um usuário específico tera permissões diretas na máquinas.

Verificamos que o usuário dbservice tem permissões de `AllowedToDelegate` que são necessárias para o Constrained Delegation (Através do BloodHound, que será trabalhado depois)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/active-enum/constrained2.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/active-enum/constrained3.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/active-enum/constrained4.png)

Para verificarmos quais usuário estão com o Constrained Habilitado em quais Máquinas devemos utilizar o `PowerView.ps1` so que agora em sua versão `Dev`

[PowerView-Dev.ps1](https://github.com/lucky-luk3/ActiveDirectory/blob/master/PowerView-Dev.ps1)

`Get-DomainUser -TrustedToAuth`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/active-enum/constrained1.png)

## Explorando o Constrained Delegation

Uma vez que temos o constrained habilitado, e sabemos que o usuário `dbservice` nessa caso tem essas permissões, vamos iniciar a exploração.

1º Verificamos que realmente não tem acesso à máquina onde o dbservice tem o constrained

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/active-enum/constrained5.png)

2º Perguntamos ao KDC pelo TGT do dbservice

Não irei demonstrar aqui como fazemos a captura do hash NTLM do usuário, isso fica pro post a respeito do `Mimikatz`

Para isso vamos utilizar o `kekeo`

[Kekeo](https://github.com/gentilkiwi/kekeo)

`tgt::ask /user:dbservice /domain:DOMINIO.LOCAL /ntlm:HASH.NTLM.DBSERVICE /ticket:dbservice.kirbi`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/active-enum/constrained6.png)

3º Gerar o TGS para os serviços que queremos explorar

Agora é gerar o TGS para os serviços, o serviço que está "vulnerável" é o TIME mas podemos gerar tickets também para o cifs, para podermos acessar a partição dele

`tgs::s4u /tgt:TGT_dbservice.kirbi /user:Administrator@DOMÍNIO /service:time/MÁQUINA.LOCAL|cifs/MÁQUINA.local`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/active-enum/constrained7.png)

Pronto, foram criados os tickets para o serviço TIME e para o CIFS, sendo assim agora vamos injetar eles na seção

4º Injetar os tickets na seção

`Invoke-Mimikatz -Command '"kerberos::ptt TICKET_GERADO"'`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/active-enum/constrained8.png)

5º Acessar o share da máquina

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/active-enum/constrained9.png)

Pronto, essas foram as principais vulnerabilidades que podemos explorar dessa maneira.