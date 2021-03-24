---
title: "Active Directory - BloodHound"
tags: [Windows,Active Directory]
categories: ActiveDirectory
---

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/active-enum/blood.png)

# Considerações Iniciais

O BloodHound é uma técnica muito utiliza por Red e Blue Teamers para verificação de como está estruturado o AD. Ele permite ter um overview muito bacana de todas as máquinas, usuários, grupos, acls... tudo que diz respeito ao AD, por incrível que pareça não é necessário ter acesso administrativo à máquina para gerar o relatório dele, tudo pode ser extraído a partir de um usuário comum, e a partir desse relatório ele realizar escalação de privilégios e movimentos lateriais dentro do ambiente.

Ah, e se você não entendeu a referência da foto do post, verifique a raça desse cachorro que está ai!

# Setando o BloodHound

A instalação dele é relativamente simples, na Kali, no Windows ele da um trabalho maior.

É só serguir esse [TUTORIAL](https://stealingthe.network/quick-guide-to-installing-bloodhound-in-kali-rolling/) e é sucesso!

Resumindo, execute o comando `apt-get install bloodhound` que ele automaticamente vai instalar, as dependências necessárias, após isso entre no `neo4j` e mude a senha do BloodHound, e seja feliz!

# BloodHound Ingestor

Para conseguirmos verificar esses dados que são disponibilizados, devemos utilizar um Ingestor do bloodhound, um script ou um executável, o que preferir, eu pessoalmente gosto mais do script.

Baixe ele neste link

[SharpHound.ps1](https://github.com/BloodHoundAD/BloodHound/tree/master/Collectors)

Após ter baixado o script, coloque ele na máquina execute-o da seguinte maneira

`Invoke-Bloodhound -CollectionMethod All,loggedon`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/active-enum/blood1.png)

Ele vai gerar um arquivo .zip, que é o compilado de todos os dados...

# Verificando o Gráfico

Com esse arquivo zip em mãos, exfiltre ele para a sua Kali que está com o BloodHound instalado, inicie o `neo4j console`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/active-enum/blood2.png)

Agora inicie o `bloodhound`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/active-enum/blood3.png)

Agora simplesmente arraste esse .zip para dentro da seção

bloodhound

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/active-enum/blood4.png)

O final é uma tabela igual a essa, ai você começa a verificar o que quer dentro do Domínio.

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/active-enum/blood5.png)

# Conclusão

O BloodHound é uma ferramenta muito boa, mas nunca dependa exclusivamente dela em seus ataques e auditorias, pois ele gera muito ruido na rede e é facilmente detectado pelo administrator do domínio. Ele deve servir como auxílio.