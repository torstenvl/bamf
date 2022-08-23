#!/bin/sh
#
# BAMF: A FreeBSD setup script providing BSD, Apache, MySQL, and FastCGI
#
# Copyright (C) 2022 Joshua Lee Ockert <torstenvl@gmail.com>
# https://github.com/torstenvl
#
# THIS WORK IS PROVIDED "AS IS" WITH NO WARRANTY OF ANY KIND. THE IMPLIED
# WARRANTIES OF MERCHANTABILITY, FITNESS, NON-INFRINGEMENT, AND TITLE ARE
# EXPRESSLY DISCLAIMED. NO AUTHOR SHALL BE LIABLE UNDER ANY THEORY OF LAW
# FOR ANY DAMAGES OF ANY KIND RESULTING FROM THE USE OF THIS WORK.
#
# Permission to use, copy, modify, and/or distribute this work for any
# purpose is hereby granted, provided this notice appears in all copies.


# INSTALLATION SETTINGS

##  Please modify to reflect your desired username, password, and domain
USER=webadmin
PASS=webadmin
HOST=dsoncr.org


# INSTALL SOFTWARE

## Basic system utilities
PATH="$PATH:/usr/local/bin/"
env ASSUME_ALWAYS_YES=YES pkg install indexinfo
env ASSUME_ALWAYS_YES=YES pkg install sudo
env ASSUME_ALWAYS_YES=YES pkg install rsync
env ASSUME_ALWAYS_YES=YES pkg install bash

## Some nice editors
env ASSUME_ALWAYS_YES=YES pkg install hexedit
env ASSUME_ALWAYS_YES=YES pkg install emacs-nox

## Fortune packages
env ASSUME_ALWAYS_YES=YES pkg install fortune-mod-freebsd-classic
env ASSUME_ALWAYS_YES=YES pkg install fortune-mod-bofh

##  CertBot, Apache, MySQL, FastCGI PHP   #
CRTBOT=`pkg search -q "^py[0-9][0-9]-certbot"   | sort -r | head -n 1 | cut -f1,2 -d'-'`
APACHE=`pkg search -q "^apache[0-9]*-[0-9]"     | sort -r | head -n 1 | cut -f1   -d'-'`
MY_SQL=`pkg search -q "^mysql[0-9][0-9]-server" | sort -r | head -n 1 | cut -f1,2 -d'-'`	
PHPPKG=`pkg search -q "^php[0-9]*-[0-9]"        | sort -r | head -n 1 | cut -f1   -d'-'`
env ASSUME_ALWAYS_YES=YES pkg install ${CRTBOT}
env ASSUME_ALWAYS_YES=YES pkg install ${APACHE}
env ASSUME_ALWAYS_YES=YES pkg install ${MY_SQL}
env ASSUME_ALWAYS_YES=YES pkg install ${PHPPKG}



# CONFIGURE SYSTEM

##  Add the wheel group to sudoers
sed -i.bak -e 's/^# %wheel ALL/%wheel ALL/g' /usr/local/etc/sudoers

##  Cut down on local terminals
sed -i.bak -e 's/^tty.[1-8]/#&/g' /etc/ttys

##  Make web server start on boot 
echo "accf_http_load=\"YES\""	>> /boot/loader.conf
echo "accf_data_load=\"YES\""	>> /boot/loader.conf
echo "${APACHE}_enable=\"YES\""	>> /etc/rc.conf
echo "php_fpm_enable=\"YES\"" 	>> /etc/rc.conf
echo "mysql_enable=\"YES\""	>> /etc/rc.conf

## Set hostname in /etc/rc.conf
sed -i.bak -e "s/me=\"freebsd\"/me=\"${HOST}\"/g" /etc/rc.conf

## Configure primary webadmin user
echo ${PASS} | pw useradd ${USER} -m -s /usr/local/bin/bash -h0
pw usermod ${USER} -G wheel

## Add a swapfile
dd if=/dev/zero of=/swap bs=1M count=1024
chmod 0600 /swap
echo "md99	none	swap	sw,file=/swap,late	0	0" >> /etc/fstab
swapon -aL

## Make MySQL conservative with RAM
sed -i.bak -e "s/^innodb_buffer.*$/innodb_buffer_pool_size         = 256M/g" /usr/local/etc/mysql/my.cnf 
sed -i.bak -e "s/^key_buffer.*$/key_buffer_size                 = 10M/g" /usr/local/etc/mysql/my.cnf



##  Default ~/.bash_profile for sane shell
cat << EOF > /home/${USER}/.bash_profile
BOLD="\[\033[1m\]"
RED="\[\033[1;31m\]"
GREEN="\[\e[32;1m\]"
OFF="\[\033[m\]"

export PS1="[\A \${RED}\u\${OFF} \w] $ "
export EDITOR=vi
export PAGER=less
export LESSHISTFILE=/dev/null

alias cp='cp -iv'
alias mv='mv -iv'
alias mkdir='mkdir -pv'
alias ll='ls -FGAlh'
alias la='ls -FGalh'
alias less='less -FSRXc'
alias which='type -all'
alias path='echo -e \${PATH//:/\\n}'
alias qfind='find . -name '
alias updatedb='sudo /etc/periodic/weekly/310.locate'
EOF


##  Default ~/Makefile for backup/restore
cat << EOF > /home/${USER}/Makefile
bd != date '+%Y%m%d-%s'

.PHONY: backup
backup:
	@echo -n "Backing up files... "
	@tar czf backup-\${bd}.tgz Makefile readme-* .bash_profile .inputrc www 
	@echo "done!"
	@echo
	@echo


.PHONY: restore
restore:
	@echo -n "Restoring latest backup... "
	@tar xf \`ls backup*.tgz | sort -r | uniq | head -n 1\`
	@echo "done!"
	@echo
	@echo


.PHONY: select
select:
	@echo "Files are:"
	@ls -FGAlh backup-*
	@rm -i backup-*


.PHONY: clean
clean: 
	@echo -n "Cleaning *~ and .*~ files... "
	@rm -f *~
	@rm -f .*~
	@echo "done!"
EOF



# CONFIGURE WEB SERVER

##  Set up user's directories for webserver work
##       Apache's directory organization is a freaking mess.
##       We are going to make everything live under ~/www/ and then
##           ~/www/       <--   /usr/local/www/
##           ~/www/conf   <--   /usr/local/etc/apacheXX
##           ~/www/data   <--   /usr/local/www/htdocs
##       This has the benefit of making it easy to back up the entire site,
##       including configuration, via SFTP. 

## Make and link directories under ~/www
mkdir /home/${USER}/www
rm -Rf /usr/local/www
ln -sf /home/${USER}/www /usr/local/www
mkdir /usr/local/www/data
mkdir /usr/local/www/conf

## Copy default configuration to contained location
cp -R /usr/local/etc/${APACHE}/* /usr/local/www/conf/

## Link configuration to expected location
rm -Rf /usr/local/etc/${APACHE}
ln -sf /usr/local/www/conf /usr/local/etc/${APACHE}

## Link the modules directory
ln -sf /usr/local/libexec/${APACHE} /usr/local/www/modules

##  Default ~/www/conf/httpd.conf for working web server
cat << EOF > /usr/local/www/conf/httpd.conf
ServerName	${HOST}
ServerRoot	/usr/local/www/
User		www
Group		www
ErrorLog	"/usr/local/www/httpd-error.log"
LogLevel	debug

RequestHeader	unset Proxy early

DocumentRoot 	"/usr/local/www/data/"
DirectoryIndex 	index.php index.cgi index.py index.pl index.shtml index.html

<Directory />
    AllowOverride None
    Require all denied
</Directory>

<Directory "/usr/local/www/data/">
    Options Indexes ExecCGI
    AllowOverride All
    Require all granted
</Directory>

<Files ".ht*">
    Require all denied
</Files>

TypesConfig conf/mime.types
AddType application/x-compress	.Z
AddType application/x-gzip	.gz .tgz

### ULTRA-BASIC MODULES
LoadModule mpm_event_module	modules/mod_mpm_event.so
LoadModule mime_module		modules/mod_mime.so
LoadModule dir_module		modules/mod_dir.so
LoadModule authz_core_module	modules/mod_authz_core.so
LoadModule unixd_module		modules/mod_unixd.so

### REQUIRED FOR HTTPS AND OTHER NORMAL OPERATION
LoadModule socache_shmcb_module	modules/mod_socache_shmcb.so
LoadModule headers_module	modules/mod_headers.so
LoadModule setenvif_module	modules/mod_setenvif.so
LoadModule rewrite_module	modules/mod_rewrite.so

### REQUIRED FOR .HTPASSWD PASSWORD PROTECTION
LoadModule auth_basic_module	modules/mod_auth_basic.so
LoadModule authn_core_module	modules/mod_authn_core.so
LoadModule authn_file_module	modules/mod_authn_file.so
LoadModule authz_user_module	modules/mod_authz_user.so

### USEFUL FOR REWRITING URLS AND REDIRECTING
LoadModule alias_module		modules/mod_alias.so
LoadModule speling_module	modules/mod_speling.so

### ENABLES TRADITIONAL CGI BUT FASTCGIWRAP-STYLE: EXTERNAL DAEMON
### RUNS CGI PROGRAM BUT GRABS STDOUT AND COMMUNICATES IT BACK TO 
### THE WEB SERVER VIA A UNIX SOCKET
LoadModule cgid_module		modules/mod_cgid.so

### ENABLES SERVER-SIDE INCLUDES
LoadModule include_module	modules/mod_include.so

### REQUIRED FOR FASTCGI PHP
LoadModule proxy_module		modules/mod_proxy.so
LoadModule proxy_fcgi_module	modules/mod_proxy_fcgi.so

### ENABLE THIS FOR HTTPS
### DO NOT UNCOMMENT THIS LINE UNTIL HTTPS CERTIFICATE INSTALLED
#LoadModule ssl_module		modules/mod_ssl.so

<IfModule mod_ssl.c>
SSLRandomSeed			startup builtin
SSLRandomSeed			connect builtin
SSLCryptoDevice			builtin
SSLPassPhraseDialog		builtin
SSLSessionCache			"shmcb:/var/run/ssl_scache(512000)"
SSLSessionCacheTimeout		300
</IfModule>

<IfModule mod_proxy_fcgi.c>?
<FilesMatch "\.php\$">
	SetHandler proxy:unix:/tmp/php-fpm.sock|fcgi://127.0.0.1:9000
</FilesMatch>
</IfModule>

<IfModule mod_include.c>
AddType text/html		.shtml
AddOutputFilter INCLUDES	.shtml
</IfModule>

<IfModule mod_cgid.c>
AddHandler cgi-script		.cgi .pl .py
</IfModule>

Listen 80
<VirtualHost *:80>
	<IfModule mod_ssl.c>
		<IfModule mod_rewrite.c>
			RewriteEngine On
			RewriteCond %{HTTPS} off
			RewriteCond %{REQUEST_URI} "!/.well-known/acme-challenge/"
			RewriteRule (.*) https://%{HTTP_HOST}%{REQUEST_URI}
		</IfModule>
	</IfModule>
</VirtualHost>

<IfModule mod_ssl.c>
	Listen 443
	<VirtualHost *:443>
		SSLEngine		on
		SSLCertificateFile	"/usr/local/www/certs/live/${HOST}/fullchain.pem"
		SSLCertificateKeyFile	"/usr/local/www/certs/live/${HOST}/privkey.pem"
		SSLCipherSuite		HIGH:MEDIUM:!MD5:!RC4:!3DES
		SSLProxyCipherSuite	HIGH:MEDIUM:!MD5:!RC4:!3DES
		SSLHonorCipherOrder	on
		SSLProtocol		all -SSLv3
		SSLProxyProtocol	all -SSLv3
		BrowserMatch		"MSIE [2-5]" \\
					nokeepalive ssl-unclean-shutdown \\
					downgrade-1.0 force-response-1.0
		<FilesMatch "\.(cgi|pl|py|shtml|php)\$">
			SSLOptions +StdEnvVars
		</FilesMatch>
	</VirtualHost>
</IfModule>
EOF


##  Default /usr/local/etc/php-fpm.d/www.conf for working FCGI PHP
cat << EOF > /usr/local/etc/php-fpm.d/www.conf
[www]
user = www
group = www

listen = /tmp/php-fpm.sock
listen.owner = www
listen.group = www
listen.mode = 0660

pm = dynamic
pm.max_children = 5
pm.start_servers = 2
pm.min_spare_servers = 1
pm.max_spare_servers = 3
EOF


##  Default ~/www/data/index.html for working web page
cat << EOF > /usr/local/www/data/index.php
<html>
  <head>
    <title>Welcome</title>
    <style type="text/css">
      body { max-width: 50em; margin: 5em auto; }
    </style>
  </head>
  <body>
    <h1>Welcome</h1>
    <p>The web server was installed correctly, but content has not yet
       been added.</p>
    <p>Please be patient while the site is under construction.</p>
    <h2>PHP Test &amp; Information</h2>
    <?php phpinfo(); ?>
  </body>
</html>
EOF



# WRAPPING IT ALL UP

## Ensure permissions are correct in home directory
chown -R ${USER}:${USER} /home/${USER}
chown -R ${USER}:www /home/${USER}/www/data

## Make new motd 
mv /etc/motd /etc/motd.bak
cat << EOF > /etc/motd
If you want to be able to SSH into the ${USER} account:
  sudo mkdir /home/${USER}/.ssh/ 
  sudo cp /home/ec2-user/.ssh/authorized_keys /home/${USER}/.ssh/ 
  sudo chown ${USER}:${USER} /home/${USER}/.ssh/*

Make sure to enable HTTPS traffic on port 443 in your firewall.

To get a Let's Encrypt HTTPS certificate:
  sudo mkdir -p /usr/local/www/certs; sudo rsync -a /usr/local/etc/letsencrypt/ /usr/local/www/certs/
  sudo rm -Rf /usr/local/etc/letsencrypt; sudo ln -sF /usr/local/www/certs /usr/local/etc/letsencrypt
  sudo sed -i.bak -e "s/^#LoadModule ssl_module/LoadModule ssl_module/g" /usr/local/www/conf/httpd.conf
  sudo certbot certonly --webroot -w /usr/local/www/data -d ${HOST} -d www.${HOST} && \\
  printf "7\t0\t*/2\t*\t*\troot\tsleep 7 && certbot renew -q --webroot -w /usr/local/www/data\n" | sudo tee -a /etc/crontab > /dev/null && \\
  sudo apachectl graceful

To make using MySQL easier, make a ~/.my.cnf containing the following:
  [client]
  user=mysql
  password=mysql

If you ever need to nuke your MySQL database(s);
  sudo rm -rf /var/db/mysql/*
  sudo /usr/local/libexec/mysqld --initialize --user=mysql
  sudo service mysql-server start
  sudo /usr/local/bin/mysql_secure_installation

To get rid of this message and restore the default:
  sudo mv -f /etc/motd.bak /etc/motd

To get rid of this message entirely:
  sudo rm -rf /etc/motd

EOF
