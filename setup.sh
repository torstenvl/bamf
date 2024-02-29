#!/bin/sh
#
# BAMF: A FreeBSD setup script providing BSD, Apache, MySQL, and FastCGI
#
# Copyright (C) 2022 Joshua Lee Ockert <torstenvl@gmail.com>
# https://github.com/torstenvl
#
# Permission to use, copy, modify, and/or distribute this work for any
# purpose is hereby granted, provided this notice appears in all copies.

# SETTINGS
USER=webadmin
PASS=webadmin
HOST=whatever.com


# INSTALL SOFTWARE
PATH="$PATH:/usr/local/bin/"
env ASSUME_ALWAYS_YES=YES pkg install indexinfo
env ASSUME_ALWAYS_YES=YES pkg install sudo
env ASSUME_ALWAYS_YES=YES pkg install rsync
env ASSUME_ALWAYS_YES=YES pkg install bash
env ASSUME_ALWAYS_YES=YES pkg install hexedit
env ASSUME_ALWAYS_YES=YES pkg install emacs-nox
CRTBOT=`pkg search -q "^py[0-9][0-9]-certbot-[0-9]" | sort -V | tail -n 1 | rev | cut -d'-' -f2- | rev`
APACHE=`pkg search -q "^apache[0-9]*-[0-9]"         | sort -V | tail -n 1 | rev | cut -d'-' -f2- | rev`
MY_SQL=`pkg search -q "^mariadb[0-9]*-server-[0-9]" | sort -V | tail -n 1 | rev | cut -d'-' -f2- | rev`
PHPPKG=`pkg search -q "^php[0-9]*-[0-9]"            | sort -V | tail -n 1 | rev | cut -d'-' -f2- | rev`
env ASSUME_ALWAYS_YES=YES pkg install ${CRTBOT}
env ASSUME_ALWAYS_YES=YES pkg install ${APACHE}
env ASSUME_ALWAYS_YES=YES pkg install ${MY_SQL}
env ASSUME_ALWAYS_YES=YES pkg install ${PHPPKG}


# CONFIGURATION
sed -i.bak -e 's/^# %wheel ALL/%wheel ALL/g' /usr/local/etc/sudoers
sed -i.bak -e 's/^tty.[1-8]/#&/g' /etc/ttys
echo "accf_http_load=\"YES\""	>> /boot/loader.conf
echo "accf_data_load=\"YES\""	>> /boot/loader.conf
echo "${APACHE}_enable=\"YES\""	>> /etc/rc.conf
echo "php_fpm_enable=\"YES\"" 	>> /etc/rc.conf
echo "mysql_enable=\"YES\""	>> /etc/rc.conf
sed -i.bak -e "s/me=\"freebsd\"/me=\"${HOST}\"/g" /etc/rc.conf
echo ${PASS} | pw useradd ${USER} -m -s /usr/local/bin/bash -h0
pw usermod ${USER} -G wheel
dd if=/dev/zero of=/swap bs=1M count=1024
chmod 0600 /swap
echo "md99	none	swap	sw,file=/swap,late	0	0" >> /etc/fstab
swapon -aL
sed -i.bak -e "s/^innodb_buffer.*$/innodb_buffer_pool_size = 256M/g" /usr/local/etc/mysql/my.cnf 
sed -i.bak -e "s/^key_buffer.*$/key_buffer_size = 10M/g" /usr/local/etc/mysql/my.cnf


# DEFAULT SHELL
cat << EOF > /home/${USER}/.bash_profile
export LC_ALL=en_US.UTF-8
export LANG=en_US.UTF-8
export LANGUAGE=en_US.UTF-8
export LESSHISTFILE=-
export SQLITE_HISTORY=/dev/null
export PATH="/usr/local/sbin:${HOME}/.bin:${PATH}"
export EDITOR="emacs"
export GPG_TTY=$(tty)

PS1="[\[\033[1m\]\t\[\033[m\] \[\033[1;31m\]\u@\h\[\033[m\] (bash) \[\e[32;1m\]\w\[\033[m\]] \$ "
export BASH_SILENCE_DEPRECATION_WARNING=1
export HISTFILE="${HOME}/.config/shell/.bash_history"
[ -f /usr/local/etc/bash_completion ] && . /usr/local/etc/bash_completion

alias cp='cp -iv'
alias mv='mv -iv'
alias less='less -FSRXc'
alias mkdir='mkdir -pv'
alias ls='ls -FGhp'
alias ll='ls -FGlhp'
alias la='ls -FGlAhp'
alias f='find . -name'
alias path='echo -e \${PATH//:/\\n}'
alias dbdump='mysqldump -p -A --hex-blob'

alias updatedb='sudo /etc/periodic/weekly/310.locate'
alias which='type -all'
udc() {
    UPTD=0
    FVER=$(freebsd-version)
    printf "LATEST UPDATES:\n"
    fetch -qo - https://www.freebsd.org/releases/ | grep 'Release [0-9]' | sed 's/^.*Release \([0-9\.]*\).*\(([A-Za-z0-9 ,]*)\).*$/\1/g' | while read i; do
        PLVL=$(fetch -qo - https://raw.githubusercontent.com/freebsd/freebsd-src/releng/$(echo $i)/sys/conf/newvers.sh | grep -E "BRANCH" | grep "=" | head -1 | cut -d"=" -f2 | sed 's/RELEASE-//g' | xargs)
        THISVER=$(printf "%-4s-RELEASE-%s\n" "${i}" "${PLVL}")
        printf "    ${THISVER}"
        [ "${THISVER}" = "${FVER}" ] && UPTD=1 && printf " (your system)\n" || printf "\n"
    done
    [ "${UPTD}" = "0" ] && printf "\nPlease update your system from ${FVER} via freebsd-update.\n\n" || printf "\nYour system is up to date.\n\n"
}
EOF

# BACKUP/RESTORE VIA MAKE
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



# SET UP APACHE DIRS
#   Apache's directory organization is a freaking mess.
#   We are going to make everything live under ~/www/ and then
#     ~/www/      <--  /usr/local/www/
#     ~/www/conf  <--  /usr/local/etc/apacheXX
#     ~/www/data  <--  /usr/local/www/htdocs
#   This has the benefit of making it easy to back up the entire site,
#   including configuration, via SFTP.
mkdir /home/${USER}/www
rm -Rf /usr/local/www
ln -sf /home/${USER}/www /usr/local/www
mkdir /usr/local/www/data
mkdir /usr/local/www/conf
cp -R /usr/local/etc/${APACHE}/* /usr/local/www/conf/
rm -Rf /usr/local/etc/${APACHE}
ln -sf /usr/local/www/conf /usr/local/etc/${APACHE}
ln -sf /usr/local/libexec/${APACHE} /usr/local/www/modules

# SET UP APACHE CONF
cat << EOF > /usr/local/www/conf/httpd.conf
ServerRoot       /usr/local/www/
User             www
Group            www
ErrorLog         "/usr/local/www/httpd-error.log"
LogLevel         debug

################################### MODULES ###################################
### FOUNDATIONAL
LoadModule mpm_event_module      modules/mod_mpm_event.so
LoadModule mime_module           modules/mod_mime.so
LoadModule dir_module            modules/mod_dir.so
LoadModule authz_core_module     modules/mod_authz_core.so
LoadModule auth_basic_module     modules/mod_auth_basic.so
LoadModule authn_core_module     modules/mod_authn_core.so
LoadModule authn_file_module     modules/mod_authn_file.so
LoadModule authz_user_module     modules/mod_authz_user.so
LoadModule unixd_module	         modules/mod_unixd.so
LoadModule socache_shmcb_module  modules/mod_socache_shmcb.so
LoadModule headers_module        modules/mod_headers.so
LoadModule setenvif_module       modules/mod_setenvif.so
LoadModule rewrite_module        modules/mod_rewrite.so
LoadModule log_config_module     modules/mod_log_config.so
LoadModule filter_module         modules/mod_filter.so
LoadModule deflate_module        modules/mod_deflate.so
### URL REWRITES/REDIRECTS
LoadModule alias_module	         modules/mod_alias.so
LoadModule speling_module        modules/mod_speling.so
### SERVER-SIDE INCLUDES
LoadModule include_module        modules/mod_include.so
### CGI AND PHP
LoadModule cgid_module           modules/mod_cgid.so
LoadModule proxy_module          modules/mod_proxy.so
LoadModule proxy_fcgi_module     modules/mod_proxy_fcgi.so
#LoadModule cgi_module            modules/mod_cgi.so
#LoadModule php_module            modules/libphp.so
### SSL/HTTPS
### LEAVE COMMENTED UNTIL
### CERTIFICATE INSTALLED!
#LoadModule ssl_module            modules/mod_ssl.so

######################### FILE HANDLING CONFIGURATION #########################
TypesConfig                      conf/mime.types
AddType                          application/x-compress     .Z
AddType                          application/x-gzip         .gz .tgz
<IfModule mod_include.c>
    AddType                      text/html                  .shtml
    AddOutputFilter              INCLUDES                   .shtml
</IfModule>
<IfModule mod_cgid.c>
    AddHandler                   cgi-script                 .cgi .pl .py
</IfModule>
<IfModule mod_proxy_fcgi.c>
    <FilesMatch "\.php\$">
        SetHandler proxy:unix:/tmp/php-fpm.sock|fcgi://127.0.0.1:9000
    </FilesMatch>
</IfModule>

<IfModule mod_filter.c>
<IfModule mod_deflate.c>
AddOutputFilterByType   DEFLATE   application/javascript
AddOutputFilterByType   DEFLATE   application/rss+xml
AddOutputFilterByType   DEFLATE   application/vnd.ms-fontobject
AddOutputFilterByType   DEFLATE   application/x-font
AddOutputFilterByType   DEFLATE   application/x-font-opentype
AddOutputFilterByType   DEFLATE   application/x-font-otf
AddOutputFilterByType   DEFLATE   application/x-font-truetype
AddOutputFilterByType   DEFLATE   application/x-font-ttf
AddOutputFilterByType   DEFLATE   application/x-javascript
AddOutputFilterByType   DEFLATE   application/xhtml+xml
AddOutputFilterByType   DEFLATE   application/xml
AddOutputFilterByType   DEFLATE   font/opentype
AddOutputFilterByType   DEFLATE   font/otf
AddOutputFilterByType   DEFLATE   font/ttf
AddOutputFilterByType   DEFLATE   image/svg+xml
AddOutputFilterByType   DEFLATE   image/x-icon
AddOutputFilterByType   DEFLATE   text/css
AddOutputFilterByType   DEFLATE   text/html
AddOutputFilterByType   DEFLATE   text/javascript
AddOutputFilterByType   DEFLATE   text/plain
AddOutputFilterByType   DEFLATE   text/xml
</IfModule>
</IfModule>


############################### CACHE AND PROXY ###############################
<FilesMatch ".(woff2)$">
    Header set Cache-Control "max-age=63072000, public"
</FilesMatch>
<IfModule mod_headers.c>
    RequestHeader unset Proxy early
</IfModule>

######################## BASIC SSL/HTTPS CONFIGURATION ########################
<IfModule mod_ssl.c>
    SSLRandomSeed           startup builtin
    SSLRandomSeed           connect builtin
    SSLCryptoDevice         builtin
    SSLPassPhraseDialog     builtin
    SSLSessionCache         "shmcb:/var/run/ssl_scache(512000)"
    SSLSessionCacheTimeout  300
    SSLStaplingCache        "shmcb:logs/ssl_stapling(32768)"
</IfModule>

################################# HTTP VHOSTS #################################
Listen 80
<VirtualHost *:80>
    ServerName      "${HOST}"
    DocumentRoot    "/usr/local/www/data/${HOST}/"
    DirectoryIndex  index.php index.cgi index.py index.pl index.shtml index.html
    <Directory />
        AllowOverride None
        Require all denied
    </Directory>
    <Directory "/usr/local/www/data/${HOST}/">
        Options None
        AllowOverride None
        Require all granted
    </Directory>
    <Files ".ht*">
        Require all denied
    </Files>
    <IfModule mod_ssl.c>
        <IfModule mod_rewrite.c>
            RewriteEngine On
            RewriteCond %{HTTPS} off
            RewriteCond %{REQUEST_URI} "!/.well-known/acme-challenge/"
            RewriteRule (.*) https://%{HTTP_HOST}%{REQUEST_URI}
        </IfModule>
    </IfModule>
</VirtualHost>


################################# HTTPS VHOSTS ################################
<IfModule mod_ssl.c>
Listen 443
<VirtualHost *:443>
    ServerName      "${HOST}"
    DocumentRoot    "/usr/local/www/data/${HOST}/"
    DirectoryIndex  index.php index.cgi index.py index.pl index.shtml index.html
    <Directory />
        AllowOverride None
        Require all denied
    </Directory>
    <Directory "/usr/local/www/data/${HOST}/">
        Options Indexes Includes ExecCGI FollowSymLinks
        AllowOverride All
        Require all granted
    </Directory>
    <Files ".ht*">
        Require all denied
    </Files>
    SSLEngine              on
    Protocols              h2 http/1.1
    Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"
    SSLCertificateFile	   "/usr/local/www/certs/live/${HOST}/fullchain.pem"
    SSLCertificateKeyFile  "/usr/local/www/certs/live/${HOST}/privkey.pem"
    SSLProtocol            all -SSLv2 -SSLv3 -TLSv1 -TLSv1.1
    SSLProxyProtocol       all -SSLv2 -SSLv3 -TLSv1 -TLSv1.1
    SSLCipherSuite         HIGH:!MEDIUM:!MD5:!RC4:!3DES:!SHA1
    SSLProxyCipherSuite    HIGH:!MEDIUM:!MD5:!RC4:!3DES:!SHA1
    SSLHonorCipherOrder    on
    SSLCompression         off
    SSLSessionTickets      off
    SSLUseStapling         on
    BrowserMatch           "MSIE [2-5]" nokeepalive ssl-unclean-shutdown downgrade-1.0 force-response-1.0
    <FilesMatch "\.(cgi|pl|py|shtml|php)\$">
        SSLOptions +StdEnvVars
    </FilesMatch>
</VirtualHost>
</IfModule>
EOF


# PHP-FPM CONFIG
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


# DEFAULT INDEX.PHP
mkdir -p "/usr/local/www/data/${HOST}"
cat << EOF > "/usr/local/www/data/${HOST}/index.php"
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


# PERMISSIONS
chown -R ${USER}:${USER} /home/${USER}
chown -R ${USER}:www /home/${USER}/www/data

# MOTD
mv /etc/motd.template /etc/motd.template.bak
cat << EOF > /etc/motd.template
If you want to be able to SSH into the ${USER} account:
  sudo mkdir /home/${USER}/.ssh/ 
  sudo cp /home/ec2-user/.ssh/authorized_keys /home/${USER}/.ssh/ 
  sudo chown ${USER}:${USER} /home/${USER}/.ssh/*

To get a Let's Encrypt HTTPS certificate:
  sudo mkdir -p /usr/local/www/certs
  sudo ln -sF /usr/local/www/certs /usr/local/etc/letsencrypt
  sudo certbot certonly --webroot -w /usr/local/www/data/${HOST}/ -d ${HOST} && \
  printf "7\t0\t*/2\t*\t*\troot\tsleep 7 && certbot renew -q --webroot -w /usr/local/www/data/${HOST}/ && apachectl graceful\n" | sudo tee -a /etc/crontab > /dev/null && \
  sudo sed -i.bak -e "s/^#LoadModule ssl_module/LoadModule ssl_module/g" /usr/local/www/conf/httpd.conf && \
  sudo apachectl graceful

  AND MAKE SURE TO ENABLE HTTPS TRAFFIC ON PORT 443 IN YOUR FIREWALL!

To make using MySQL easier, make a ~/.my.cnf containing the following:
  [client]
  user=mysql
  password=mysql

If you ever need to nuke your MySQL database(s):
  sudo rm -rf /var/db/mysql/*
  sudo /usr/local/libexec/mysqld --initialize --user=mysql
  sudo service mysql-server start
  sudo /usr/local/bin/mysql_secure_installation

To export your entire MySQL database(s):
  dbdump -u DBAdminUserName > exportname.sql

To get rid of this message and restore the default:
  sudo mv -f /etc/motd.template.bak /etc/motd.template

To get rid of this message entirely:
  sudo rm -rf /etc/motd.template /var/run/motd


EOF
cp /etc/motd.template /var/run/motd
