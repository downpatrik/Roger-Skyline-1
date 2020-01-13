# Roger-Skyline-1
Roger-Skyline-1 42
## V.2 VM Part
### You have to run a Virtual Machine with the Linux OS of your choice in the hypervisor of your choice.
* A disk size of 8GB.
* Have at least one 4.2 GB partition.
* It will also have to be up to date as well as the whole packages installed to meet the demands of this subject.
```console
$ su
$ apt-get update -y && apt-get upgrade -y
$ apt-get install sudo vim ufw fail2ban portsentry -y
$ exit
$ reboot
```
## V.3 Network and Security Part
### You must create a non-root user to connect to the machine and work.
```console
$ su
$ sudo adduser newuser
$ exit
```
### Use sudo, with this user, to be able to perform operation requiring special rights.
```console
$ su
$ sudo echo -e "\nuser\tALL=(ALL:ALL) NOPASSWD:ALL" >> /etc/sudoers
$ exit
```
### We don’t want you to use the DHCP service of your machine. You’ve got to configure it to have a static IP and a Netmask in \30.
```console
$ su
$ ip ad | grep 'inet ' | awk '(NR == 2)' | awk '{print $2}' | cut -d '/' -f1
# address
$ ip route | awk '(NR == 2)' | awk '{ print $1 }'  | cut -d / -f 1 | grep default
# gateway
$ sudo vim /etc/network/interfaces
# Static ip address for enp0s3
> iface enp0s3 inet static
>		address 10.114.254.42
>		netmask 255.255.255.252
>		gateway 10.114.254.254
$ sudo reboot
```
### You have to change the default port of the SSH service by the one of your choice. SSH access HAS TO be done with publickeys. SSH root access SHOULD NOT be allowed directly, but with a user who can be root.
* Server
```console
$ su
$ sudo vim /etc/ssh/sshd_config
> Port 2121
> PermitRootLogin no
> PasswordAuthentication no
> AuthorizedKeysFile .ssh/authorized_keys
$ sudo service sshd restart
```
* Client
On MacOS port 1111, because port forwarding on VM to 2121
```console
$ ssh-keygen -t rsa
$ ssh-copy-id -i id_rsa.pub user@127.0.0.1 -p1111
$ ssh -p1111 user@127.0.1.1
```
### You have to set the rules of your firewall on your server only with the services used outside the VM.
```console
$ sudo ufw status
$ sudo ufw enable
# allow ssh
$ sudo ufw allow 2121/tcp
# allow http
$ sudo ufw allow 80/tcp
# allow https
$ sudo ufw allow 443
```
### You have to set a DOS (Denial Of Service Attack) protection on your open ports of your VM.
```console
$ sudo cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local
$ sudo vim /etc/fail2ban/jail.local
> [sshd]
> enabled = true
> port    = 42
> logpath = %(sshd_log)s
> backend = %(sshd_backend)s
> maxretry = 3
> bantime = 600
>
> [http-get-dos]
> enabled = true
> port = http,https
> filter = http-get-dos
> logpath = /var/log/apache2/access.log (le fichier d'access sur server web)
> maxretry = 300
> findtime = 300
> bantime = 600
> action = iptables[name=HTTP, port=http, protocol=tcp]
$ sudo vim /etc/fail2ban/filter.d/http-get-dos.conf
> [Definition]
> failregex = ^<HOST> -.*"(GET|POST).*
> ignoreregex =
$ sudo ufw reload
$ sudo service fail2ban restart
```
### You have to set a protection against scans on your VM’s open ports.
```console
$ sudo vim /etc/default/portsentry
> TCP_MODE="atcp"
> UDP_MODE="audp"
$ sudo vim /etc/portsentry/portsentry.conf
...
> BLOCK_UDP="1"
> BLOCK_TCP="1"
...
> #KILL_ROUTE="/sbin/iptables -I INPUT -s $TARGET$ -j DROP"
...
> #KILL_HOSTS_DENY="ALL: $TARGET$ : DENY
$ sudo service portsentry restart
```
### Stop the services you don’t need for this project.
```console
$ ls /etc/init.d
...
$ sudo systemctl disable console-setup.service
$ sudo systemctl disable keyboard-setup.service
$ sudo systemctl disable apt-daily.timer
$ sudo systemctl disable apt-daily-upgrade.timer
```
### Create a script that updates all the sources of package, then your packages and which logs the whole in a file named /var/log/update_script.log. Create a scheduled task for this script once a week at 4AM and every time the machine reboots.
```console
$ touch update.sh
$ sudo chmod 755 update.sh
$ echo "sudo apt-get update -y >> /var/log/update_script.log" >> ~/update.sh
$ echo "sudo apt-get upgrade -y >> /var/log/update_script.log" >> ~/update.sh
$ sudo crontab -e
> SHELL=/bin/bash
> PATH=/sbin:/bin:/usr/sbin:/usr/bin
>
> @reboot sudo ~/update.sh
> 0 4 * * MON sudo ~/update.sh
```
### Make a script to monitor changes of the /etc/crontab file and sends an email to root if it has been modified. Create a scheduled script task every day at midnight.
```console
$ vim cronMonitor.sh
> #!/bin/bash
> 
> FILE="/home/user/cron_md5"
> MD5="$(sudo md5sum '/etc/crontab' | awk '{print $1}') "
>
> if [ ! -f $FILE]
> then
>   sudo touch $FILE
>   sudo chmod 777 $FILE
>   echo "$MD5" > $FILE
>   exit 0;
> fi; 
>
> if [ "$MD5" != "$(cat $FILE)" ] ; then
> 	echo "$MD5" > $FILE
> 	echo "KO on crontab" | mail -s "Cronfile was modified !" root
> fi;
$ sudo chmod 755 cronMonitor.sh
$ sudo crontab -e
> 0 0 * * * sudo ~/cronMonitor.sh
```
## V.4 Optional Part
### Web Part
### You have to set a web server who should BE available on the VM’s IP or an host (init.login.com for exemple). About the packages of your web server, you can choose between Nginx and Apache. You have to set a self-signed SSL on all of your services. You have to set a web "application" from those choices
* A login page.
* A display site.
* A wonderful website that blow our minds.
```console
$ sudo apt install -y nginx
$ systemctl status nginx
$ sudo mkdir -p /var/www/roger-skyline/html
$ sudo chown -R $USER:$USER /var/www/roger-skyline/html/
$ sudo chmod -R 0755 /var/www/roger-skyline/
$ sudo vim /var/www/roger-skyline/html/index.html
# [See my login page](web/index.html)
$ sudo chmod 0644 /var/www/roger-skyline/html/index.html
$ sudo vim /etc/nginx/sites-available/roger-skyline
> server {
> 	listen 80;
> 	listen [::]:80;
> 
> 	root /var/www/roger-skyline/html;
> 	index index.html;
> 
> 	server_name roger-skyline.com www.roger-skyline.com;
> 
> 	location / {
> 		try_files $uri $uri/ =404;
> 	}
> }
$ sudo ln -s /etc/nginx/sites-available/roger-skyline /etc/nginx/sites-enabled/
$ sudo systemctl restart nginx
#SSL
$ sudo openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout /etc/ssl/private/nginx-selfsigned.key -out /etc/ssl/certs/nginx-selfsigned.crt
$ sudo openssl dhparam -out /etc/nginx/dhparam.pem 4096
$ sudo vim /etc/nginx/snippets/self-signed.conf
> ssl_certificate /etc/ssl/certs/nginx-selfsigned.crt;
> ssl_certificate_key /etc/ssl/private/nginx-selfsigned.key;
$ sudo vim /etc/nginx/snippets/ssl-params.conf
> ssl_protocols TLSv1.2;
> ssl_prefer_server_ciphers on;
> ssl_dhparam /etc/nginx/dhparam.pem;
> ssl_ciphers
> ECDHE-RSA-AES256-GCM-SHA512:DHE-RSA-AES256-GCM-SHA512:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-SHA384;
> ssl_ecdh_curve secp384r1; # Requires nginx >= 1.1.0
> ssl_session_timeout  10m;
> ssl_session_cache shared:SSL:10m;
> ssl_session_tickets off; # Requires nginx >= 1.5.9
> # ssl_stapling on; # Requires nginx >= 1.3.7
> # ssl_stapling_verify on; # Requires nginx => 1.3.7
> resolver 8.8.8.8 8.8.4.4 valid=300s;
> resolver_timeout 5s;
> add_header X-Frame-Options DENY;
> add_header X-Content-Type-Options nosniff;
> add_header X-XSS-Protection "1; mode=block";
$ sudo chmod 0644 /etc/nginx/snippets/ssl-params.conf
$ sudo vim /etc/nginx/sites-available/roger-skyline
> server {
> 	listen 443 ssl;
> 	listen [::]:443 ssl;
> 	include snippets/self-signed.conf;
> 	include snippets/ssl-params.conf;
> 
> 	root /var/www/roger-skyline/html;
> 	index index.html;
> 
> 	server_name roger-skyline.com www.roger-skyline.com;
> 
> 	location / {
> 		try_files $uri $uri/ =404;
> 	}
> }
> 
> server {
> 	listen 80;
> 	listen [::]:80;
> 
> 	server_name roger-skyline.com www.roger-skyline.com;
> 
> 	return 302 https://$server_name$request_uri;
> }
$ sudo nginx -t
$ sudo systemctl reload nginx
```
### Deployment Part
### Propose a functional solution for deployment automation.
