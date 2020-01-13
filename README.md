# Roger-Skyline-1
Roger-Skyline-1 42
## V.2 VM Part
### You have to run a Virtual Machine with the Linux OS of your choice in the hypervisor of your choice.
* A disk size of 8GB.
* Have at least one 4.2 GB partition.
![img1](img/1.png)
![img2](img/2.png)
![img3](img/3.png)
![img4](img/4.png)
![img5](img/5.png)
![img6](img/6.png)
![img7](img/7.png)
![img8](img/8.png)
![img9](img/9.png)
![img10](img/10.png)
![img11](img/11.png)
![img12](img/12.png)
![img13](img/13.png)
![img14](img/14.png)
![img15](img/15.png)
![img16](img/16.png)
![img17](img/17.png)
![img18](img/18.png)
![img19](img/19.png)
![img20](img/20.png)
![img21](img/21.png)
![img22](img/22.png)
![img23](img/23.png)
![img24](img/24.png)
![img25](img/25.png)
![img26](img/26.png)
![img27](img/27.png)
![img28](img/28.png)
![img29](img/29.png)
![img30](img/30.png)
![img31](img/31.png)
* It will also have to be up to date as well as the whole packages installed to meet the demands of this subject.
```console
user@roger:~$ su
user@roger:~$ apt-get update -y && apt-get upgrade -y
user@roger:~$ apt-get install sudo vim ufw fail2ban portsentry -y
user@roger:~$ exit
user@roger:~$ reboot
```
## V.3 Network and Security Part
### You must create a non-root user to connect to the machine and work.
```console
user@roger:~$ su
user@roger:~$ sudo adduser newuser
user@roger:~$ exit
```
### Use sudo, with this user, to be able to perform operation requiring special rights.
```console
user@roger:~$ su
user@roger:~$ sudo echo -e "\nuser\tALL=(ALL:ALL) NOPASSWD:ALL" >> /etc/sudoers
user@roger:~$ exit
```
### We don’t want you to use the DHCP service of your machine. You’ve got to configure it to have a static IP and a Netmask in \30.
```console
user@roger:~$ su
user@roger:~$ ip ad | grep 'inet ' | awk '(NR == 2)' | awk '{print user@roger:~$2}' | cut -d '/' -f1
# address
user@roger:~$ ip route | awk '(NR == 2)' | awk '{ print user@roger:~$1 }'  | cut -d / -f 1 | grep default
# gateway
user@roger:~$ sudo vim /etc/network/interfaces
# Static ip address for enp0s3
> iface enp0s3 inet static
>		address 10.114.254.42
>		netmask 255.255.255.252
>		gateway 10.114.254.254
user@roger:~$ sudo reboot
```
### You have to change the default port of the SSH service by the one of your choice. SSH access HAS TO be done with publickeys. SSH root access SHOULD NOT be allowed directly, but with a user who can be root.
* Server
```console
user@roger:~$ su
user@roger:~$ sudo vim /etc/ssh/sshd_config
...
> Port 2121
...
> PermitRootLogin no
...
> PasswordAuthentication no
...
> AuthorizedKeysFile .ssh/authorized_keys
user@roger:~$ sudo service sshd restart
```
* Client
![port0](img/port0.png)
![port1](img/port1.png)
On MacOS port 1111, because port forwarding on VM to 2121
```console
user@roger:~$ ssh-keygen -t rsa
user@roger:~$ ssh-copy-id -i id_rsa.pub user@127.0.0.1 -p1111
user@roger:~$ ssh -p1111 user@127.0.1.1
```
### You have to set the rules of your firewall on your server only with the services used outside the VM.
```console
user@roger:~$ sudo ufw status
user@roger:~$ sudo ufw enable
# allow ssh
user@roger:~$ sudo ufw allow 2121/tcp
# allow http
user@roger:~$ sudo ufw allow 80/tcp
# allow https
user@roger:~$ sudo ufw allow 443
```
### You have to set a DOS (Denial Of Service Attack) protection on your open ports of your VM.
```console
user@roger:~$ sudo cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local
user@roger:~$ sudo vim /etc/fail2ban/jail.local
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
user@roger:~$ sudo vim /etc/fail2ban/filter.d/http-get-dos.conf
> [Definition]
> failregex = ^<HOST> -.*"(GET|POST).*
> ignoreregex =
user@roger:~$ sudo ufw reload
user@roger:~$ sudo service fail2ban restart
```
### You have to set a protection against scans on your VM’s open ports.
```console
user@roger:~$ sudo vim /etc/default/portsentry
> TCP_MODE="atcp"
> UDP_MODE="audp"
user@roger:~$ sudo vim /etc/portsentry/portsentry.conf
...
> BLOCK_UDP="1"
> BLOCK_TCP="1"
...
> #KILL_ROUTE="/sbin/iptables -I INPUT -s user@roger:~$TARGETuser@roger:~$ -j DROP"
...
> #KILL_HOSTS_DENY="ALL: user@roger:~$TARGETuser@roger:~$ : DENY
user@roger:~$ sudo service portsentry restart
```
### Stop the services you don’t need for this project.
```console
user@roger:~$ ls /etc/init.d
...
user@roger:~$ sudo systemctl disable console-setup.service
user@roger:~$ sudo systemctl disable keyboard-setup.service
user@roger:~$ sudo systemctl disable apt-daily.timer
user@roger:~$ sudo systemctl disable apt-daily-upgrade.timer
```
### Create a script that updates all the sources of package, then your packages and which logs the whole in a file named /var/log/update_script.log. Create a scheduled task for this script once a week at 4AM and every time the machine reboots.
```console
user@roger:~$ touch update.sh
user@roger:~$ sudo chmod 755 update.sh
user@roger:~$ echo "sudo apt-get update -y >> /var/log/update_script.log" >> ~/update.sh
user@roger:~$ echo "sudo apt-get upgrade -y >> /var/log/update_script.log" >> ~/update.sh
user@roger:~$ sudo crontab -e
> SHELL=/bin/bash
> PATH=/sbin:/bin:/usr/sbin:/usr/bin
>
> @reboot sudo ~/update.sh
> 0 4 * * MON sudo ~/update.sh
```
### Make a script to monitor changes of the /etc/crontab file and sends an email to root if it has been modified. Create a scheduled script task every day at midnight.
```console
user@roger:~$ vim cronMonitor.sh
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
user@roger:~$ sudo chmod 755 cronMonitor.sh
user@roger:~$ sudo crontab -e
...
> 0 0 * * * sudo ~/cronMonitor.sh
```
## V.4 Optional Part
### Web Part
### You have to set a web server who should BE available on the VM’s IP or an host (init.login.com for exemple). About the packages of your web server, you can choose between Nginx and Apache. You have to set a self-signed SSL on all of your services. You have to set a web "application" from those choices
* A login page.
* A display site.
* A wonderful website that blow our minds.
```console
user@roger:~$ sudo apt install -y nginx
user@roger:~$ systemctl status nginx
user@roger:~$ sudo mkdir -p /var/www/roger-skyline/html
user@roger:~$ sudo chown -R $USER:$USER /var/www/roger-skyline/html/
user@roger:~$ sudo chmod -R 0755 /var/www/roger-skyline/
user@roger:~$ sudo vim /var/www/roger-skyline/html/index.html
```
[See my login page](web/index.html)
```console
user@roger:~$ sudo chmod 0644 /var/www/roger-skyline/html/index.html
user@roger:~$ sudo vim /etc/nginx/sites-available/roger-skyline
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
user@roger:~$ sudo ln -s /etc/nginx/sites-available/roger-skyline /etc/nginx/sites-enabled/
user@roger:~$ sudo systemctl restart nginx
```
SSL
```console
user@roger:~$ sudo openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout /etc/ssl/private/nginx-selfsigned.key -out /etc/ssl/certs/nginx-selfsigned.crt
user@roger:~$ sudo openssl dhparam -out /etc/nginx/dhparam.pem 4096
user@roger:~$ sudo vim /etc/nginx/snippets/self-signed.conf
> ssl_certificate /etc/ssl/certs/nginx-selfsigned.crt;
> ssl_certificate_key /etc/ssl/private/nginx-selfsigned.key;
user@roger:~$ sudo vim /etc/nginx/snippets/ssl-params.conf
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
user@roger:~$ sudo chmod 0644 /etc/nginx/snippets/ssl-params.conf
user@roger:~$ sudo vim /etc/nginx/sites-available/roger-skyline
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
user@roger:~$ sudo nginx -t
user@roger:~$ sudo systemctl reload nginx
```
### Deployment Part
### Propose a functional solution for deployment automation.
The deployment script deploy.sh can be run after the prerequisites are met which are:
```console
1) A VM has been created using Virtualbox with the settings stated above.
2) The VM network is set to Bridged Adapter.
3) sudo has been set up for the user.
4) Git is installed on the VM ("user@roger:~$ apt-get install git" as root)
```
Clone the repository to the VM:
```console
git clone https://github.com/downpatrik/Roger-Skyline-1
```
Execute the deployment script (must be done with sudo):
```console
user@roger:~$ chmod +x ./deploy.sh
user@roger:~$ sudo ./deploy.sh
```
Test that the deployment went fine by logging in to `http://10.0.2.15` on the host machine browser.