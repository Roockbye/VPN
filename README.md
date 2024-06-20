# VPN


L'objectif est de créer un VPN sécurisé permettant un accès distant à un intranet. Nous allons utiliser WireGuard. WireGuard est réputé pour sa simplicité, sa rapidité et son efficacité en matière de sécurité.

1.Connectez-vous à votre VPS:

A. Préparation

- Un serveur VPS, pour nous chez Ionos (utilisation d'une vraie IP publique).
- Un accès ssh en root aux serveurs.

```
ssh root@YOUR_VPS_IP
```

2. Installation de WireGuard sur le serveur

A. Prérequis

Mise à jour des paquets:

```
sudo apt update && sudo apt upgrade -y
```
Et paquets à installer qui nous serons utiles pour la suite
```
sudo apt install python3 python3-pip
sudo apt install net-tools
sudo pip3 install gunicorn
sudo apt install python3-pip
sudo pip3 install flask
sudo pip3 install flask_qrcode
```

Installation de WireGuard:
```
sudo apt install wireguard -y
```

B. Configuration de WireGuard

Génération des clés pour le serveur:

```
umask 077
wg genkey | tee privatekey | wg pubkey > publickey
```

Configuration du serveur WireGuard:

Crée un fichier de configuration pour WireGuard 

/etc/wireguard/wg0.conf:

```
[Interface]
Address = 10.0.0.1/24
SaveConfig = true
ListenPort = 51820
PrivateKey = clé_privé_serveur (qu'on a généré plus haut)

[Peer]
PublicKey = clé_publique_client
AllowedIPs = 10.0.0.2/32 (par exemple)
Endpoint = ip_serveur:57416
```

Dans notre cas, nos Peers (soit clients) seront créé automatiquement dans le fichier grâce à notre dashboard.


3. Configuration du pare-feu

Installer UFW (si non natif):
```
sudo apt install ufw -y
```

Configurer UFW:

```
sudo ufw allow 51820/udp
ufw allow OpenSSH
ufw enable
sudo ufw allow 10086
```
Vérifiez l'état du pare-feu pour vous assurer que les règles sont bien appliquées :

```
sudo ufw status
```

Pour vérifier les règles iptables:
```
sudo iptables -L -n
```
Règles iptables:

Attention, modifiez ens6 par votre interface réseau en faisant ```ip a```
```
sudo iptables -A FORWARD -i wg0 -j ACCEPT
```
```
sudo iptables -A FORWARD -o wg0 -j ACCEPT
```
```
sudo iptables -t nat -A POSTROUTING -o ens6 -j 
MASQUERADE
```
```
sudo iptables -D FORWARD -i wg0 -j ACCEPT
```
```
sudo iptables -D FORWARD -o wg0 -j ACCEPT
```
```
sudo iptables -t nat -D POSTROUTING -o ens6 -j MASQUERADE
```
```
sudo iptables -A INPUT -p tcp --dport 51821 -j ACCEPT
```
```
sudo iptables -A INPUT -p udp --dport 51820 -j ACCEPT
```
Sauvegarder les règles iptables:
```
sudo iptables-save > /etc/iptables/rules.v4
```

Activer l'IP forwarding

Modifiez /etc/sysctl.conf pour ajouter:

```
net.ipv4.ip_forward = 1
```

Vérifiez les changements:

```
sysctl -p
```

Démarrer WireGuard:

```
wg-quick up wg0
systemctl enable wg-quick@wg0
```
4. Installation Dashboard (https://github.com/donaldzou/WGDashboard)

Télécharger WGDashboard
```
git clone -b v3.0.6.2 https://github.com/donaldzou/WGDashboard.git wgdashboard
```
Ouvrir le dossier wgdashboard
```
cd wgdashboard/src
```
Installer WGDashboard
```
sudo chmod u+x wgd.sh
sudo ./wgd.sh install
sudo chmod -R 755 /etc/wireguard
```
Run
```
./wgd.sh start
```
Nous avons accès à la dashboard sur le port 10086, que nous pouvons changer pour des questions de sécurité

Start/Stop/Restart WGDashboard:
```
cd wgdashboard/src
-----------------------------
./wgd.sh start   
-----------------------------
./wgd.sh debug     
-----------------------------
./wgd.sh stop     
-----------------------------
./wgd.sh restart
```

Modifier le fichier:

 /root/wgdashboard/src/wg-dashboard.service

```
[Unit]
Description=WG Dashboard Service
After=netword.service

[Service]
WorkingDirectory=/root/wgdashboard/src
ExecStart=/usr/bin/python3 /root/wgdashboard/src/dashboard.py
Restart=always
User=root

[Install]
WantedBy=multi-user.target
```

Copier le fichier de service dans le dossier systemd
```
cp wg-dashboard.service /etc/systemd/system/wg-dashboard.service
```

Mettre en route le service:

```
sudo chmod 664 /etc/systemd/system/wg-dashboard.service
sudo systemctl daemon-reload
sudo systemctl enable wg-dashboard.service
sudo systemctl start wg-dashboard.service
```
Vérifier que le service tourne correctement:
```
sudo systemctl status wg-dashboard.service
```
On a accès à la dashboard depuis notre ip privé du serveur:10086
C'est sur cette dashboard que nous allons créer nos clients
PS: Faire toutes ces configurations sur nos deux serveur (si vous désirez faire de la redondance)

5. Redondance du serveur VPN

Pour assurer la redondance, configurer un second serveur VPS avec une configuration identique et utiliser un service de basculement (failover) comme Keepalived.

Sur les deux serveurs (Serveur 1 et Serveur 2):

Installation de Keepalived:

```
sudo apt install keepalived -y
```

Configuration de Keepalived:

Créons cet utilisateur pour éviter les avertissements de sécurité.
```
sudo useradd -r -s /bin/false keepalived_script
```

Édite le fichier :

/etc/keepalived/keepalived.conf 

Serveur 1 (principal):

```
global_defs {
    script_security 2
   #lvs_sync_daemon_interface ens6
    script_user keepalived_script
}

vrrp_script chk_wg0 {
    script "/usr/local/bin/check_wg0.sh"
    interval 2
    weight 2
}

vrrp_instance VI_1 {
    state MASTER
    interface ens6
    virtual_router_id 51
    priority 101
    authentication {
        auth_type PASS
        auth_pass password
    }
    track_script {
        chk_wg0
    }
    virtual_ipaddress {
        10.0.0.100
    }
}
```
serveur 2(backup):
```
global_defs {
    script_security 2
    #lvs_sync_daemon_interface ens6
    script_user keepalived_script
}

vrrp_script chk_wg0 {
    script "/usr/local/bin/check_wg0.sh"
    interval 2
    weight 2
}

vrrp_instance VI_1 {
    state BACKUP
    interface ens6
    virtual_router_id 51
    priority 100
    authentication {
        auth_type PASS
        auth_pass password
    }
    track_script {
        chk_wg0
    }
    virtual_ipaddress {
        10.0.0.100
    }
}
```
Créez le script de vérification /usr/local/bin/check_wg0.sh :

```
sudo nano /usr/local/bin/check_wg0.sh
```
Avec le contenu suivant:
```
#!/bin/bash
#if ping -c 1 10.0.0.1 &> /dev/null
if ip link show wg0 | grep -q "state UP"; then
    exit 0
else
    exit 1
fi
```
Rendez le script exécutable :
```
sudo chown root:keepalived_script /usr/local/bin/check_wg0.sh
sudo chmod 750 /usr/local/bin/check_wg0.sh
```
Démarrez et activez Keepalived :

```
sudo systemctl enable keepalived
sudo systemctl start keepalived
```

Vérifiez l'état de Keepalived sur les deux serveurs :

```
sudo systemctl status keepalived
```

Vérifier que la VIP(ici 10.0.0.100) est Attribué
```
ip a
```
ou
```
ip addr show | grep 10.0.0.100
```
Tester le basculement

Arrêtez WireGuard sur le Serveur 1 :
```
sudo systemctl stop wg-quick@wg0
```
ou
```
sudo systemctl stop keepalived
```
Vérifiez que le client bascule automatiquement vers le Serveur 2.Ce dernier passe en état 'MASTER'
Le basculement peut durer plusieurs secondes.

6. Monitoring

Pour monitorer l'activité de nos serveurs, nous utilisons Netdata. Avec Netdata installé et configuré, vous pouvez surveiller en temps réel les performances de vos serveurs. Vous pouvez également configurer des alertes pour être informé en cas de problèmes.

Netdata offre une interface web intuitive et des graphiques en temps réel, ce qui vous permet d'analyser facilement l'utilisation des ressources et de diagnostiquer les problèmes potentiels. Profitez des informations détaillées pour maintenir la santé de vos serveurs.

Installez les dépendances nécessaires :

```
sudo apt install -y zlib1g-dev uuid-dev libmnl-dev gcc make git autoconf autogen automake pkg-config curl nodejs
```
Install Netdata
```
wget -O /tmp/netdata-kickstart.sh https://get.netdata.cloud/kickstart.sh && sh /tmp/netdata-kickstart.sh --no-updates
```
```
sudo systemctl status netdata
```
Une fois installé, vous pouvez accéder à Netdata via un navigateur web en utilisant l'adresse IP de votre serveur et le port 19999 (par défaut)

- Sécurisation de l'accès à Netdata

Netdata est accessible par défaut à tout le monde. Pour sécuriser l'accès, vous pouvez configurer une authentification de base ou restreindre l'accès à certaines adresses IP.


Modifier le fichier de configuration Netdata :
```
sudo nano /etc/netdata/netdata.conf
```
```
[web]
allow connections from = localhost
```

Installer Nginx :
```
sudo apt install nginx -y
```
```
sudo apt install apache2-utils -y
```

Configurer Nginx pour agir comme un proxy avec authentification de base :

```
sudo htpasswd -c /etc/nginx/.htpasswd your_username
```

Créer un fichier de configuration pour le site Netdata :

```
sudo nano /etc/nginx/sites-available/netdata
```

Ajoutez le contenu suivant :

```
server {
    listen 80;

    server_name your_server_ip; #juste modifier your_server_ip

    location / {
        proxy_pass http://localhost:19999;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        auth_basic "Restricted Content";
        auth_basic_user_file /etc/nginx/.htpasswd;
    }
}
```
Activer la configuration du site :
```
sudo ln -s /etc/nginx/sites-available/netdata /etc/nginx/sites-enabled/
sudo systemctl restart nginx
```

Maintenant, vous pouvez accéder à Netdata en utilisant l'adresse IP de votre serveur sans spécifier le port, et vous serez invité à entrer le nom d'utilisateur et le mot de passe définis précédemment

[dashboard netdata](./netdata.png)

Alerte Discord

[alerte](./alerte.png)

Install:
```
sudo apt-get install stress
```
```
sudo apt-get install stress-ng
```

Sur Discord (obligatoirement un serveur discord dont vous avez les droits)
 --> dans Paramètres --> Intégrations --> Webhook --> Créer un webhook

Nous copierons son lien dans notre fichier de configuration : /etc/netdata/health_alarm_notify.conf

```
SEND_DISCORD="YES"
DISCORD_WEBHOOK_URL="lien du webhook"
DEFAULT_RECIPIENT_DISCORD="alerte" #nom de mon canal
```
Dans le fichier /etc/netdata/netdata.conf, rajouter:
```
[health]
    enabled = yes
```

Pour forcer l'envoi d'une notification de test, vous pouvez utiliser le script de notification intégré de Netdata :

```
sudo /usr/libexec/netdata/plugins.d/alarm-notify.sh test
```

Assurez-vous que vous avez une règle d'alerte configurée pour la charge CPU dans Netdata. Dans /etc/netdata/health.d/cpu.conf:

```
template: 100c_5min_cpu_usage
      on: system.cpu
    calc: $user + $system + $softirq
   every: 10s
    units: %
    warn: $this > 75
    crit: $this > 90
   delay: up 1m for 5m, down 1m for 5m
    info: the CPU utilization is too high
      to: discord
```

Pour tester l'envoi de notifications Discord, vous pouvez créer une alerte personnalisée temporaire dans Netdata. Par exemple, dans /etc/netdata/health.d/custom_test.conf :

```
template: custom_test
      on: system.cpu
    calc: $user + $system + $softirq
   every: 10s
    units: %
    warn: $this > 10
    crit: $this > 20
   delay: up 1m for 5m, down 1m for 5m
    info: this is a test alert
      to: discord
```

Ensuite, redémarrez Netdata :

```
sudo systemctl restart netdata
```

Commande de stress pour déclencher des alertes:
```
stress-ng --cpu 8 --cpu-load 100 --timeout 60s --metrics-brief
```
ou (plus violent)
```
stress-ng --cpu 8 --cpu-load 100 --vm 2 --vm-bytes 80% --io 4 --hdd 2 --timeout 120s --metrics-brief
```

7. Authentification des utilisateurs (si vous désirez le faire manuellement)

Création de configurations clients
Pour chaque utilisateur, génère une paire de clés:

```
wg genkey | tee client_privatekey | wg pubkey > client_publickey
```

Ajout des clients à la configuration du serveur:
Dans /etc/wireguard/wg0.conf:

```
    [Peer]
    PublicKey = <client-public-key>
    AllowedIPs = 10.0.0.2/32
```

8. Gestion des logs

Configuration de la journalisation:

WireGuard journalise les connexions via systemd-journald. Configure journald pour conserver les logs:

```
sudo vim /etc/systemd/journald.conf
```
```
Storage=persistent
MaxRetentionSec=30day
```

Configurer systemd pour capturer les logs:

Créez un fichier /etc/systemd/system/wg-quick@wg0.service.d/logging.conf avec le contenu suivant:

```
[Service]
ExecStartPost=/bin/bash -c 'journalctl -u wg-quick@%i -f >> /var/log/wireguard/%i.log & echo $! > /run/wg-quick-%i-log.pid'
ExecStopPost=/bin/bash -c 'kill $(cat /run/wg-quick-%i-log.pid) && rm /run/wg-quick-%i-log.pid'
```

Configurer logrotate:

Créez un fichier /etc/logrotate.d/wireguard avec le contenu suivant:

```
/var/log/wireguard/*.log {
    daily
    missingok
    rotate 7
    compress
    delaycompress
    notifempty
    create 640 syslog adm
    sharedscripts
    postrotate
        systemctl kill -s HUP --kill-who=main wg-quick@wg0.service
    endscript
}
```

9. Commandes utiles:

Vérification de l'installation de WireGuard

Vérifiez que le module WireGuard est chargé:

```
lsmod | grep wireguard
```

Si WireGuard est installé et le module est chargé, vous devriez voir une sortie contenant "wireguard".

Vérifiez la version de WireGuard:

```
wg --version
```
Cette commande affiche la version installée de WireGuard. Une sortie typique pourrait ressembler à ceci :
```
    wireguard-tools v1.0.20200827
```

Vérifiez l'état du service WireGuard:

```
systemctl status wg-quick@wg0
```
Vérifiez les journaux pour les erreurs:
```
journalctl -xe | grep wireguard
```
Commandes wireguard:
```
sudo systemctl start wg-quick@wg0
```
```
sudo systemctl stop wg-quick@wg0
```
```
sudo systemctl restart wg-quick@wg0
```
```
sudo systemctl status wg-quick@wg0
```

Vérifiez les journaux du service wg-dashboard :

```
sudo journalctl -xeu wg-dashboard.service
```

Assurez-vous que toutes les dépendances Python nécessaires sont installées. Nous avons déjà rencontré un problème de dépendance avec flask_qrcode. Voici comment installer toutes les dépendances à partir du fichier requirements.txt :

```
sudo pip3 install -r /root/wgdashboard/src/requirements.txt
```
Si nous n'arrivons pas à rédémarrer le service de la dashboard.

Utilisez la commande suivante pour identifier le programme qui utilise le port 10086 :

```
sudo lsof -i :10086
```

Cela affichera des informations sur le processus utilisant le port. Vous pouvez ensuite arrêter ce processus. Par exemple, si le PID (Process ID) du programme est 1234, vous pouvez le stopper avec :

```
sudo kill [PID]
```
Journaux de Keepalived:
```
sudo journalctl -u keepalived -f
```

Logs Nginx : Consultez les logs de Nginx pour des erreurs supplémentaires :

```
sudo tail -f /var/log/nginx/error.log
```

Logs Netdata : Vérifiez également les logs de Netdata pour des erreurs potentielles :

```
sudo journalctl -xeu netdata.service
```