# VPN


L'objectif est de créer un VPN sécurisé permettant un accès distant à un intranet. Nous allons utiliser WireGuard. WireGuard est réputé pour sa simplicité, sa rapidité et son efficacité en matière de sécurité.

1.Connectez-vous à votre VPS:

A. Préparation

- Un serveur VPS chez Ionos (utilisation d'une vraie IP publique).
- Un accès ssh en root à ce serveur.

```
ssh root@YOUR_VPS_IP
```

2. Installation de WireGuard sur le serveur

A. Prérequis

Mise à jour des paquets:

```
sudo apt update && sudo apt upgrade -y
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
PrivateKey = clé_privé_serveur

[Peer]
PublicKey = clé_publique_client
AllowedIPs = 10.0.0.2/32 (par exemple)
Endpoint = ip_serveur:57416

[Peer]
PublicKey = clé_publique_client
PresharedKey = 
AllowedIPs = 10.0.0.3/32
Endpoint = ip_serveur:53978

[Peer]
PublicKey = clé_publique_client
PresharedKey = 
AllowedIPs = 10.0.0.4/32
Endpoint = ip_serveur:50232
```


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
```
sudo iptables -A INPUT -p udp --dport 51820 -j ACCEPT
```
```
sudo iptables-save > /etc/iptables/rules.v4
```
```
sudo iptables -A INPUT -p tcp --dport 51821 -j ACCEPT
```

Modifiez /etc/sysctl.conf pour ajouter:

```
net.ipv4.ip_forward = 1
```

Appliquez les changements:

```
sysctl -p
```

Démarrer WireGuard:

```
wg-quick up wg0
systemctl enable wg-quick@wg0
```
4. Installation Dashboard

Télécharger WGDashboard
```
git clone -b v3.0.6.2 https://github.com/donaldzou/WGDashboard.git wgdashboard
```

```
cd wgdashboard/src
```
Install WGDashboard
```
sudo chmod u+x wgd.sh
sudo ./wgd.sh install
sudo chmod -R 755 /etc/wireguard
```
```
./wgd.sh start
```
Modifier le fichier:

 /root/wgdashboard/src/wg-dashboard.service

```
[Unit]
Description=WG Dashboard Service
After=netword.service
#ConditionPathIsDirectory=/etc/wireguard

[Service]
WorkingDirectory=/root/wgdashboard/src
ExecStart=/usr/bin/python3 /root/wgdashboard/src/dashboard.py
#ExecStart=/usr/local/bin/gunicorn --workers 3 --bind 0.0.0.0:10086 dashboard:app
Restart=always
User=root
#RestartSec=5
#StartLimitInterval=1

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

5. Redondance du serveur VPN

Pour assurer la redondance, configurer un second serveur VPS avec une configuration identique et utiliser un service de basculement (failover) comme Keepalived ou HAProxy

    Installation de Keepalived:

```
sudo apt install keepalived -y
```

Configuration de Keepalived:
Édite le fichier :

/etc/keepalived/keepalived.conf 

sur les deux serveurs:

```
    vrrp_instance VI_1 {
        state MASTER
        interface eth0
        virtual_router_id 51
        priority 100
        advert_int 1
        authentication {
            auth_type PASS
            auth_pass somepassword
        }
        virtual_ipaddress {
            192.168.0.1/24
        }
    }
```

6. Authentification des utilisateurs

    Création de configurations clients:
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

7. Gestion des logs

    Configuration de la journalisation:
    WireGuard journalise les connexions via systemd-journald. Configure journald pour conserver les logs:

```
    sudo vim /etc/systemd/journald.conf
    # Ajoute ou modifie les lignes suivantes
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