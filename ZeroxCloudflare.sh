#!/bin/bash

# Función para mostrar el banner
show_banner() {
    clear
    echo '

╺━┓┏━╸┏━┓┏━┓╻ ╻   ┏━┓┏━╸┏━╸╻ ╻┏━┓╻╺┳╸╻ ╻
┏━┛┣╸ ┣┳┛┃ ┃┏╋┛   ┗━┓┣╸ ┃  ┃ ┃┣┳┛┃ ┃ ┗┳┛
┗━╸┗━╸╹┗╸┗━┛╹ ╹   ┗━┛┗━╸┗━╸┗━┛╹┗╸╹ ╹  ╹	
     Protección Nivel 2
    '
}

# Función para mostrar las opciones de scripts
show_options() {
    echo "Selecciona una opción para ejecutar:"
    echo "1. CLOUDFLARE"
    echo "2. WORDPRESS"
    echo "3. PROTEGER APACHE"
    echo "4. MODSECURITY"
    echo "5. ESCUDO-SSH"
    echo "4. UBUNTU ESPfAÑOL"
    echo "4. FAIL2BAN"
    echo "4. PHP INI"
    echo "0. Salir"
}

# Función para ejecutar el script seleccionado
execute_script() {
    case $1 in
        1)
            

#Actualizas repositorios

apt update && apt upgrade -y

# Paso 1: Pídele al usuario que ingrese el dominio
read -p "Por favor ingresa el dominio: " domain

# Agrega el dominio al comando hostnamectl
sudo hostnamectl set-hostname "$domain"

# Paso 2: Agrega el dominio al archivo /etc/hosts
echo "127.0.0.1    $domain   $(echo $domain | cut -d'.' -f1)" | sudo tee -a /etc/hosts

# Paso 3: Indica al usuario las instrucciones y opciones
echo -e "\e[32mPor favor elimina las líneas que se muestran en el tutorial suministrado por ZEROX SECURITY\e[0m"
read -p "Entendiste? (Y/N): " user_response

if [ "$user_response" == "Y" ] || [ "$user_response" == "y" ]; then
    # Usuario confirmó comprensión, abre el archivo /etc/hosts para edición
    sudo nano /etc/hosts
else
    # Usuario no comprendió, proporciona la URL del video tutorial
    echo "Vamos a abrir el video para ti, copia la URL y pégala en tu navegador: https://youtu.be/hrwoKO7LMzk?t=492"
    read -p "Cuando hayas terminado presiona Y, ¿entendiste el tutorial? (Y/N): " user_response_again
    if [ "$user_response_again" == "Y" ] || [ "$user_response_again" == "y" ]; then
        echo "¡Excelente! Procediendo..."
		sudo nano /etc/hosts
    else
        echo "No parece que hayas comprendido completamente. Por favor, revisa el tutorial nuevamente."
    fi
fi


echo "Se han realizado los cambios en /etc/hosts."


# Paso 1: Verificar la arquitectura del sistema
architecture=$(uname -m)

# Paso 2: Determinar la URL de descarga según la arquitectura
case $architecture in
    "x86_64" | "amd64")
        download_url="https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64.deb"
        filename="cloudflared-linux-amd64.deb"
        ;;
    "i386")
        download_url="https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-386.deb"
        filename="cloudflared-linux-386.deb"
        ;;
    "armv7l")
        download_url="https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-arm.deb"
        filename="cloudflared-linux-arm.deb"
        ;;
    "aarch64")
        download_url="https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-arm64.deb"
        filename="cloudflared-linux-arm64.deb"
        ;;
    *)
        echo "Arquitectura no compatible: $architecture"
        exit 1
        ;;
esac

# Paso 3: Descargar e instalar Cloudflared
echo "Descargando Cloudflared desde $download_url..."
wget "$download_url" -O "$filename"
sudo dpkg -i "$filename"

# Paso 4: Limpiar archivos descargados
rm "$filename"


#Ejecutar el comando de autorización
cloudflared tunnel login

# Paso 9: Informar al usuario sobre la creación del túnel
echo "Vamos a crear un túnel con Cloudflared."

# Paso 10: Pedir al usuario que ingrese el nombre del túnel
read -p "Por favor, ingresa un nombre para el túnel: " tunnel_name

# Paso 11: Crear el túnel con el nombre proporcionado por el usuario
cloudflared tunnel create "$tunnel_name"

echo "¡Túnel \"$tunnel_name\" creado exitosamente!"

cd ~/.cloudflared

# Paso 13: Copiar el nombre del archivo .json
json_filename=$(ls -1 ~/.cloudflared/*.json | tail -n 1)

# Paso 14: Obtener el nombre del archivo sin la extensión .json
filename_no_extension=$(basename "$json_filename" .json)

# Paso 15: Crear el archivo config.yml
cat << EOF > ~/.cloudflared/config.yml
tunnel: $filename_no_extension
credentials-file: /root/.cloudflared/${filename_no_extension}.json

ingress:
  - hostname: $(hostnamectl --static)
    service: http://localhost:80
  - hostname: xtr3am.$(hostnamectl --static)
    service: http://localhost:80
    originRequest:
      noTLSVerify: true
  - service: http_status:404
EOF

echo "Se ha creado el archivo config.yml en la carpeta .cloudflared con los ajustes solicitados."


# Paso 16: Pedir al usuario que ingrese el nombre del túnel
read -p "Por favor, ingresa el nombre del túnel que habías creado: " tunnel_name

# Paso 14: Pedir al usuario que ingrese el dominio
read -p "Por favor, ingresa el dominio que ingresaste anteriormente: " user_domain

while true; do
    # Paso 17: Ejecutar el comando cloudflared tunnel route dns con el nombre del túnel y dominio
    cloudflared tunnel route dns "$tunnel_name" "$user_domain"

    if [ $? -eq 0 ]; then
        echo "Se ha agregado la ruta DNS al túnel \"$tunnel_name\" para el dominio \"$user_domain\"."
        break
    else
        echo "El comando arrojó errores. Volviendo a ejecutar..."
    fi
done


mkdir -p --mode=0755 /usr/share/keyrings

curl -fsSL https://pkg.cloudflare.com/cloudflare-main.gpg | sudo tee /usr/share/keyrings/cloudflare-main.gpg >/dev/null 
echo 'deb [signed-by=/usr/share/keyrings/cloudflare-main.gpg] https://pkg.cloudflare.com/cloudflared focal main' | sudo tee /etc/apt/sources.list.d/cloudflared.list

echo "Se ha creado la actualizacíon automatica de CloudFlare"


sudo apt-get update && sudo apt-get upgrade -y

cloudflared service install

systemctl restart cloudflared


# Comandos persistentes
sudo apt-get install iptables-persistent -y

/sbin/iptables-save > /etc/iptables.conf

iptables-restore < /etc/iptables.conf

sudo netfilter-persistent save

sudo netfilter-persistent reload

echo "TODAS LAS IPS DE ZEROX SECURITY SERAN ACTUALIZADAS, AL IGUAL QUE EL SISTEMA, AHORA ESTAS SEGURO, NO TIENES NECESIDAD DE ABRIR PUERTOS, SOLO DEBES AGREGAR LOS PUERTOS DE CLOUDFLARE"

# Descargar la lista de IPs desde la URL de Cloudflare
IPS_URL="https://www.cloudflare.com/ips-v4"
TMP_FILE=$(mktemp)
wget -q -O "$TMP_FILE" "$IPS_URL"

# Limpiar las reglas de iptables existentes
iptables -F
iptables -P INPUT ACCEPT

# Agregar reglas para las IPs de Cloudflare
while read -r ip; do
    iptables -A INPUT -s "$ip" -p tcp -m multiport --dports 80,443 -j ACCEPT
done < "$TMP_FILE"

# Reglas de bloqueo
iptables -A INPUT -p tcp -m tcp --tcp-flags SYN,ACK SYN,ACK -m state --state NEW -j DROP
iptables -A INPUT -p tcp -m tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG NONE -j DROP
iptables -A INPUT -p tcp -m tcp --tcp-flags FIN,SYN FIN,SYN -j DROP
iptables -A INPUT -p tcp -m tcp --tcp-flags SYN,RST SYN,RST -j DROP
iptables -A INPUT -p tcp -m tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG FIN,SYN,RST,ACK,URG -j DROP
iptables -A INPUT -p tcp -m tcp --tcp-flags FIN,RST FIN,RST -j DROP
iptables -A INPUT -p tcp -m tcp --tcp-flags FIN,ACK FIN -j DROP
iptables -A INPUT -p tcp -m tcp --tcp-flags PSH,ACK PSH -j DROP
iptables -A INPUT -p tcp -m tcp --tcp-flags ACK,URG URG -j DROP

# Guardar las reglas en iptables
iptables-save > /etc/iptables/rules.v4

# Eliminar el archivo temporal
rm "$TMP_FILE"


# Verificar si git está instalado
if ! command -v git &> /dev/null; then
    echo "Git no está instalado. Instalando..."
    sudo apt update
    sudo apt install -y git
fi

# Clonar el repositorio
git clone https://github.com/Zerox-Security/ips-zerox.sh.git /root/ips-zerox

# Mover el contenido a /usr/local/bin/
sudo cp /root/ips-zerox/* /usr/local/bin/

# Dar permisos de ejecución
sudo chmod +x /usr/local/bin/ips-zerox.sh

#Instalar dos2unix si no está instalado
if ! command -v dos2unix &> /dev/null; then
    sudo apt-get install dos2unix -y
fi

# Convertir el script ips-zerox.sh a formato UNIX si contiene caracteres ^M
if [[ -f "ips-zerox.sh" && $(grep -q $'\r' "ips-zerox.sh") ]]; then
    dos2unix /usr/local/bin/ips-zerox.sh
fi


# Crear el archivo de configuración para el gancho de APT
echo 'DPkg::Post-Invoke { "if [ -x /usr/local/bin/ips-zerox.sh ]; then /usr/local/bin/ips-zerox.sh; fi"; };' | sudo tee /etc/apt/apt.conf.d/99ips-zerox
 

#Limpiar el directorio temporal
rm -rf /root/ips-zerox

echo "Todas las tareas se han completado."

dos2unix /usr/local/bin/ips-zerox.sh

apt update && apt upgrade -y
# Paso 20: Realizar un reinicio con contador y puntos
echo "El sistema se reiniciará en 5 segundos..."chmod +x /usr/local/bin/ips-zerox.sh

# Contenido del archivo rc.local
RC_LOCAL_CONTENT="#!/bin/sh -e\n\n# Añadir comandos aquí\n\nexit 0"

# Ruta al archivo de script
SCRIPT_FILE="/usr/local/bin/ips-zerox.sh"

chmod +x /usr/local/bin/ips-zerox.sh

# Crear o sobrescribir el archivo /etc/rc.local
echo -e "$RC_LOCAL_CONTENT" | sudo tee /etc/rc.local > /dev/null

# Añadir permisos de ejecución a /etc/rc.local
sudo chmod +x /etc/rc.local

# Habilitar el servicio rc-local
sudo systemctl enable rc-local
for i in {5..1}; do
    echo -n "$i..."
    sleep 1
done

reboot
            ;;
       
        2)
	
apt install apache2 -y
apt install -y mysql-server -y

# Paso 0: Instalación de MySQL y configuración de base de datos
read -p "Ingresa el nombre de la base de datos: " db_name
read -p "Ingresa la contraseña para la base de datos: " db_password

mysql -e "CREATE DATABASE $db_name;"
mysql -e "CREATE USER '$db_name'@'localhost' IDENTIFIED BY '$db_password';"
mysql -e "GRANT ALL ON $db_name.* to '$db_name'@'localhost';"

# Paso 1: Instalación de PHP y Apache con módulos
sudo apt install -y php7.4 php7.4-mysql libapache2-mod-php7.4
sudo a2enmod php7.4
sudo a2enmod headers

# Añadir la directiva ServerName al archivo de configuración de Apache
echo "ServerName localhost" | sudo tee /etc/apache2/conf-available/servername.conf
sudo a2enconf servername

echo "Configuración completada hemos reparado un error que va a suceder."

# Reiniciar Apache
sudo systemctl restart apache2

# Paso 2: Habilitar .htaccess
sudo a2enmod rewrite
sudo systemctl restart apache2

# Paso 3: Dar permisos a las carpetas de WordPress
sudo chown -R www-data:www-data /var/www/html
sudo chmod -R 755 /var/www/html

# Paso 4, 5 y 6: Configuración del administrador de WordPress
read -p "Ingresa el nombre de usuario del administrador de WordPress: " wp_admin
read -p "Ingresa la contraseña del administrador de WordPress: " wp_password
read -p "Ingresa el correo del administrador de WordPress: " wp_email

# Descargar y configurar WordPress
cd /tmp
wget https://wordpress.org/latest.tar.gz
tar -xzvf latest.tar.gz
sudo cp -r wordpress/* /var/www/html/
sudo mv /var/www/html/wp-config-sample.php /var/www/html/wp-config.php
sudo sed -i "s/database_name_here/$db_name/" /var/www/html/wp-config.php
sudo sed -i "s/username_here/$db_name/" /var/www/html/wp-config.php
sudo sed -i "s/password_here/$db_password/" /var/www/html/wp-config.php

# Configurar datos del administrador en wp-config.php
sudo sed -i "s/'username'/'$wp_admin'/" /var/www/html/wp-config.php
sudo sed -i "s/'password'/'$wp_password'/" /var/www/html/wp-config.php
sudo sed -i "s/'email'/'$wp_email'/" /var/www/html/wp-config.php


# Verificar si se está ejecutando como superusuario
if [[ $EUID -ne 0 ]]; then
    echo "Este script debe ejecutarse como superusuario (root)." 
    exit 1
fi

# Configurar actualizaciones automáticas de seguridad
echo "Configurando actualizaciones automáticas de seguridad..."
apt-get install -y unattended-upgrades
cat <<EOF > /etc/apt/apt.conf.d/20auto-upgrades
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
EOF

# Reiniciar el servicio de actualizaciones automáticas
systemctl enable unattended-upgrades
systemctl restart unattended-upgrades

echo "Configuración finalizada. Tu servidor Apache2 está configurado en modo paranoico y con medidas de seguridad adicionales."



# Ruta al archivo apache2.conf
httpd_conf="/etc/apache2/apache2.conf"

# Actualizar la configuración de AllowOverride en apache2.conf
sed -i 's/AllowOverride None/AllowOverride All/g' "$httpd_conf"

# Actualizar la configuración en los bloques <Directory>
sed -i 's/<Directory \"\/var\/www\">/<Directory \"\/var\/www\">\n    AllowOverride All\n    Require all granted/g' "$httpd_conf"
sed -i 's/<Directory \"\/var\/www\/html\">/<Directory \"\/var\/www\/html\">\n    AllowOverride All\n    Options Indexes FollowSymLinks\n    Require all granted/g' "$httpd_conf"

# Reiniciar el servicio de Apache
systemctl restart apache2

echo "La configuración de AllowOverride en Apache ha sido actualizada y el servicio reiniciado."

#permisos de Wordpress

sudo chown -R www-data:www-data /var/www/html
sudo find /var/www/html -type d -exec chmod 755 {} \;
sudo find /var/www/html -type f -exec chmod 644 {} \;
rm -r /var/www/html/license.txt
rm -r /var/www/html/readme.html
rm -r /var/www/html/index.html
cd /var/www/html/wp-content/plugins


# Define la URL del archivo ZIP
URL="https://raw.githubusercontent.com/Zerox-Security/ssl-cloudflare/main/cloudflare-flexible-ssl.1.3.1.zip"

# Define la carpeta de destino de WordPress
WP_PLUGIN_DIR="/var/www/html/wp-content/plugins"

# Verifica si el descompresor zip está instalado
if ! command -v unzip &>/dev/null; then
    echo "El descompresor 'zip' no está instalado. Instalándolo..."
    sudo apt-get update
    sudo apt-get install -y unzip
fi

# Descarga el archivo ZIP
echo "Descargando el archivo ZIP..."
curl -o /tmp/cloudflare-flexible-ssl.zip "$URL"

# Verifica si la descarga fue exitosa
if [ $? -eq 0 ]; then
    # Descomprime el archivo ZIP en la carpeta de plugins de WordPress
    echo "Descomprimiendo el archivo ZIP en $WP_PLUGIN_DIR..."
    unzip /tmp/cloudflare-flexible-ssl.zip -d "$WP_PLUGIN_DIR"

    # Permisos ejecutados
    echo "Cambiando los permisos de la carpeta del plugin..."
    chown -R www-data:www-data "$WP_PLUGIN_DIR/cloudflare-flexible-ssl"
    chmod -R 755 "$WP_PLUGIN_DIR/cloudflare-flexible-ssl"

    echo "Instalación completada exitosamente."
else
    echo "Error al descargar el archivo ZIP."
fi


# Paso 7: Mostrar la información al usuario
echo -e "\nInstalación completada. Aquí está la información:"
echo "Tu Base de datos: $db_name"
echo "Tu Contraseña de la base de datos: $db_password"
echo "Tu Nombre de usuario del administrador: $wp_admin"
echo "Tu Contraseña del administrador: $wp_password"
echo "Tu Correo del administrador: $wp_email"

# Imprimir el enlace al sitio WordPress con el nombre de dominio
domain_name=$(hostname)
echo "Accede a tu sitio WordPress en: https://$domain_name/"
            ;;
        3)
          

# Actualizar el sistema
apt update
apt upgrade -y



# Deshabilitar los módulos de Apache no utilizados
a2dismod -f autoindex
a2dismod -f status

# Configurar encabezados HTTP seguros
echo "Header always set X-XSS-Protection \"1; mode=block\"" >> /etc/apache2/conf-available/security.conf
echo "Header always set X-Content-Type-Options \"nosniff\"" >> /etc/apache2/conf-available/security.conf
echo "Header always set X-Frame-Options \"SAMEORIGIN\"" >> /etc/apache2/conf-available/security.conf
a2enconf security
systemctl reload apache2

# Obtener la dirección IP de la máquina
ip_address=$(hostname -I | awk '{print $1}')

# Ruta al archivo de configuración en /etc/apache2/sites-available
config_file="/etc/apache2/sites-available/000-default.conf"

# Agregar la dirección IP como ServerName en la configuración
sed -i "s/ServerName xxxxxxxxxx/ServerName $ip_address/g" "$config_file"

# Agregar las directivas al final del archivo de configuración
echo "
<VirtualHost *:80>
    ServerName $ip_address
    RewriteEngine On
    RewriteRule ^(.*)$ https://%{HTTP_HOST}$1 [R=301,L]
</VirtualHost>
" >> "$config_file"

# Reiniciar el servicio de Apache
systemctl restart apache2

echo "NADIE ACCEDERÁ A TU PAGINA, DESDE LA IP DIRECTA"


# Instalar mod_evasive para protección contra ataques DoS
apt install libapache2-mod-evasive -y
mkdir /var/log/mod_evasive
chown www-data:www-data /var/log/mod_evasive
echo "DOSHashTableSize 3097" >> /etc/apache2/mods-available/evasive.conf
echo "DOSPageCount 5" >> /etc/apache2/mods-available/evasive.conf
echo "DOSSiteCount 50" >> /etc/apache2/mods-available/evasive.conf
echo "DOSPageInterval 1" >> /etc/apache2/mods-available/evasive.conf
echo "DOSSiteInterval 1" >> /etc/apache2/mods-available/evasive.conf
echo "DOSBlockingPeriod 10" >> /etc/apache2/mods-available/evasive.conf
a2enmod evasive
systemctl reload apache2

if [ "$EUID" -ne 0 ]; then
    echo "Este script debe ser ejecutado como superusuario (root)." 
    exit 1
fi

# Ruta del archivo de configuración de Apache
apache_config="/etc/apache2/apache2.conf"

# Incrementar el número de procesos concurrentes
sed -i "s/MaxRequestWorkers .*/MaxRequestWorkers 150/" $apache_config

# Ajustar el número de procesos inactivos
sed -i "s/MinSpareServers .*/MinSpareServers 5/" $apache_config
sed -i "s/MaxSpareServers .*/MaxSpareServers 10/" $apache_config

# Ajustar el número máximo de conexiones concurrentes
sed -i "s/ServerLimit .*/ServerLimit 100/" $apache_config

# Habilitar compresión Gzip para acelerar la transferencia de datos
echo "<IfModule mod_deflate.c>" >> $apache_config
echo "    SetOutputFilter DEFLATE" >> $apache_config
echo "    SetEnvIfNoCase Request_URI \.(?:gif|jpe?g|png)$ no-gzip" >> $apache_config
echo "    SetEnvIfNoCase Request_URI \.(?:exe|t?gz|zip|gz2|sit|rar)$ no-gzip" >> $apache_config
echo "    SetEnvIfNoCase Request_URI \.pdf$ no-gzip" >> $apache_config
echo "    BrowserMatch ^Mozilla/4 gzip-only-text/html" >> $apache_config
echo "    BrowserMatch ^Mozilla/4\.0[678] no-gzip" >> $apache_config
echo "    BrowserMatch \bMSIE !no-gzip !gzip-only-text/html" >> $apache_config
echo "</IfModule>" >> $apache_config

# Reiniciar Apache para aplicar los cambios
systemctl restart apache2

echo "Apache2 ha sido optimizado para un mejor rendimiento."



# Reiniciar Apache
systemctl restart apache2

echo "Configuración de seguridad completada y optimizado para un mejor rendimiento."


			
			;;
			
			4) 
			

# Verificar si se está ejecutando como root
if [ "$EUID" -ne 0 ]; then
  echo "Por favor, ejecuta este script como superusuario (root)."
  exit 1
fi

# Actualizar el sistema
apt update
apt upgrade -y

# Instalar Apache2 y PHP 7.4 si aún no están instalados
apt install -y apache2 php7.4 libapache2-mod-php7.4

# Instalar ModSecurity
apt install -y libapache2-mod-security2

# Habilitar el módulo ModSecurity
a2enmod security2

# Configurar ModSecurity
cat <<EOL > /etc/apache2/mods-available/security2.conf
<IfModule security2_module>
    SecDataDir /var/cache/modsecurity
    IncludeOptional /etc/modsecurity/*.conf
    IncludeOptional /etc/modsecurity/*.load
</IfModule>
EOL

# Habilitar el módulo ModSecurity
a2enmod security2

# Descargar el Core Rule Set (CRS)
apt install -y git
cd /etc/apache2/
git clone https://github.com/coreruleset/coreruleset.git

# Habilitar las reglas del CRS en la configuración de ModSecurity
cat <<EOL >> /etc/apache2/mods-available/security2.conf
IncludeOptional /etc/apache2/coreruleset/*.conf
EOL

# Reiniciar Apache
systemctl restart apache2

echo "La instalación y configuración de ModSecurity se ha completado."

			;;
   
   			5) 
      # Función para cambiar y descomentar el puerto SSH
change_ssh_port() {
  read -p "Por favor, ingrese el nuevo puerto SSH: " new_port
  if [[ $new_port =~ ^[0-9]+$ ]]; then
    sed -i "/^#*Port/c\Port $new_port" /etc/ssh/sshd_config
    systemctl restart sshd
    echo "El puerto SSH se ha cambiado y descomentado exitosamente a $new_port."
  else
    echo "¡Por favor, ingrese un número de puerto válido!"
  fi
}

# Pregunta al usuario si ya abrió el puerto en el panel de control de la empresa
read -p "¿Ha abierto el puerto SSH en el panel de control de su empresa de distribuidor? (Y/N): " response

if [ "$response" == "Y" ] || [ "$response" == "y" ]; then
  change_ssh_port
elif [ "$response" == "N" ] || [ "$response" == "n" ]; then
  # Advertencia en color verde y en mayúsculas
  echo -e "\e[32m¡ADVERTENCIA: DEBE ABRIR Y DESCOMENTAR EL PUERTO SSH EN EL PANEL DE CONTROL DE SU EMPRESA DE DISTRIBUIDOR PARA EVITAR PERDER ACCESO A SU MÁQUINA!\e[0m"
else
  echo "Respuesta no válida. Por favor, ingrese 'Y' o 'N'."
fi

#!/bin/bash

# Elimina las claves host existentes
rm /etc/ssh/ssh_host_*

# Genera nuevas claves RSA
ssh-keygen -t rsa -b 4096 -f /etc/ssh/ssh_host_rsa_key -N ""

# Genera nuevas claves Ed25519
ssh-keygen -t ed25519 -f /etc/ssh/ssh_host_ed25519_key -N ""

# Filtra y modifica el archivo moduli
awk '$5 >= 3071' /etc/ssh/moduli > /etc/ssh/moduli.safe
mv /etc/ssh/moduli.safe /etc/ssh/moduli

# Actualiza la configuración del servidor SSH
sed -i 's/^\#HostKey \/etc\/ssh\/ssh_host_\(rsa\|ed25519\)_key$/HostKey \/etc\/ssh\/ssh_host_\1_key/g' /etc/ssh/sshd_config

# Agrega configuraciones de seguridad adicionales
echo -e "\n# Restricción de algoritmos de intercambio de claves, cifrado y MAC, según sshaudit.com\n# guía de endurecimiento.\nKexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group-exchange-sha256\nCiphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr\nMACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,umac-128-etm@openssh.com\nHostKeyAlgorithms ssh-ed25519,ssh-ed25519-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,sk-ssh-ed25519-cert-v01@openssh.com,rsa-sha2-256,rsa-sha2-512,rsa-sha2-256-cert-v01@openssh.com,rsa-sha2-512-cert-v01@openssh.com" > /etc/ssh/sshd_config.d/ssh-audit_hardening.conf

# Reinicia el servicio SSH
service ssh restart

echo "Configuración de SSH completada."



echo "Configuración de SSH completada."

      
      			;;

        *)
            echo "Opción inválida."
            ;;
    esac
}

# Ciclo principal
while true; do
    show_banner
    show_options
    read -p "Ingresa el número de la opción (0 para salir): " option

    if [ "$option" -eq 0 ]; then
        echo "Saliendo..."
        break
    fi

    execute_script $option

    read -p "Presiona Enter para continuar..."
done
