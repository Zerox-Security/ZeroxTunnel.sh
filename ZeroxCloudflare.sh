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
    echo "Vamos a abrir el video para ti, copia la URL y pégala en tu navegador: https://youtu.be/"
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
echo "El sistema se reiniciará en 5 segundos..."
for i in {5..1}; do
    echo -n "$i..."
    sleep 1
done

reboot
            ;;
       
        2)
	
apt install apache2 -y
apt install -y mysql-server -y


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


# Obtén el nombre de dominio de la máquina
domain_name=$(hostname -f)

# Ruta al archivo apache2.conf
httpd_conf="/etc/apache2/apache2.conf"

# Actualizar la configuración de AllowOverride en apache2.conf
sed -i 's/AllowOverride None/AllowOverride All/g' "$httpd_conf"

# Pregunta al usuario dónde desea instalar WordPress (/var/www/ por defecto)
read -p "Ingrese la ubicación donde desea instalar WordPress (/var/www/): " install_location
install_location="${install_location:-/var/www/}"

# Verifica que el directorio de instalación exista
if [ ! -d "$install_location" ]; then
  echo "El directorio de instalación no existe. Creando el directorio..."
  mkdir -p "$install_location"
fi

# Descarga y descomprime WordPress en español
cd "$install_location"
wget https://es.wordpress.org/latest-es_ES.tar.gz
tar -xzvf latest-es_ES.tar.gz
rm latest-es_ES.tar.gz
mv wordpress/* wordpress/.[^.]* .

# Configura Apache2 para servir WordPress desde la ubicación especificada
echo "Configurando Apache2..."
cat <<EOF > "/etc/apache2/sites-available/$domain_name.conf"
<VirtualHost *:80>
    DocumentRoot ${install_location}
    ServerName $domain_name
    <Directory ${install_location}>
        AllowOverride All
        Require all granted
    </Directory>
    <Directory ${install_location}/wp-content>
        Options FollowSymLinks
    </Directory>
</VirtualHost>
EOF

a2ensite "$domain_name.conf"
systemctl reload apache2

# Actualiza la configuración en los bloques <Directory> en el archivo del usuario
httpd_user_conf="${HOME}/.htaccess"
cat <<EOF >> "$httpd_user_conf"
<Directory "${install_location}">
    AllowOverride All
    Require all granted
</Directory>
<Directory "${install_location}/wp-content">
    AllowOverride All
    Options Indexes FollowSymLinks
    Require all granted
</Directory>
EOF

# Descarga e instala el plugin de Cloudflare Flexible SSL
cd "${install_location}/wp-content/plugins"
wget https://downloads.wordpress.org/plugin/cloudflare-flexible-ssl.1.3.1.zip
unzip cloudflare-flexible-ssl.1.3.1.zip
rm cloudflare-flexible-ssl.1.3.1.zip

# Configura las claves y permisos de WordPress
cd "${install_location}"
cp wp-config-sample.php wp-config.php

# Pide al usuario la información de la base de datos
read -p "Ingrese el nombre de la base de datos: " db_name
read -p "Ingrese el usuario de la base de datos: " db_user
read -p "Ingrese la contraseña de la base de datos: " db_password

# Agrega la información de la base de datos al archivo de configuración de WordPress
sed -i "s/database_name_here/$db_name/" wp-config.php
sed -i "s/username_here/$db_user/" wp-config.php
sed -i "s/password_here/$db_password/" wp-config.php

# Genera las claves de WordPress
curl -s https://api.wordpress.org/secret-key/1.1/salt/ >> wp-config.php

# Pide al usuario un nombre de usuario y contraseña para WordPress
read -p "Ingrese el nombre de usuario para WordPress: " wp_user
read -sp "Ingrese la contraseña para WordPress: " wp_password
echo # Salto de línea después de la contraseña

# Agrega el nombre de usuario y la contraseña a WordPress
wp user create "$wp_user" --role=administrator --user_pass="$wp_password"

# Establece los permisos apropiados
chown -R www-data:www-data "${install_location}"
chmod -R 755 "${install_location}"

# Muestra al usuario los datos ingresados y la URL de acceso
echo "Datos ingresados:"
echo "Ubicación de WordPress: ${install_location}"
echo "Nombre de la base de datos: $db_name"
echo "Usuario de la base de datos: $db_user"
echo "Contraseña de la base de datos: ********" # oculta la contraseña
echo "URL de acceso a WordPress: http://$domain_name/"
echo "Nombre de usuario para WordPress: $wp_user"

# Finalización
echo "WordPress en español se ha instalado y configurado correctamente en ${install_location}."
echo "Las configuraciones se han agregado al archivo del usuario en ${httpd_user_conf}."

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
