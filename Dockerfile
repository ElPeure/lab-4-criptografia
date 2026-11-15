FROM ubuntu:22.04

# Evitar preguntas interactivas durante la instalación
ENV DEBIAN_FRONTEND=noninteractive

# Instalar el servidor SSH
RUN apt-get update && apt-get install -y openssh-server && \
    mkdir /var/run/sshd

# Establecer una contraseña para root (ejemplo: "password")
RUN echo 'root:password' | chpasswd

# Copiar tu archivo de configuración personalizado
COPY sshd_config /etc/ssh/sshd_config

# Generar las claves de host (incluyendo ed25519 que especificaste)
RUN ssh-keygen -A

# Exponer el puerto SSH
EXPOSE 22

# Comando para arrancar sshd en primer plano y mostrar logs en consola
CMD ["/usr/sbin/sshd", "-D", "-e"]