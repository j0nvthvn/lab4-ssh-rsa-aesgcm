FROM ubuntu:22.04

# Servidor SSH y el directorio que sshd exige para arrancar
RUN apt-get update \
    && apt-get install -y --no-install-recommends openssh-server \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Usuario de prueba para la conexión
RUN useradd -m -s /bin/bash lab4 \
    && echo 'lab4:lab4pass' | chpasswd

# Dejar solo la clave de host Ed25519
RUN rm -f /etc/ssh/ssh_host_*_key* \
    && ssh-keygen -q -t ed25519 -f /etc/ssh/ssh_host_ed25519_key -N ''

# Configuración propia del servidor
COPY sshd_config /etc/ssh/sshd_config

EXPOSE 22
CMD ["/usr/sbin/sshd", "-D", "-e"]