FROM clusterdock/topology_nodebase:centos6.8

RUN yum install -y httpd mod_ssl mod_auth_kerb krb5-workstation
RUN mkdir -p /var/www/webserver.cluster/public_html
RUN chown -R apache:apache /var/www/webserver.cluster/public_html && \
    chmod 755 /var/www

# Overwrite the default config files.
COPY conf/ssl.conf /etc/httpd/conf.d/ssl.conf
COPY conf/httpd.conf /etc/httpd/conf/
COPY conf/index.html /var/www/webserver.cluster/public_html/

# Copy self-signed certificate and private key.
COPY conf/selfsigned.crt /etc/ssl/certs
RUN mkdir /etc/ssl/private
COPY conf/private.key /etc/ssl/private/
