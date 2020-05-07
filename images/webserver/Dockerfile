FROM clusterdock/topology_nodebase:centos6.8

RUN yum install -y httpd mod_auth_kerb krb5-workstation
RUN mkdir -p /var/www/webserver.cluster/public_html
RUN chown -R apache:apache /var/www/webserver.cluster/public_html && \
    chmod 755 /var/www
COPY conf/httpd.conf /etc/httpd/conf/
COPY conf/index.html /var/www/webserver.cluster/public_html/
