# -*- coding: utf-8 -*-
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import logging
import os
import re

from clusterdock.models import Cluster, Node
from clusterdock.utils import wait_for_condition

logger = logging.getLogger('clusterdock.{}'.format(__name__))

DEFAULT_NAMESPACE = 'clusterdock'

KERBEROS_VOLUME_DIR = '/etc/clusterdock/kerberos'

KDC_ACL_FILENAME = '/var/kerberos/krb5kdc/kadm5.acl'
KDC_CONF_FILENAME = '/var/kerberos/krb5kdc/kdc.conf'
KDC_KEYTAB_FILENAME = '{}/clusterdock.keytab'.format(KERBEROS_VOLUME_DIR)
SERVICE_KEYTAB_FILENAME = '{}/service.keytab'.format(KERBEROS_VOLUME_DIR)
CLIENT_KEYTAB_FILENAME = '{}/client.keytab'.format(KERBEROS_VOLUME_DIR)
KDC_KRB5_CONF_FILENAME = '/etc/krb5.conf'


def main(args):
    kerberos_volume_dir = os.path.expanduser(args.kerberos_config_directory or args.clusterdock_config_directory)

    # kerberos node.
    kdc_image = '{}/clusterdock/topology_nodebase_kerberos:centos6.8'.format(args.registry)
    kdc_hostname = args.kdc_node[0]
    kdc_node = Node(hostname=kdc_hostname, group='kdc', image=kdc_image,
                    volumes=[{kerberos_volume_dir: KERBEROS_VOLUME_DIR}])

    # webserver node. this is the reverse proxy that exposes the URLs
    webserver_image = '{}/{}/topology_http_kerberos:webserver'.format(args.registry,
                                                                      args.namespace or DEFAULT_NAMESPACE)
    webserver_hostname = args.webserver_node[0]
    webserver_node = Node(hostname=webserver_hostname, group='webserver', image=webserver_image,
                          volumes=[{kerberos_volume_dir: KERBEROS_VOLUME_DIR}], ports={80: 80, 443: 443})

    # service node. the actual service (in our case, pretenders, which allows us to create mock http urls)
    service_hostname = args.service_node[0]
    service_node = Node(hostname=service_hostname, group='service', image='pretenders/pretenders:1.4',
                        ports={8000: 8000})

    cluster = Cluster(kdc_node, webserver_node, service_node)
    cluster.start(args.network)

    logger.info('Updating KDC configurations ...')
    realm = cluster.network.upper()
    krb5_conf_data = kdc_node.get_file(KDC_KRB5_CONF_FILENAME)
    kdc_node.put_file(KDC_KRB5_CONF_FILENAME,
                      re.sub(r'EXAMPLE.COM', realm,
                             re.sub(r'example.com', cluster.network,
                                    re.sub(r'kerberos.example.com',
                                           r'{}.{}'.format(kdc_hostname, cluster.network),
                                           krb5_conf_data))))
    kdc_conf_data = kdc_node.get_file(KDC_CONF_FILENAME)
    kdc_node.put_file(KDC_CONF_FILENAME,
                      re.sub(r'EXAMPLE.COM', realm,
                             re.sub(r'\[kdcdefaults\]',
                                    r'[kdcdefaults]\n max_renewablelife = 7d\n max_life = 1d',
                                    kdc_conf_data)))
    acl_data = kdc_node.get_file(KDC_ACL_FILENAME)
    kdc_node.put_file(KDC_ACL_FILENAME, re.sub(r'EXAMPLE.COM', realm, acl_data))

    logger.info('Starting KDC ...')
    kdc_commands = [
        'kdb5_util create -s -r {realm} -P kdcadmin'.format(realm=realm),
        'kadmin.local -q "addprinc -pw {admin_pw} admin/admin@{realm}"'.format(admin_pw='acladmin',
                                                                               realm=realm)
    ]

    # Add two principals. One for the http service & the other for a client.
    principals = [{'principal': 'HTTP/webserver.{}@{}'.format(cluster.network, realm),
                   'keytab': SERVICE_KEYTAB_FILENAME},
                  {'principal': 'HTTP/sdcwebserver.{}@{}'.format(cluster.network, realm),
                   'keytab': '/etc/clusterdock/kerberos/sdcwebserver.keytab'},
                  {'principal': 'browser@{0}'.format(realm),
                   'keytab': CLIENT_KEYTAB_FILENAME}]

    create_principals_cmds = ['kadmin.local -q "addprinc -randkey {}"'.format(principal['principal'])
                              for principal in principals]
    kdc_commands.extend(create_principals_cmds)

    # Delete any exisiting keytab files.
    kdc_commands.append('rm -f {}/*.keytab'.format(KERBEROS_VOLUME_DIR))

    create_keytab_cmds = ['kadmin.local -q "xst -norandkey -k {} {}"'.format(principal['keytab'],
                                                                             principal['principal'])
                          for principal in principals]
    kdc_commands.extend(create_keytab_cmds)

    kdc_commands.extend([
        'krb5kdc',
        'kadmind',
        'authconfig --enablekrb5 --update'
    ])

    kdc_commands.append('cp -f {} {}'.format(KDC_KRB5_CONF_FILENAME, KERBEROS_VOLUME_DIR))
    kdc_commands.extend(['chmod 644 {}'.format(principal['keytab']) for principal in principals])

    kdc_node.execute(command="bash -c '{}'".format('; '.join(kdc_commands)),
                     quiet=not args.verbose)

    logger.info('Validating kerberos service health ...')
    _validate_service_health(node=kdc_node, services=['krb5kdc', 'kadmin'], quiet=not args.verbose)

    # copy self signed certificate and private key from image to clusterdock config location. Any consumer
    # can then import the certificate as a trusted certificate.
    webserver_node.execute('cp /etc/ssl/certs/selfsigned.crt {ssl_cert_dir}/selfsigned.crt '
                           '&& cp /etc/ssl/private/private.key {ssl_cert_dir}/private.key'.format(
                               ssl_cert_dir=KERBEROS_VOLUME_DIR),
                           quiet=not args.verbose)

    # copy the krb5.conf file from the shared location to /etc on the webserver node and start the webserver.
    webserver_node.execute('cp -p {}/krb5.conf {}'.format(KERBEROS_VOLUME_DIR, KDC_KRB5_CONF_FILENAME),
                           quiet=not args.verbose)
    webserver_node.execute('service httpd start', quiet=not args.verbose)

    logger.info('Validating web server health ...')
    _validate_service_health(node=webserver_node, services=['httpd'], quiet=not args.verbose)


def _validate_service_health(node, services, quiet=True):
    def condition(node, services):
        services_with_poor_health = [service
                                     for service in services
                                     if node.execute(command='service {} status'.format(service),
                                                     quiet=quiet).exit_code != 0]
        if services_with_poor_health:
            logger.debug('Services with poor health: %s',
                         ', '.join(services_with_poor_health))
        # Return True if the list of services with poor health is empty.
        return not bool(services_with_poor_health)

    def success(time):
        logger.debug('Validated service health in %s seconds.', time)

    def failure(timeout):
        raise TimeoutError('Timed out after {} seconds waiting '
                           'to validate service health.'.format(timeout))
    wait_for_condition(condition=condition, condition_args=[node, services],
                       time_between_checks=3, timeout=30, success=success, failure=failure)
