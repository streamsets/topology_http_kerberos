#!/bin/bash

#pushd kdc
#podman build . -t clusterdock/topology_http_kerberos:kdc
#popd

pushd webserver
podman build . -t clusterdock/topology_http_kerberos:webserver
popd
