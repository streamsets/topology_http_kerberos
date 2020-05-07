#!/bin/bash

#pushd kdc
#docker build . -t clusterdock/topology_http_kerberos:kdc
#popd

pushd webserver
docker build . -t clusterdock/topology_http_kerberos:webserver
popd
