#!/usr/bin/env bash
!#/bin/bash

AUG_X64="augeas-lenses augeas-tools libaugeas0 python-augeas"
AUG_X386="augeas-lenses augeas-tools:i386 libaugeas0:i386 python-augeas"


# detect if 64 or 32 bit machine because packages are different
MACHINE_TYPE=`uname -m`
if [ ${MACHINE_TYPE} == 'x86_64' ]; then
    # 64-bit stuff here
   MISC=$AUG_X64
else
      # 32-bit stuff here
   MISC=$AUG_X386
fi
echo "hello"
echo ${MACHINE_TYPE}
echo ${MISC}


if [ -f /etc/lsb-release ]; then
        os=$(lsb_release -s -d)
elif [ -f /etc/debian_version ]; then
        os="Debian $(cat /etc/debian_version)"
elif [ -f /etc/centos-release ]; then
        os=`cat /etc/redhat-release`
else
        os="$(uname -s) $(uname -r)"
fi

a=( $os )
echo ${a[0]}

if [ ${a[0]} == 'CentOS' ]; then
    echo 'success'
fi

