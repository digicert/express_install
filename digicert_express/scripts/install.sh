#!/bin/bash

echo
echo "DigiCert Express Install bootstrapper"
echo

CHECK_INSTALL_PACKAGES=""
CHECK_PYTHON_PACKAGES="digicert-client digicert-express"


# check for distribution, debian, centos, ubuntu
if [ -f /etc/lsb-release ]
then
        os=$(lsb_release -s -d)
elif [ -f /etc/debian_version ]; then
        os="Debian $(cat /etc/debian_version)"
elif [ -f /etc/centos-release ]; then
        os=`cat /etc/redhat-release`
else
        os="$(uname -s) $(uname -r)"
fi
#echo $os


# check for architecture 32 bit or 64 bit
MACHINE_TYPE=`uname -m`
if [ ${MACHINE_TYPE} = "x86_64" ]; then
    # 64-bit stuff here
    CHECK_INSTALL_PACKAGES="augeas-lenses augeas-tools libaugeas0 python-augeas openssl"
else
  # 32-bit stuff here
    CHECK_INSTALL_PACKAGES="augeas-lenses augeas-tools:i386 libaugeas0:i386 python-augeas openssl"
fi


INSTALL_PACKAGES=""
if [[ $os == *"CentOS"* ]]
then
    for package in "openssl augeas-libs augeas python-pip"; do
        if yum list installed "$package" >/dev/null 2>&1; then
            echo "Prerequisite package $package is already installed."
        else
            INSTALL_PACKAGES="$INSTALL_PACKAGES $package"
            install_cmd="yum"
        fi
    done
else
    for package in $CHECK_INSTALL_PACKAGES; do
        if dpkg --get-selections | grep -q "^$package[[:space:]]*install$" >/dev/null; then
            echo "Prerequisite package $package is already installed."
        else
            INSTALL_PACKAGES="$INSTALL_PACKAGES $package"
            install_cmd="apt-get"
        fi
    done
fi

PYTHON_PACKAGES=""
for package in $CHECK_PYTHON_PACKAGES; do
    installed_package=`pip list | grep $package | cut -c -${#package}`
    if [ "$installed_package" = "$package" ]; then
        echo "Prerequisite Python package $package is already installed."
    else
        PYTHON_PACKAGES="$PYTHON_PACKAGES $package"
    fi
done

if ! [ "$INSTALL_PACKAGES" = "" ]; then
    echo "The following system packages need to be installed: $INSTALL_PACKAGES"
fi
if ! [ "$PYTHON_PACKAGES" = "" ]; then
    echo "The following Python packages need to be installed: $PYTHON_PACKAGES"
fi

if ! [[ "$INSTALL_PACKAGES" = "" && "$PYTHON_PACKAGES" = "" ]]; then
    read -p "Do you wish to install these packages? [y/n] " REPLY
    if [ "$REPLY" = "y" ]; then
        if ! [ "$INSTALL_PACKAGES" = "" ]; then
            sudo $install_cmd -q -y install $INSTALL_PACKAGES
            if [ $? -ne 0 ]; then
                echo "Installation of package $package failed - aborting."
                exit
            fi
        fi
        if ! [ "$PYTHON_PACKAGES" = "" ]; then 
            sudo pip install --pre $PYTHON_PACKAGES
            if [ $? -ne 0 ]; then
                echo "Installation of package $package failed - aborting."
                exit
            fi
        fi
        echo "All prerequisite packages have been installed."
    else
        echo "Aborting installation."
        exit
    fi
fi

