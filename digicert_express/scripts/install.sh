#!/bin/bash

echo
echo "DigiCert Express Install bootstrapper"
echo

CHECK_INSTALL_PACKAGES=""
CHECK_PYTHON_PACKAGES="digicert-client digicert-express python-augeas argparse"


# check for distribution, debian, centos, ubuntu
if [ -f /etc/lsb-release ]
then
        os=$(lsb_release -s -d)
elif [ -f /etc/debian_version ]; then
        os="Debian $(cat /etc/debian_version)"
elif [ -f /etc/centos-release ]; then
        os=`cat /etc/centos-release`
elif [ -f /etc/redhat-release ]; then
        os=`cat /etc/redhat-release`
else
        os="$(uname -s) $(uname -r)"
fi


# check for architecture 32 bit or 64 bit
MACHINE_TYPE=`uname -m`
if [ ${MACHINE_TYPE} = "x86_64" ]; then
    # 64-bit stuff here
    CHECK_INSTALL_PACKAGES="augeas-lenses augeas-tools libaugeas0 openssl python-pip mod_ssl"
else
  # 32-bit stuff here
    CHECK_INSTALL_PACKAGES="augeas-lenses augeas-tools:i386 libaugeas0:i386 openssl python-pip mod_ssl"
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
    read -p "Do you wish to install these packages? [Y/n] " REPLY
    if ! [ "$REPLY" = "n" ]; then
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

LINK_PATH="`pip show digicert-express | grep Location | cut -d ':' -f 2 | tr -d '[[:space:]]'`/digicert_express/express_install.py"
if [ -e "$LINK_PATH" ]; then
        sudo ln -s "$LINK_PATH" /usr/local/bin/express_install
        sudo chmod 755 "$LINK_PATH"
	echo ""
	echo "DigiCert Express Install has been installed on your system."
	echo "As root, run 'express_install all' to install your certificate,"
	echo "or 'express_install --help' for more information."
	echo ""
fi

# DYNAMIC STUFF
# order details
FILEPATH="/etc/digicert"
DOMAIN=""
ORDER=""
CERTIFICATE=""
CERTIFICATE_CHAIN=""
if ! [[ "$DOMAIN" = "" || "$ORDER" = "" ]]; then
    if ! [[ "$CERTIFICATE" = "" || "$CERTIFICATE_CHAIN" = "" ]]; then
        mkdir -p "$FILEPATH"
        CERT_NAME=`echo "$DOMAIN" | sed -e "s/\./_/g"`

        # write the certificate to file
        echo "$CERTIFICATE" >> "$FILEPATH/$CERT_NAME.crt"
        echo "$CERTIFICATE_CHAIN" >> "$FILEPATH/$CERT_NAME.pem"

        # run express install
        sudo express_install all --domain "$DOMAIN" --order_id "$ORDER"
    else
        # run express install
        sudo express_install all --domain "$DOMAIN" --order_id "$ORDER" --create_csr
    fi
else
    echo "ERROR: You are missing your domain name or order id, please contact digicert support"
fi