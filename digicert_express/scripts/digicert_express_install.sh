#!/bin/bash

LOG_FILE="digicert_express_install.log"

function dc_log {
    echo $1 | tee -a ${LOG_FILE}
}

function cent_is_package_installed {
  if yum list installed "$@" >/dev/null 2>&1; then
    return 0
  else
    return 1
  fi
}

dc_log
dc_log "DigiCert Express Install Bootstrapper"
dc_log

CHECK_INSTALL_PACKAGES=""
DIGICERT_PYTHON_PACKAGES="digicert-client digicert-express"
CHECK_PYTHON_PACKAGES="python-augeas"
touch ${LOG_FILE}
start_date=`date`
dc_log "${start_date}"

read -p "I agree to the terms & conditions at: https://www.digicert.com/docs/agreements/DigiCert_SA.pdf [y/N] " REPLY
if ! [[ "$REPLY" = "y" || "$REPLY" = "Y" || "$REPLY" = "Yes" || "$REPLY" = "yes" || "$REPLY" = "YES" ]]; then
    dc_log "You must accept the terms & conditions to use this program"
    exit
fi


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
echo "Found OS: ${os}"


# check for wget because CentOS needs it to install pip
if [[ $os == *"CentOS"* ]]
then
    wget --version >> /dev/null 2>&1
    if [ $? -eq 0 ]
    then
        dc_log "Prerequisite package wget is installed, continuing installation."
    else
        pip -V >> /dev/null 2>&1
        if [ $? -eq 127 ]
        then
            dc_log "wget is not installed.  Please install wget by typing: 'sudo yum install wget'"
            exit
        fi
    fi
fi


# check for architecture 32 bit or 64 bit
MACHINE_TYPE=`uname -m`
if [ ${MACHINE_TYPE} = "x86_64" ]; then
    # 64-bit stuff here
    CHECK_INSTALL_PACKAGES="augeas-lenses augeas-tools libaugeas0 openssl"
else
  # 32-bit stuff here
    CHECK_INSTALL_PACKAGES="augeas-lenses augeas-tools:i386 libaugeas0:i386 openssl"
fi


# add argparse to the install list if python < 2.7
PY_VERSION=`python -c 'import sys; print sys.version_info < (2, 7)'`
if [ $PY_VERSION = True ]; then
    CHECK_PYTHON_PACKAGES="$CHECK_PYTHON_PACKAGES argparse"
fi

VERSION=`python -c 'import sys; print sys.version_info < (2, 6)'`

# check for apache version
if [[ $os == *"CentOS"* ]]
then
    APACHE_VERSION=`apachectl -v | grep 'Server version' | cut -d '/' -f 2 | cut -d ' ' -f 1`
    if [[ ! $os =~ "6.5" ]] || [[ $VERSION = True ]] || [[ ! $APACHE_VERSION =~ "2.2" ]]; then
        echo ""
        echo "The requirements to run DigiCert Express Install are Cent OS 6.5 with Python 2.6.x and Apache 2.2.x"
        echo ""
        exit
    fi
else
    APACHE_VERSION=`apachectl -v | grep 'Server version' | cut -d '/' -f 2 | cut -d ' ' -f 1`
    if [[ ! $os =~ "14.04" ]] || [[ $PY_VERSION = True ]] || [[ ! $APACHE_VERSION =~ "2.4" ]]; then
        echo ""
        echo "The requirements to run DigiCert Express Install are Ubuntu 14.04 with Python 2.7.x and Apache 2.4.x"
        echo ""
        exit
    fi
fi


# check for dependencies installed
INSTALL_PACKAGES=""
PACKAGES="augeas openssl augeas-libs mod_ssl"
if [[ $os == *"CentOS"* ]]
then
    for package in $PACKAGES; do
        if cent_is_package_installed $package; then
            dc_log "Prerequisite package $package is already installed."
        else
            INSTALL_PACKAGES="$INSTALL_PACKAGES $package"
            install_cmd="yum"
        fi
    done
else
    for package in $CHECK_INSTALL_PACKAGES; do
        if dpkg --get-selections | grep -q "^$package[[:space:]]*install$" >> ${LOG_FILE}; then
            dc_log "Prerequisite package $package is already installed."
        else
            INSTALL_PACKAGES="$INSTALL_PACKAGES $package"
            install_cmd="apt-get"
        fi
    done
fi


# check for python-pip dependency
if [[ $os == *"CentOS"* ]]; then
    pip -V >> /dev/null 2>&1
    if [ $? -eq 127 ]
    then
        dc_log "Python PIP package needs to be installed."
        dc_log "Downloading PIP install script to /tmp"
        wget --no-check-certificate --directory-prefix=/tmp https://bootstrap.pypa.io/get-pip.py >> ${LOG_FILE} 2>&1

        dc_log "Installing PIP package from install script."
        sudo python /tmp/get-pip.py >> ${LOG_FILE} 2>&1
    else
        dc_log "Prerequisite python-pip package is already installed."
    fi
else
    if [ "dpkg-query -W python-pip | awk {'print $1'} = """ ]; then
        dc_log "Updating repository."
        sudo apt-get update >> ${LOG_FILE} 2>&1

        dc_log "Python PIP package needs to be installed.  Installing PIP now from repository."
        sudo apt-get install -q -y python-pip >> ${LOG_FILE} 2>&1
    fi
fi


# check for python dependency modules
PYTHON_PACKAGES=""
for package in $CHECK_PYTHON_PACKAGES; do
    installed_package=`pip list | grep $package | cut -c -${#package}`
    if [ "$installed_package" = "$package" ]; then
        dc_log "Prerequisite Python package $package is already installed."
    else
        PYTHON_PACKAGES="$PYTHON_PACKAGES $package"
    fi
done


MISSING_DIGICERT_PYTHON_PACKAGES=""
for package in $DIGICERT_PYTHON_PACKAGES; do
    installed_package=`pip list | grep $package | cut -c -${#package}`
    if [ "$installed_package" = "$package" ]; then
        dc_log "Prerequisite Python package $package is already installed."
    else
        MISSING_DIGICERT_PYTHON_PACKAGES="$MISSING_DIGICERT_PYTHON_PACKAGES $package"
    fi
done

# show what needs to be installed
if ! [ "$INSTALL_PACKAGES" = "" ]; then
    dc_log "The following system packages need to be installed: $INSTALL_PACKAGES"
fi
if ! [ "$PYTHON_PACKAGES" = "" ]; then
    dc_log "The following Python packages need to be installed: $PYTHON_PACKAGES"
fi
if ! [ "$MISSING_DIGICERT_PYTHON_PACKAGES" = "" ]; then
    dc_log "The following DigiCert packages need to be installed: $MISSING_DIGICERT_PYTHON_PACKAGES"
fi


# install the dependencies
if ! [[ "$INSTALL_PACKAGES" = "" && "$PYTHON_PACKAGES" = "" && $MISSING_DIGICERT_PYTHON_PACKAGES = "" ]]; then
    read -p "Do you wish to install these packages? [Y/n] " REPLY
    if ! [ "$REPLY" = "n" ]; then
        if ! [ "$INSTALL_PACKAGES" = "" ]; then
            dc_log "Installing packages...$INSTALL_PACKAGES. Please wait."
            sudo $install_cmd -q -y install $INSTALL_PACKAGES >> ${LOG_FILE} 2>&1
            if [ $? -ne 0 ]; then
                dc_log "Installation of package $package failed - aborting."
                exit
            fi
        fi
        if ! [ "$PYTHON_PACKAGES" = "" ]; then
            dc_log "Installing modules...$PYTHON_PACKAGES. Please wait."
            sudo pip install $PYTHON_PACKAGES >> ${LOG_FILE} 2>&1
            if [ $? -ne 0 ]; then
                dc_log "Installation of package $package failed - aborting."
                exit
            fi
        fi
        if ! [ "$MISSING_DIGICERT_PYTHON_PACKAGES" = "" ]; then
            dc_log "Installing modules...$MISSING_DIGICERT_PYTHON_PACKAGES. Please wait."
            sudo pip install --pre <?php echo $pypiSource ?> $MISSING_DIGICERT_PYTHON_PACKAGES >> ${LOG_FILE} 2>&1
            if [ $? -ne 0 ]; then
                dc_log "Installation of package $package failed - aborting."
                exit
            fi
        fi
        dc_log "All prerequisite packages have been installed."
    else
        dc_log "Aborting installation."
        exit
    fi
fi


# create a link so we can be run from the CLI
LINK_PATH="`pip show digicert-express | grep Location | cut -d ':' -f 2 | tr -d '[[:space:]]'`/digicert_express/express_install.py"
if [ -e "$LINK_PATH" ]; then
    if [[ $os == *"CentOS"* ]]
    then
        LINK_DIR="/usr/sbin/express_install"
    else
        LINK_DIR="/usr/local/bin/express_install"
    fi

    dc_log "Adding links to run DigiCert Express Install in ${LINK_DIR}"
    sudo ln -s "$LINK_PATH" "$LINK_DIR"
    sudo chmod 755 "$LINK_PATH"
	dc_log ""
	dc_log "DigiCert Express Install has been installed on your system."
	dc_log "As root, run 'express_install all' to install your certificate,"
	dc_log "or 'express_install --help' for more information."
	dc_log ""
fi


# DYNAMIC STUFF
# order details
DOMAIN=""
DOMAIN_PATH=`echo "$DOMAIN" | sed -e "s/\./_/g"`
FILEPATH="/etc/digicert/$DOMAIN_PATH"
ORDER=""
CERTIFICATE=""
CERTIFICATE_CHAIN=""
SUB=""

if ! [[ "$DOMAIN" = "" || "$ORDER" = "" ]]; then
    if ! [[ "$CERTIFICATE" = "" || "$CERTIFICATE_CHAIN" = "" ]]; then
        sudo mkdir -p "$FILEPATH"
        CERT_NAME=`echo "$DOMAIN" | sed -e "s/\./_/g"`

        # write the certificate to file
        dc_log "Copying certificate file to $FILEPATH/$CERT_NAME.crt"
        echo "$CERTIFICATE" | sudo tee "$FILEPATH/$CERT_NAME.crt" > /dev/null

        dc_log "Copying certificate chain file to $FILEPATH/DigiCertCA.crt"
        echo "$CERTIFICATE_CHAIN" | sudo tee "$FILEPATH/DigiCertCA.crt" > /dev/null
    fi

    # run express install
    dc_log "running: sudo express_install all --domain \"$DOMAIN\" --order_id \"$ORDER\""
    sudo express_install all --domain "$DOMAIN" --order_id "$ORDER" --sub_id "$SUB"

else
    dc_log "ERROR: You are missing your domain name or order id, please contact digicert support"
fi


dc_log
dc_log
dc_log "DigiCert Express Install Finished"
end_date=`date`
dc_log "${end_date}"
