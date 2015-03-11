#!/bin/sh

INSTALL_PACKAGES=""
DIGICERT_PACKAGES="digicert_client express_install"

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
echo $os



# check for architecture 32 bit or 64 bit
check_architecture() {
    MACHINE_TYPE=`uname -m`
    if [ ${MACHINE_TYPE} == 'x86_64' ]; then
        # 64-bit stuff here
        MISC=$AUG_X64
    else
      # 32-bit stuff here
        MISC=$AUG_X386
    fi
    local myresult="x64"
    echo $MACHINE_TYPE

}
if [ ${MACHINE_TYPE} = "x86_64" ]
then
    INSTALL_PACKAGES="augeas-lenses augeas-tools libaugeas0 python-augeas openssl python-pip"
else
    INSTALL_PACKAGES="augeas-lenses augeas-tools:i386 libaugeas0:i386 python-augeas openssl python-pip"
fi



if [[ $os == *"CentOS"* ]]
then
    for package in "openssl augeas-libs augeas python-pip"; do
        if yum list installed "$package" >/dev/null 2>&1
        then
            echo "$package is already installed"
        else
            echo "$package is not installed"
            echo "$package needs to be installed"
            echo "Should I install $package (y/n)"
            read REPLY
            if [ "$REPLY" = "y" ]
            then
                sudo yum -q install $package
                echo "Successfully installed $package"
            fi
        fi
    done
else
    for pkg in $INSTALL_PACKAGES
    do
          if dpkg --get-selections | grep -q "^$pkg[[:space:]]*install$" >/dev/null
          then
              echo "$pkg is already installed"
          else
              echo "$pkg is not installed"
              echo "$pkg needs to be installed"
              echo "Should I install $pkg (y/n)"
              read
              if "$REPLY" = "y"
              then
                  apt-get -q install $pkg
                  echo "Successfully installed $pkg"
              fi
          fi
    done
fi

# install digicert modules
for package in $DIGICERT_PACKAGES
do
      sudo pip install $package
      echo "Successfully installed $package"
done