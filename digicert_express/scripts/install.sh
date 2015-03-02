#!/bin/sh

AUG_X64="augeas-lenses augeas-tools libaugeas0 python-augeas"
AUG_X386="augeas-lenses augeas-tools:i386 libaugeas0:i386 python-augeas"

DIGICERT_INSTALL="digicert_procure express_install"

# check for distribution, debian, centos, ubuntu
check_distribution() {
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
}



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



# check for augeas packages
check_for_augeas() {

    for pkg in $MISC; do
          if dpkg --get-selections | grep -q "^$pkg[[:space:]]*install$" >/dev/null; then
              echo -e "$pkg is already installed"
          else
              echo "$pkg is not installed"
              echo "$pkg needs to be installed"
              echo -e "Should I install $pkg (y/n) \c"
              read
              if "$REPLY" = "y"; then
                  apt-get -q install $pkg
                  echo "Successfully installed $pkg"
              fi
          fi
    done
}


check_for_augeas_centos() {
    "yum list installed bind"

    for pkg in $MISC; do
          if yum list installed "$package" >/dev/null 2>&1; then
              echo -e "$pkg is already installed"
          else
              echo "$pkg is not installed"
              echo "$pkg needs to be installed"
              echo -e "Should I install $pkg (y/n) \c"
              read
              if "$REPLY" = "y"; then
                  yum -q install $pkg
                  echo "Successfully installed $pkg"
              fi
          fi
    done
}

# install our deps via pip
check_for_digicert_deps() {
    for pkg in $DIGICERT_INSTALL; do
          pip install $pkg
          echo "Successfully installed $pkg"
    done
}



# 1.  call check_architecture
arch=$(check_architecture)
echo $arch

# 2.  call check_distro
distro=$(check_distribution)
echo $distro

# 3.  check and install packages
if "$distro"= 'CentOS'; then
    check_for_augeas_centos
else
    check_for_augeas
fi

# 4.  install express install client
check_for_digicert_deps

#res=$(testReturn)
#echo $res