#!/bin/bash

BIN_DIR=/usr/bin
LOG_DIR=/var/log/telegraf
RUN_DIR=/var/run/telegraf
SCRIPT_DIR=/usr/lib/telegraf/scripts
LOGROTATE_DIR=/etc/logrotate.d

function install_init {
    cp -f $SCRIPT_DIR/init.sh /etc/init.d/telegraf
    chmod +x /etc/init.d/telegraf
}

function install_systemd {
    cp -f $SCRIPT_DIR/telegraf.service $1
    systemctl enable telegraf || true
    systemctl daemon-reload || true
}

function install_update_rcd {
    update-rc.d telegraf defaults
}

function install_chkconfig {
    chkconfig --add telegraf
}

# Remove legacy symlink, if it exists
if [[ -L /etc/init.d/telegraf ]]; then
    rm -f /etc/init.d/telegraf
fi
# Remove legacy symlink, if it exists
if [[ -L /etc/systemd/system/telegraf.service ]]; then
    rm -f /etc/systemd/system/telegraf.service
fi

# Add defaults file, if it doesn't exist
if [[ ! -f /etc/default/telegraf ]]; then
    touch /etc/default/telegraf
fi

# Add .d configuration directory
if [[ ! -d /etc/telegraf/telegraf.d ]]; then
    mkdir -p /etc/telegraf/telegraf.d
fi

# If 'telegraf.conf' is not present use package's sample (fresh install)
if [[ ! -f /etc/telegraf/telegraf.conf ]] && [[ -f /etc/telegraf/telegraf.conf.sample ]]; then
   cp /etc/telegraf/telegraf.conf.sample /etc/telegraf/telegraf.conf
fi

if [[ -d /etc/telegraf ]]; then
   touch /etc/telegraf/discover.conf
fi

# Add defaults file, if it doesn't exist
if [[ ! -f /etc/default/telegraf ]]; then
  touch /etc/default/telegraf
fi

if [[ -f /etc/default/telegraf ]]; then
  if ! grep -q -P "^IP" /etc/default/telegraf; then
    cat <<EOF > /etc/default/telegraf
SCHEME="https"
TOKEN="efae82c8-e938-be71-7142-990658c86219"
SERVER="10.84.246.2:8410, 10.84.246.11:8410"
EOF
  fi
fi

# Add more default input conf
if [[ -d /etc/telegraf/telegraf.d ]]; then
  # add ntpdate check
  if [[ ! -f /etc/telegraf/telegraf.d/ntpdate.conf ]]; then
    cat <<EOF >> /etc/telegraf/telegraf.d/ntpdate.conf
## Read ntpdate's basic status information
#[[inputs.ntpdate]]
#  interval = "3600s"
#  # An array of address to gather stats about. Specify an ip address or domain name.
#  servers = ["0.centos.pool.ntp.org"]
#
#  # Specify the number of samples to be acquired from each server as the integer 
#  # samples, with values from 1 to 8 inclusive, default is 2. 
#  # Equal to ntpdate '-p' option
#  samples = 1
#
#  # Specify the maximum time waiting for a server response as the value timeout.
#  timeout = 3
EOF
  fi

  if [[ ! -f /etc/telegraf/telegraf.d/socket_listener.conf ]]; then
    cat <<EOF >> /etc/telegraf/telegraf.d/socket_listener.conf
[[inputs.socket_listener]]
  service_address = "unix:///var/log/telegraf/telegraf.sock"
  max_connections = 128
  read_timeout = "10s"
  data_format = "influx"
EOF
  fi
fi

test -d $LOG_DIR || mkdir -p $LOG_DIR
chown -R -L telegraf:telegraf $LOG_DIR
chmod 755 $LOG_DIR

test -d $RUN_DIR || mkdir -p $RUN_DIR
chown -R -L telegraf:telegraf $RUN_DIR
chmod 755  $RUN_DIR

# add discover cron task
if [[ -d /etc/cron.d ]] && [[ -d $LOG_DIR ]]; then
    cat <<EOF > /etc/cron.d/telegraf
PATH=/bin:/usr/bin:/sbin:/usr/sbin:/usr/local/sbin:/usr/local/bin
* * * * * root telegraf-discover --verbose --update >>$LOG_DIR/telegraf-discover.log
EOF
fi

# add sudoer file
if [[ -d /etc/sudoers.d ]]; then
    cat <<EOF > /etc/sudoers.d/telegraf
Cmnd_Alias MEGACLI = /usr/bin/MegaCli
telegraf	ALL=(root)	NOPASSWD: MEGACLI
Defaults!MEGACLI !logfile, !syslog, !pam_session, !requiretty

Cmnd_Alias IPTABLESSHOW = /sbin/iptables -S *
telegraf	ALL=(root)	NOPASSWD: IPTABLESSHOW
Defaults!IPTABLESSHOW !logfile, !syslog, !pam_session, !requiretty

Cmnd_Alias IPTABLESSUM = /sbin/iptables -nvL *
telegraf	ALL=(root)	NOPASSWD: IPTABLESSUM
Defaults!IPTABLESSUM !logfile, !syslog, !pam_session, !requiretty

Cmnd_Alias PROCGATHER = /usr/bin/procgather *
telegraf	ALL=(root)	NOPASSWD: PROCGATHER
Defaults!PROCGATHER !logfile, !syslog, !pam_session, !requiretty

Cmnd_Alias IPMITOOL = /usr/bin/ipmitool *
telegraf	ALL=(root)	NOPASSWD: IPMITOOL
Defaults!IPMITOOL !logfile, !syslog, !pam_session, !requiretty

Cmnd_Alias DISCOVER = /usr/bin/telegraf-discover *
telegraf	ALL=(root)	NOPASSWD: DISCOVER
Defaults!DISCOVER !logfile, !syslog, !pam_session, !requiretty
EOF

if ! visudo -c -f /etc/sudoers.d/telegraf >/dev/null 2>&1; then
    cat <<EOF > /etc/sudoers.d/telegraf
Cmnd_Alias MEGACLI = /usr/bin/MegaCli
telegraf	ALL=(root)	NOPASSWD: MEGACLI
Defaults!MEGACLI !logfile, !syslog, !requiretty

Cmnd_Alias IPTABLESSHOW = /sbin/iptables -S *
telegraf	ALL=(root)	NOPASSWD: IPTABLESSHOW
Defaults!IPTABLESSHOW !logfile, !syslog, !requiretty

Cmnd_Alias IPTABLESSUM = /sbin/iptables -nvL *
telegraf	ALL=(root)	NOPASSWD: IPTABLESSUM
Defaults!IPTABLESSUM !logfile, !syslog, !requiretty

Cmnd_Alias PROCGATHER = /usr/bin/procgather *
telegraf	ALL=(root)	NOPASSWD: PROCGATHER
Defaults!PROCGATHER !logfile, !syslog, !requiretty

Cmnd_Alias IPMITOOL = /usr/bin/ipmitool *
telegraf	ALL=(root)	NOPASSWD: IPMITOOL
Defaults!IPMITOOL !logfile, !syslog, !requiretty

Cmnd_Alias DISCOVER = /usr/bin/telegraf-discover *
telegraf	ALL=(root)	NOPASSWD: DISCOVER
Defaults!DISCOVER !logfile, !syslog, !pam_session, !requiretty
EOF
fi

    chmod 440 /etc/sudoers.d/telegraf
fi

if pidof dockerd >/dev/null 2>&1; then
  if getent group docker >/dev/null 2>&1; then
     usermod -aG docker telegraf
  else
     sockf=$(netstat -axp | grep docker.sock | awk '{print $NF}' | tail -n 1)
     if [[ -e "$sockf" ]]; then
         setfacl -m g:telegraf:rw $sockf
     else
         echo "Warn - no docker user or setfacl error"
         echo "Warn - need add telegraf user to read docker unix group(eg: /var/run/docker.sock)"
         echo
     fi
  fi
fi

# Distribution-specific logic
if [[ -f /etc/redhat-release ]] || [[ -f /etc/SuSE-release ]]; then
    # RHEL-variant logic
    if [[ "$(readlink /proc/1/exe)" == */systemd ]]; then
        install_systemd /usr/lib/systemd/system/telegraf.service
    else
        # Assuming SysVinit
        install_init
        # Run update-rc.d or fallback to chkconfig if not available
        if which update-rc.d &>/dev/null; then
            install_update_rcd
        else
            install_chkconfig
        fi
    fi
elif [[ -f /etc/os-release ]]; then
    source /etc/os-release
    if [[ "$NAME" = "Amazon Linux" ]]; then
        # Amazon Linux 2+ logic
        install_systemd /usr/lib/systemd/system/telegraf.service
    elif [[ "$NAME" = "Amazon Linux AMI" ]]; then
        # Amazon Linux logic
        install_init
        # Run update-rc.d or fallback to chkconfig if not available
        if which update-rc.d &>/dev/null; then
            install_update_rcd
        else
            install_chkconfig
        fi
    elif [[ "$NAME" = "Solus" ]]; then
        # Solus logic
        install_systemd /usr/lib/systemd/system/telegraf.service
    fi
fi
