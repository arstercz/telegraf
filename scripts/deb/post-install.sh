#!/bin/bash

BIN_DIR=/usr/bin
LOG_DIR=/var/log/telegraf
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

get_one_ip() {
  ifconfig -a | \
     perl -ne '
      BEGIN {
        sub ip_int {
          my $ip = shift;
          return 0 unless defined $ip;
          my $ipint = 0;
          my $i = 3;
          foreach ( $ip =~ /\d+/g) {
            $ipint += ($_ << (8*$i--));
          }
         
          return $ipint;
        }
    
        # internal ip range
        sub is_in_privite {
          my $ipint = shift;
         
          if (($ipint >= 167772160 && $ipint <= 184549375)
             || ($ipint >= 2886729728 && $ipint <= 2887778303)
             || ($ipint >= 3232235520 && $ipint <= 3232301055)) {
            return 1;
          }
          else {
            return 0;
          }
        }
    
        my @ips;
      };
    
      chomp;
      next unless grep(/inet\b/, $_);
      my $ip;
      if (m/\s*inet\s+(?:addr:|)(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+/) {
        $ip = $1;
      }
      if (is_in_privite(ip_int($ip))) {
        push @ips, $ip;
      }
    
      END {
        if (@ips + 0 > 0) {
          print $ips[0] . "\n";
        }
        else {
          print "\n";
        }
      }
  '
}

# Add defaults file, if it doesn't exist
if [[ ! -f /etc/default/telegraf ]]; then
  touch /etc/default/telegraf
fi

if [[ -f /etc/default/telegraf ]]; then
  IP=$(get_one_ip)
  IP="${IP:-"NULL"}"
  cat <<EOF >> /etc/default/telegraf
DC="NULL"
MARK="NULL"
TEAM="NULL"
IP="$IP"
EOF
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
#  servers = ["0.centos.pool.ntp.org", "162.159.200.1"]
#
#  # Specify the number of samples to be acquired from each server as the integer 
#  # samples, with values from 1 to 8 inclusive, default is 2. 
#  # Equal to ntpdate '-p' option
#  samples = 2
#
#  # Specify the maximum time waiting for a server response as the value timeout.
#  timeout = 5
EOF
  fi

  # add MegaCli check
  if [[ ! -f /etc/telegraf/telegraf.d/megacli.conf ]]; then
    cat <<EOF >> /etc/telegraf/telegraf.d/megacli.conf
## Read megacli's basic status information
## This canbe used in physical server.
#[[inputs.megacli]]
#  interval = "3600s"
#  ## Optionally specify the path to the megacli executable
#  path_megacli = "/usr/bin/MegaCli"
#
#  ## Gather info of the following type:
#  ## raid, disk, bbu
#  ## default is gather all of the three type
#  gather_type = ['disk', 'raid', 'bbu']
#
#  ## On most platforms used cli utilities requires root access.
#  ## Setting 'use_sudo' to true will make use of sudo to run MegaCli.
#  ## Sudo must be configured to allow the telegraf user to run MegaCli
#  ## without a password.
#  use_sudo = false
#
#  ## Timeout for the cli command to complete.
#  timeout = "3s"
EOF
  fi

  # add iptables check
  if [[ ! -f /etc/telegraf/telegraf.d/iptables.conf ]]; then
    cat <<EOF >> /etc/telegraf/telegraf.d/iptables.conf
## Gather packets and bytes throughput from iptables.
## need sudo privileges
#[[inputs.iptables]]
#  use_sudo = true
#  use_lock = false
#  table = "filter"
#  chains = [ "INPUT"]
EOF
  fi

  # add dns check
  if [[ ! -f /etc/telegraf/telegraf.d/dns_query.conf ]]; then
    cat <<EOF >> /etc/telegraf/telegraf.d/dns_query.conf
## Query given DNS server and gives statistics
#[[inputs.dns_query]]
#  ## servers to query
#  servers = ["1.1.1.1", "8.8.8.8"]
#
#  ## Network is the network protocol name.
#  # network = "udp"
#
#  ## Domains or subdomains to query.
#  # domains = ["www.baidu.com"]
#
#  ## Query record type.
#  ## Possible values: A, AAAA, CNAME, MX, NS, PTR, TXT, SOA, SPF, SRV.
#  # record_type = "A"
#
#  ## Dns server port.
#  # port = 53
#
#  ## Query timeout in seconds.
#  # timeout = 2
EOF
  fi

  if [[ ! -f /etc/telegraf/telegraf.d/http_response.conf ]]; then
    cat <<EOF >> /etc/telegraf/telegraf.d/http_response.conf
## HTTP/HTTPS request given an address a method and a timeout
#[[inputs.http_response]]
#  ## List of urls to query.
#  urls = ["https://www.baidu.com"]
#
#  ## Set http_proxy (telegraf uses the system wide proxy settings if it's is not set)
#  # http_proxy = "http://localhost:8888"
#
#  ## Set response_timeout (default 5 seconds)
#  # response_timeout = "5s"
#
#  ## HTTP Request Method
#  # method = "GET"
#
#  ## Whether to follow redirects from the server (defaults to false)
#  # follow_redirects = false
#
#  ## Optional HTTP Basic Auth Credentials
#  # username = "username"
#  # password = "password"
#
#  # response_body_max_size = "32MiB"
#
#  ## Optional substring or regex match in body of the response (case sensitive)
#  # response_string_match = "ok"
#
#  ## Expected response status code.
#  ## The status code of the response is compared to this value. If they match, the field
#  ## "response_status_code_match" will be 1, otherwise it will be 0. If the
#  ## expected status code is 0, the check is disabled and the field won't be added.
#  response_status_code = 200
EOF
  fi
fi

test -d $LOG_DIR || mkdir -p $LOG_DIR
chown -R -L telegraf:telegraf $LOG_DIR
chmod 755 $LOG_DIR

# add discover cron task
if [[ -d /etc/cron.d ]] && [[ -d $LOG_DIR ]]; then
    cat <<EOF > /etc/cron.d/telegraf
PATH=/bin:/usr/bin:/sbin:/usr/sbin:/usr/local/sbin:/usr/local/bin
* * * * * root telegraf-discover --verbose --update >>$LOG_DIR/telegraf-discover.log
EOF
fi

if [[ "$(readlink /proc/1/exe)" == */systemd ]]; then
	install_systemd /lib/systemd/system/telegraf.service
	deb-systemd-invoke restart telegraf.service || echo "WARNING: systemd not running."
else
	# Assuming SysVinit
	install_init
	# Run update-rc.d or fallback to chkconfig if not available
	if which update-rc.d &>/dev/null; then
		install_update_rcd
	else
		install_chkconfig
	fi
	invoke-rc.d telegraf restart
fi
