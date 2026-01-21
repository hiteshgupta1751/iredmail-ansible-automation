#!/bin/bash

# Define the domain and hostname
DOMAIN="hitesh.site"
HOSTNAME="$HOSTNAME"        

# Update and upgrade the system
apt update -y

# Set the hostname and update /etc/hosts
hostnamectl set-hostname $HOSTNAME
echo "127.0.0.1 $HOSTNAME localhost" >> /etc/hosts

# Verify hostname
hostname -f

# Install required packages for iRedMail installer
apt-get install -y gzip dialog

# Download iRedMail
wget https://github.com/iredmail/iRedMail/archive/refs/tags/1.7.4.tar.gz

# Move and extract iRedMail
mv 1.7.4.tar.gz /root/
cd /root/
tar zxf 1.7.4.tar.gz
cd iRedMail-1.7.4/

# Create the configuration file with required settings
cat <<EOL > config
export STORAGE_BASE_DIR='/var/vmail'
export DISABLE_WEB_SERVER='YES'
export WEB_SERVER=''
export BACKEND_ORIG='MARIADB'
export BACKEND='MYSQL'
export VMAIL_DB_BIND_PASSWD='sjdvboajbsnclnaslcnkasnco'
export VMAIL_DB_ADMIN_PASSWD='4wTZdJxASL4dx0K1GL3EBuiahbsvhibca'
export MLMMJADMIN_API_AUTH_TOKEN='MkIfeUtMNTRLnFeaho9vyfcbajbswRb'
export NETDATA_DB_PASSWD='dbOyuPSFrrHn9hj04dvHeb3JPoyg7tjg'
export MYSQL_ROOT_PASSWD='isbcabjsdxcansko'
export FIRST_DOMAIN='$DOMAIN'
export DOMAIN_ADMIN_PASSWD_PLAIN='isbcabjsdxcansko'
export USE_FAIL2BAN='YES'
export AMAVISD_DB_PASSWD='YblgX9qwyhqmpQBknDlKBvUDwJHkQsdvdv'
export IREDADMIN_DB_PASSWD='uI2cwOkjfpvHLE608ZdBIZ61HzscvasdvZ'
export RCM_DB_PASSWD='8E9qXaT6THlbGdKzdxvadbOodZlGo07'
export SOGO_DB_PASSWD='ejJTQE0Idqxcabshcbak62ALamGiGbew'
export SOGO_SIEVE_MASTER_PASSWD='MAlgcviacehyci5GcwKlEbhqPleY0KO8IPYq'
export IREDAPD_DB_PASSWD='jWxtvyVAdEdpXrGcasihbckCiY1kLe94aL'
export FAIL2BAN_DB_PASSWD='mW4d8lRB2oUyskbajsdbcabvJ4l99L7E'
#EOF
EOL

# Set environment variables for unattended installation
export AUTO_USE_EXISTING_CONFIG_FILE=y
export AUTO_INSTALL_WITHOUT_CONFIRM=y
export AUTO_CLEANUP_REMOVE_SENDMAIL=y
export AUTO_CLEANUP_REPLACE_FIREWALL_RULES=n
export AUTO_CLEANUP_RESTART_FIREWALL=n
export AUTO_CLEANUP_REPLACE_MYSQL_CONFIG=y

# Run the iRedMail installer with Enter key presses piped in
yes "" | bash iRedMail.sh

# Mariadb password and postmaster users
# mariadb password: isbcabjsdxcansko
# postmaster@$DOMAIN password: isbcabjsdxcansko

# Install Certbot
apt install certbot python-is-python3 -y

# Get the certificate
certbot certonly --standalone --agree-tos --non-interactive --register-unsafely-without-email -d $HOSTNAME

# Set permissions for Let's Encrypt directories
chmod 0755 /etc/letsencrypt/{live,archive}
mv /etc/ssl/certs/iRedMail.crt{,.bak}
mv /etc/ssl/private/iRedMail.key{,.bak}
rm -f /etc/ssl/certs/iRedMail.crt
rm -f /etc/ssl/private/iRedMail.key
# Symlink the fetched certificate
ln -s /etc/letsencrypt/live/$HOSTNAME/fullchain.pem /etc/ssl/certs/iRedMail.crt
ln -s /etc/letsencrypt/live/$HOSTNAME/privkey.pem /etc/ssl/private/iRedMail.key

# Restart Postfix and Dovecot to apply the new certificates
systemctl restart postfix dovecot

# Create a cronjob to renew the certificate and restart services
(crontab -l ; echo "1 3 * * * certbot certificates; certbot renew --post-hook 'ln -sf /etc/letsencrypt/live/$HOSTNAME/privkey.pem /etc/ssl/private/key.pem; /usr/sbin/systemctl restart postfix dovecot'") | crontab -

# Post processing the server
# Commenting out not required stuff in Postfix configuration
sed -i.bak '/^content_filter = smtp-amavis:\[127.0.0.1\]:10024/s/^/# /' /etc/postfix/main.cf
sed -i.bak '/^receive_override_options = no_address_mappings/s/^/# /' /etc/postfix/main.cf
sed -i.bak '/^[[:space:]]*-o content_filter=smtp-amavis:\[127.0.0.1\]:10026/s/^/# /' /etc/postfix/master.cf
sed -i.bak '/^[[:space:]]*MLMMJ_DEFAULT_PROFILE_SETTINGS.update({'"'"'smtp_port'"'"': 10027})/s/^/# /' /opt/mlmmjadmin/settings.py
sed -i \
    -e '/^[[:space:]]*postscreen_greet_action = drop/s/^/# /' \
    -e '/^[[:space:]]*postscreen_blacklist_action = drop/s/^/# /' \
    -e '/^[[:space:]]*postscreen_dnsbl_action = drop/s/^/# /' \
    -e '/^[[:space:]]*postscreen_dnsbl_threshold = 2/s/^/# /' \
    -e '/^[[:space:]]*postscreen_dnsbl_sites =/s/^/# /' \
    -e '/^[[:space:]]*    zen.spamhaus.org=127.0.0.\[2..11\]\*3/s/^/# /' \
    -e '/^[[:space:]]*    b.barracudacentral.org=127.0.0.2\*2/s/^/# /' \
    -e '/^[[:space:]]*postscreen_dnsbl_reply_map = texthash:\/etc\/postfix\/postscreen_dnsbl_reply/s/^/# /' \
    -e '/^[[:space:]]*postscreen_access_list = permit_mynetworks cidr:\/etc\/postfix\/postscreen_access.cidr/s/^/# /' \
    -e '/^[[:space:]]*postscreen_dnsbl_whitelist_threshold = -2/s/^/# /' \
    /etc/postfix/main.cf

# Adding required settings in Postfix configuration
sudo bash -c 'echo "relayhost =" >> /etc/postfix/main.cf'
sudo bash -c 'echo "smtp_sender_dependent_authentication = no" >> /etc/postfix/main.cf'
sudo bash -c 'echo "smtp_sasl_password_maps = hash:/etc/postfix/sasl_password" >> /etc/postfix/main.cf'
sudo bash -c 'echo "smtp_sasl_auth_enable = yes" >> /etc/postfix/main.cf'
sudo bash -c 'echo "smtp_sasl_mechanism_filter = plain" >> /etc/postfix/main.cf'
sudo bash -c 'echo "smtp_sasl_security_options = noanonymous" >> /etc/postfix/main.cf'
sudo bash -c 'echo "smtpd_relay_before_recipient_restrictions = yes" >> /etc/postfix/main.cf'

# Create and hash the Postfix SASL password file
touch /etc/postfix/sasl_password
postmap /etc/postfix/sasl_password


# Increase limits and system parameters
echo "Configuring system parameters..."
cat <<EOF >> /etc/sysctl.conf
fs.inotify.max_user_instances=90240
fs.file-max = 1000000
net.ipv4.tcp_max_syn_backlog = 8192
net.core.somaxconn = 65535
net.ipv4.tcp_fin_timeout = 30
net.ipv4.tcp_keepalive_time = 1200
vm.dirty_background_ratio = 5
vm.dirty_ratio = 10
fs.inotify.max_user_watches = 524288
EOF
sysctl -p

cat <<EOF >> /etc/security/limits.conf
*               soft    nofile          1000000
*               hard    nofile          1000000
dovecot         soft    nofile          1000000
dovecot         hard    nofile          1000000
EOF

#####Dovecot Configuration Added
# Backup existing dovecot.conf file
cp /etc/dovecot/dovecot.conf /etc/dovecot/dovecot.conf.bak

# Replace dovecot.conf with new configuration
cat << 'EOF' > /etc/dovecot/dovecot.conf
# More details about Dovecot settings: https://doc.dovecot.org

# Listen addresses.
#   - '*' means all available IPv4 addresses.
#   - '[::]' means all available IPv6 addresses.
# Listen on all available addresses by default
listen = * [::]

#base_dir = /var/run/dovecot
mail_plugins = quota mailbox_alias acl mail_log notify

# Enabled mail protocols.
protocols = pop3 imap sieve lmtp

# User/group who owns the message files:
mail_uid = 2000
mail_gid = 2000

# Assign uid to virtual users.
first_valid_uid = 2000
last_valid_uid = 2000

# Logging. Reference: http://wiki2.dovecot.org/Logging
#
# Use syslog
syslog_facility = local5

# Debug
#mail_debug = yes
#auth_verbose = yes
#auth_debug = yes
#auth_debug_passwords = yes

# Possible values: no, yes, plain, sha1.
# Set to 'yes' or 'plain', to output plaintext password (NOT RECOMMENDED).
#auth_verbose_passwords = no

# SSL: Global settings.
# Refer to wiki site for per protocol, ip, server name SSL settings:
# http://wiki2.dovecot.org/SSL/DovecotConfiguration
ssl_min_protocol = TLSv1.2
ssl = required
verbose_ssl = no
#ssl_ca = </path/to/ca
ssl_cert = </etc/ssl/certs/iRedMail.crt
ssl_key = </etc/ssl/private/iRedMail.key
ssl_dh = </etc/ssl/dh2048_param.pem

# Fix 'The Logjam Attack'
ssl_cipher_list = EECDH+CHACHA20:EECDH+AESGCM:EDH+AESGCM:AES256+EECDH
ssl_prefer_server_ciphers = yes

# With disable_plaintext_auth=yes AND ssl=required, STARTTLS is mandatory.
# Set disable_plaintext_auth=no AND ssl=yes to allow plain password transmitted
# insecurely.
disable_plaintext_auth = yes

# Allow plain text password per IP address/net
#remote 192.168.0.0/24 {
#   disable_plaintext_auth = no
#}

# Mail location and mailbox format.
mail_location = maildir:%Lh/Maildir/:INDEX=%Lh/Maildir/

# Authentication related settings.
# Append this domain name if client gives empty realm.
#auth_default_realm = email.joinlucidgrowth.com

# Authentication mechanisms.
auth_mechanisms = PLAIN LOGIN

# Limits the number of users that can be logging in at the same time.
# Default is 100. This can be overridden by `process_limit =` in
# `service [protocol]` block.
# e.g.
#       protocol imap-login {
#           ...
#           process_limit = 500
#       }
#default_process_limit = 100

# Login log elements.
# Add '%k' for detailed SSL protocol and cipher information.
# e.g. "TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits)"
login_log_format_elements = user=<%u> method=%m rip=%r lip=%l mpid=%e %c %k session=<%{session}>

# Mail delivery log format
deliver_log_format = from=%{from}, envelope_sender=%{from_envelope}, subject=%{subject}, msgid=%m, size=%{size}, delivery_time=%{delivery_time}ms, %$

service auth {
    client_limit = 50400
    unix_listener /var/spool/postfix/private/dovecot-auth {
        user = postfix
        group = postfix
        mode = 0666
    }
    unix_listener auth-master {
        user = vmail
        group = vmail
        mode = 0666
    }
    unix_listener auth-userdb {
        user = vmail
        group = vmail
        mode = 0660
    }
}

service anvil {
  client_limit = 50000
}
service imap {
  process_limit = 50000
}

# LMTP server (Local Mail Transfer Protocol).
# Reference: http://wiki2.dovecot.org/LMTP
service lmtp {
    user = vmail

    # For higher volume sites, it may be desirable to increase the number of
    # active listener processes. A range of 5 to 20 is probably good for most
    # sites.
    process_min_avail = 5

    # Logging.
    executable = lmtp -L

    # Listening on socket file and TCP
    unix_listener /var/spool/postfix/private/dovecot-lmtp {
        user = postfix
        group = postfix
        mode = 0600
    }

    inet_listener lmtp {
        # Listen on localhost (ipv4)
        address = 127.0.0.1
        port = 24
    }
}

# Virtual mail accounts.
userdb {
    args = /etc/dovecot/dovecot-mysql.conf
    driver = sql
}
passdb {
    args = /etc/dovecot/dovecot-mysql.conf
    driver = sql
}

# Master user.
# Master users are able to log in as other users. It's also possible to
# directly log in as any user using a master password, although this isn't
# recommended.
# Reference: http://wiki2.dovecot.org/Authentication/MasterUsers
auth_master_user_separator = *
passdb {
    driver = passwd-file
    args = /etc/dovecot/dovecot-master-users
    master = yes
}

plugin {
    # Quota configuration.
    # Reference: http://wiki2.dovecot.org/Quota/Configuration
    quota = dict:user::proxy::quotadict

    # Set default quota rule if no quota returned from SQL/LDAP query.
    #quota_rule = *:storage=1G
    #quota_rule2 = *:messages=0
    #quota_rule3 = Trash:storage=1G
    #quota_rule4 = Junk:ignore

    # Quota warning.
    #
    # If user suddenly receives a huge mail and the quota jumps from
    # 85% to 95%, only the 95% script is executed.
    #
    # Only the command for the first exceeded limit is executed, so configure
    # the highest limit first.
    quota_warning = storage=100%% quota-warning 100 %u
    quota_warning2 = storage=95%% quota-warning 95 %u
    quota_warning3 = storage=90%% quota-warning 90 %u
    quota_warning4 = storage=85%% quota-warning 85 %u

    # allow user to become max 10% (or 50 MB) over quota
    quota_grace = 10%%
    #quota_grace = 50 M

    # Custom Quota Exceeded Message.
    # You can specify the message directly or read the message from a file.
    #quota_exceeded_message = Quota exceeded, please try again later.
    #quota_exceeded_message = </path/to/quota_exceeded_message.txt

    # Used by quota-status service.
    quota_status_success = DUNNO
    quota_status_nouser = DUNNO
    quota_status_overquota = "552 5.2.2 Mailbox is full"

    # ACL and share folder
    acl = vfile
    acl_shared_dict = proxy::acl

    # By default Dovecot doesn't allow using the IMAP "anyone" or
    # "authenticated" identifier, because it would be an easy way to spam
    # other users in the system. If you wish to allow it,
    #acl_anyone = allow

    # Pigeonhole managesieve service.
    # Reference: http://wiki2.dovecot.org/Pigeonhole/Sieve/Configuration
    # Per-user sieve settings.
    sieve_dir = ~/sieve
    sieve = ~/sieve/dovecot.sieve

    # Global sieve settings.
    sieve_global_dir = /var/vmail/sieve
    # Note: if user has personal sieve script, global sieve rules defined in
    #       sieve_default will be ignored. Please use sieve_before or
    #       sieve_after instead.
    #sieve_default =

    sieve_before = /var/vmail/sieve/dovecot.sieve
    #sieve_after =

    # The maximum number of redirect actions that can be performed during a
    # single script execution.
    # The meaning of 0 differs based on your version. For pigeonhole-0.3.0 and
    # beyond this means that redirect is prohibited. For older versions,
    # however, this means that the number of redirects is unlimited.
    sieve_max_redirects = 30

    # Use recipient as vacation message sender instead of null sender (<>).
    sieve_vacation_send_from_recipient = yes

    # Reference: http://wiki2.dovecot.org/Plugins/MailboxAlias
    mailbox_alias_old = Sent
    mailbox_alias_new = Sent Messages
    mailbox_alias_old2 = Sent
    mailbox_alias_new2 = Sent Items

    # Events to log. `autoexpunge` is included in `expunge`
    # Defined in https://github.com/dovecot/core/blob/master/src/plugins/mail-log/mail-log-plugin.c
    mail_log_events = delete undelete expunge copy mailbox_create mailbox_delete mailbox_rename
    mail_log_fields = uid box msgid size from subject flags

    # Track user last login
    last_login_dict = proxy::lastlogin
    last_login_key = last-login/%s/%u/%d
}

service stats {
    client_limit = 50000
    fifo_listener stats-mail {
        user = vmail
        mode = 0644
    }

    unix_listener stats-writer {
        user = vmail
        group = vmail
        mode = 0660
    }

    inet_listener {
        address = 127.0.0.1
        port = 24242
    }
}

service quota-warning {
    executable = script /usr/local/bin/dovecot-quota-warning.sh
    unix_listener quota-warning {
        user = vmail
        group = vmail
        mode = 0660
    }
}

service quota-status {
    # '-p <protocol>'. Currently only 'postfix' protocol is supported.
    executable = quota-status -p postfix
    client_limit = 1
    inet_listener {
        address = 127.0.0.1
        port = 12340
    }
}

service dict {
    unix_listener dict {
        mode = 0660
        user = vmail
        group = vmail
    }
}

dict {
    quotadict = mysql:/etc/dovecot/dovecot-used-quota.conf
    acl = mysql:/etc/dovecot/dovecot-share-folder.conf
    lastlogin = mysql:/etc/dovecot/dovecot-last-login.conf
}

protocol lda {
    mail_plugins = $mail_plugins sieve
    lda_mailbox_autocreate = yes
    lda_mailbox_autosubscribe = yes
}

protocol lmtp {
    # Plugins
    mail_plugins = $mail_plugins sieve

    # Address extension delivery
    lmtp_save_to_detail_mailbox = yes
    recipient_delimiter = +
}

protocol imap {
    mail_plugins = $mail_plugins imap_quota imap_acl last_login
    imap_client_workarounds = tb-extra-mailbox-sep
    imap_idle_notify_interval = 600s
    # Maximum number of IMAP connections allowed for a user from each IP address.
    # NOTE: The username is compared case-sensitively.
    # Default is 10.
    # Increase it to avoid issue like below:
    # "Maximum number of concurrent IMAP connections exceeded"
    mail_max_userip_connections = 50000
}

protocol pop3 {
    mail_plugins = $mail_plugins last_login
    pop3_client_workarounds = outlook-no-nuls oe-ns-eoh
    pop3_uidl_format = %08Xu%08Xv

    # Maximum number of IMAP connections allowed for a user from each IP address.
    # NOTE: The username is compared case-sensitively.
    # Default is 10.
    mail_max_userip_connections = 50000

    # POP3 logout format string:
    #  %i - total number of bytes read from client
    #  %o - total number of bytes sent to client
    #  %t - number of TOP commands
    #  %p - number of bytes sent to client as a result of TOP command
    #  %r - number of RETR commands
    #  %b - number of bytes sent to client as a result of RETR command
    #  %d - number of deleted messages
    #  %m - number of messages (before deletion)
    #  %s - mailbox size in bytes (before deletion)
    # Default format doesn't have 'in=%i, out=%o'.
    #pop3_logout_format = top=%t/%p, retr=%r/%b, del=%d/%m, size=%s, in=%i, out=%o
}

# Login processes. Refer to Dovecot wiki for more details:
# http://wiki2.dovecot.org/LoginProcess
service imap-login {
    #inet_listener imap {
    #    port = 143
    #}
    #inet_listener imaps {
    #    port = 993
    #    ssl = yes
    #}
    service_count = 0

    # To avoid startup latency for new client connections, set process_min_avail
    # to higher than zero. That many idling processes are always kept around
    # waiting for new connections.
    process_min_avail = 250

    # number of simultaneous IMAP connections
    process_limit = 50000

    # vsz_limit should be fine at its default 64MB value
    vsz_limit = 264M
}

service pop3-login {
    #inet_listener pop3 {
    #    port = 110
    #}
    #inet_listener pop3s {
    #    port = 995
    #    ssl = yes
    #}

    service_count = 1

    # number of simultaneous POP3 connections
    #process_limit = 500
}

service managesieve-login {
    inet_listener sieve {
        # Listen on localhost (ipv4)
        address = 127.0.0.1
        port = 4190
    }
}

namespace {
    type = private
    separator = /
    prefix =
    inbox = yes

    # Refer to document for more details about alias mailbox:
    # http://wiki2.dovecot.org/MailboxSettings
    #
    # Sent
    mailbox Sent {
        auto = subscribe
        special_use = \Sent
    }
    mailbox "Sent Messages" {
        auto = no
        special_use = \Sent
    }
    mailbox "Sent Items" {
        auto = no
        special_use = \Sent
    }

    mailbox Drafts {
        auto = subscribe
        special_use = \Drafts
    }

    # Trash
    mailbox Trash {
        auto = subscribe
        special_use = \Trash
    }

    mailbox "Deleted Messages" {
        auto = no
        special_use = \Trash
    }

    # Junk
    mailbox Junk {
        auto = subscribe
        special_use = \Junk
    }
    mailbox Spam {
        auto = no
        special_use = \Junk
    }
    mailbox "Junk E-mail" {
        auto = no
        special_use = \Junk
    }

    # Archive
    mailbox Archive {
        auto = no
        special_use = \Archive
    }
    mailbox Archives {
        auto = no
        special_use = \Archive
    }
}

namespace {
    type = shared
    separator = /
    prefix = Shared/%%u/
    location = maildir:%%Lh/Maildir/:INDEX=%%Lh/Maildir/Shared/%%Ld/%%Ln

    # this namespace should handle its own subscriptions or not.
    subscriptions = yes
    list = children
}

# Public mailboxes.
# Refer to Dovecot wiki page for more details:
# http://wiki2.dovecot.org/SharedMailboxes/Public
#namespace {
#    type = public
#    separator = /
#    prefix = Public/
#    location = maildir:/var/vmail/public:CONTROL=%Lh/Maildir/public:INDEXPVT=%Lh/Maildir/public
#
#    # Allow users to subscribe to the public folders.
#    subscriptions = yes
#}

mail_debug = no
auth_verbose = no
auth_debug = no
auth_debug_passwords = no
auth_worker_max_count = 10000
mail_fsync = optimized
mail_nfs_index = no
mail_nfs_storage = no
mmap_disable = no
mailbox_list_index = yes
auth_cache_ttl = 1 hour
auth_cache_negative_ttl = 2 mins

service auth-worker {
  process_limit = 50000
  vsz_limit = 512M
}

service stats {
  client_limit = 50000
  vsz_limit = 512M
  fifo_listener stats-mail {
    user = vmail
    mode = 0644
  }

  unix_listener stats-writer {
    user = vmail
    group = vmail
    mode = 0660
  }

#  inet_listener {
#    address = 127.0.0.1
#    port = 24242
#  }
}

!include_try /etc/dovecot/iredmail/*.conf
EOF

# Replace dovecot master file at /etc/dovecot/conf.d/10-master.conf
cat << 'EOF' > /etc/dovecot/conf.d/10-master.conf
default_process_limit = 100000
default_client_limit = 100000

# Default VSZ (virtual memory size) limit for service processes. This is mainly
# intended to catch and kill processes that leak memory before they eat up
# everything.
default_vsz_limit = 512M

# Login user is internally used by login processes. This is the most untrusted
# user in Dovecot system. It shouldn't have access to anything at all.
#default_login_user = dovenull

# Internal user is used by unprivileged processes. It should be separate from
# login user, so that login processes can't disturb other processes.
#default_internal_user = dovecot

service imap-login {
  inet_listener imap {
    #port = 143
  }
  inet_listener imaps {
    #port = 993
    #ssl = yes
  }

  # Number of connections to handle before starting a new process. Typically
  # the only useful values are 0 (unlimited) or 1. 1 is more secure, but 0
  # is faster. <doc/wiki/LoginProcess.txt>
  #service_count = 1

  # Number of processes to always keep waiting for more connections.
  #process_min_avail = 0

  # If you set service_count=0, you probably need to grow this.
  #vsz_limit = $default_vsz_limit
}

service pop3-login {
  inet_listener pop3 {
    #port = 110
  }
  inet_listener pop3s {
    #port = 995
    #ssl = yes
  }
}

service submission-login {
  inet_listener submission {
    #port = 587
  }
}

service lmtp {
  unix_listener lmtp {
    #mode = 0666
  }

  # Create inet listener only if you can't use the above UNIX socket
  #inet_listener lmtp {
    # Avoid making LMTP visible for the entire internet
    #address =
    #port =
  #}
}

service imap {
  # Most of the memory goes to mmap()ing files. You may need to increase this
  # limit if you have huge mailboxes.
  #vsz_limit = $default_vsz_limit

  # Max. number of IMAP processes (connections)
  process_limit = 50000
}

service pop3 {
  # Max. number of POP3 processes (connections)
  #process_limit = 1024
}

service submission {
  # Max. number of SMTP Submission processes (connections)
  #process_limit = 1024
}

service auth {
  # auth_socket_path points to this userdb socket by default. It's typically
  # used by dovecot-lda, doveadm, possibly imap process, etc. Users that have
  # full permissions to this socket are able to get a list of all usernames and
  # get the results of everyone's userdb lookups.
  #
  # The default 0666 mode allows anyone to connect to the socket, but the
  # userdb lookups will succeed only if the userdb returns an "uid" field that
  # matches the caller process's UID. Also if caller's uid or gid matches the
  # socket's uid or gid the lookup succeeds. Anything else causes a failure.
  #
  # To give the caller full permissions to lookup all users, set the mode to
  # something else than 0666 and Dovecot lets the kernel enforce the
  # permissions (e.g. 0777 allows everyone full permissions).
  unix_listener auth-userdb {
    #mode = 0666
    #user =
    #group =
  }

  # Postfix smtp-auth
  #unix_listener /var/spool/postfix/private/auth {
  #  mode = 0666
  #}

  # Auth process is run as this user.
  #user = $default_internal_user
}

service auth-worker {
  # Auth worker process is run as root by default, so that it can access
  # /etc/shadow. If this isn't necessary, the user should be changed to
  # $default_internal_user.
  #user = root
}

service dict {
  # If dict proxy is used, mail processes should have access to its socket.
  # For example: mode=0660, group=vmail and global mail_access_groups=vmail
  unix_listener dict {
    #mode = 0600
    #user =
    #group =
  }
}

service log {
  process_min_avail = 250
}

EOF

# Configure rsyslog
# Create a temporary file with the configuration
cat <<EOF > /tmp/rsyslog-config
\$OMFileIOBufferSize 256k
\$OMFileAsyncWriting on
\$OMFileFlushOnTXEnd off
\$OMFileFlushInterval 1
EOF

# Prepend the temporary file content to the target file
cat /tmp/rsyslog-config | cat - /etc/rsyslog.d/1-iredmail-dovecot.conf > /tmp/rsyslog-dovecot.conf && mv /tmp/rsyslog-dovecot.conf /etc/rsyslog.d/1-iredmail-dovecot.conf

# Clean up
rm /tmp/rsyslog-config

echo "Configuration added to the top of /etc/rsyslog.d/1-iredmail-dovecot.conf"

#
echo "Configuring MariaDB..."
cat <<EOF >> /etc/mysql/my.cnf

max_connections = 50000
max_user_connections = 5000
thread_cache_size = 3000
open_files_limit = 65535
table_open_cache = 4000
innodb_buffer_pool_size = 10G
innodb_flush_log_at_trx_commit = 2
innodb_flush_method = O_DIRECT
query_cache_type = 1
query_cache_size = 128M
query_cache_limit = 70M
innodb_log_file_size = 512M
innodb_log_buffer_size = 106M
innodb_read_io_threads = 80
innodb_write_io_threads = 80
innodb_io_capacity = 500
wait_timeout = 600
interactive_timeout = 600
net_read_timeout = 30
net_write_timeout = 60
tmp_table_size = 128M
max_heap_table_size = 64M
EOF

#run the command

echo "Creating directory /etc/ssl/private if it doesn't exist..."
sudo mkdir -p /etc/ssl/private

# Step 2: Download the ffdhe4096 parameters
echo "Downloading ffdhe4096 parameters..."
sudo curl https://raw.githubusercontent.com/internetstandards/dhe_groups/master/ffdhe4096.pem -o /etc/ssl/private/ffdhe4096.pem

# Step 3: Verify the checksum
echo "Verifying the checksum..."
echo "64852d6890ff9e62eecd1ee89c72af9af244dfef5b853bcedea3dfd7aade22b3 /etc/ssl/private/ffdhe4096.pem" | sudo sha256sum -c

# Step 4: Set the correct permissions
echo "Setting permissions for ffdhe4096.pem..."
sudo chmod 644 /etc/ssl/private/ffdhe4096.pem

# Step 5: Verify the file contents (optional)
echo "Verifying the file contents (optional)..."
sudo head -n 5 /etc/ssl/private/ffdhe4096.pem

# Configure Postfix
echo "Configuring Postfix..."
sudo postconf -e 'smtpd_tls_dh1024_param_file = /etc/ssl/private/ffdhe4096.pem'
sudo postconf -e 'compatibility_level=3.6'
sudo postconf -e 'smtpd_client_connection_count_limit=100'
sudo postconf -e 'default_process_limit = 2000'
sudo postconf -e 'smtp_destination_concurrency_limit = 50'
sudo postconf -e 'smtp_destination_recipient_limit = 2000'

#disable grelisting for all domains
python3 /opt/iredapd/tools/greylisting_admin.py --disable --from '@.'

# Comment out the specified lines in main.cf
sudo sed -i.bak '/^smtpd_tls_dh512_param_file =/s/^/#/' /etc/postfix/main.cf
sudo sed -i.bak '/^smtpd_tls_dh1024_param_file =/s/^/#/' /etc/postfix/main.cf

# Add the new lines to main.cf
cat <<EOF | sudo tee -a /etc/postfix/main.cf > /dev/null

# Set cipher preferences
smtpd_tls_ciphers = high
smtp_tls_ciphers = high
smtpd_tls_mandatory_ciphers = high
smtp_tls_mandatory_ciphers = high

# Exclude weak ciphers
smtpd_tls_exclude_ciphers = aNULL, LOW, EXP, MEDIUM, ADH, AECDH, MD5, DSS, ECDSA, CAMELLIA128, 3DES, DES, RC4, PSK, SRP, kRSA, SHA1
smtp_tls_exclude_ciphers = aNULL, LOW, EXP, MEDIUM, ADH, AECDH, MD5, DSS, ECDSA, CAMELLIA128, 3DES, DES, RC4, PSK, SRP, kRSA, SHA1

# Prefer server's cipher order
tls_preempt_cipherlist = yes

# Use strong curves
smtpd_tls_eecdh_grade = ultra
EOF

echo "Reloading and restarting Postfix..."
sudo postfix reload

echo "Script execution completed."

# Restart services
echo "Restarting services..."
systemctl restart postfix dovecot iredapd
systemctl disable --now fail2ban

#cronjob for fail2ban

(crontab -l ; echo "* * * * * /bin/bash -c 'fail2ban-client status postfix | grep -oP \"\d{1,3}(\.\d{1,3}){3}\" | while read -r ip; do fail2ban-client set postfix unbanip \"$ip\"; done && rm -f /tmp/banned_ips.txt' > /dev/null 2>&1") | crontab -

# Disable and remove unnecessary services
echo "Disabling and removing unnecessary services..."
systemctl disable --now clamav-daemon
apt remove clamav-base -y
systemctl disable --now amavis
systemctl mask clamav-daemon clamav-freshclam
systemctl mask amavisd amavis

echo "Setup completed successfully."
