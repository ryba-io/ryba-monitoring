module.exports = 'servers': 
  "master1.ryba":
    connection:
      private_key: '''
        -----BEGIN RSA PRIVATE KEY-----
        MIIEogIBAAKCAQEArBDFt50aN9jfIJ629pRGIMA1fCMb9RyTHt9A+jx3FOsIOtJs
        eaBIpv98drbFVURr+cUs/CrgGVk5k2NIeiz0bG4ONV5nTwx38z5CzqLb7UryZS3i
        a/TS14fWOxvWTRR27R71ePX90G/ZIReKFeTrucw9y9Pl+xAzsmeblRwLBxv/SWBX
        Uai2mHAZaejlG9dGkn9f2n+oPmbgk6krLMCjLhlNBnkdroBNSXGA9ewLPFF4y54Q
        kBqmG3eLzCqAKAzwyJ5PpybtNGAWfN81gY/P5LBzC66WdtEzpwsYAv1wCioqggtg
        xVZN2s0ajxQrCxahRkXstBI2IDcm2qUTxaDbUwIDAQABAoIBAFruOi7AvXxKBhCt
        D6/bx/vC2AEUZM/yG+Wywhn8HkpVsvGzBlR4Wiy208XA7SQUlqNWimFxHyEGQCEd
        1M2MOFedCbE2hI4H3tQTUSb2dhc/Bj5mM0QuC8aPKK3wFh6B9B93vu3/wfSHR03v
        rK/JXLHBt96hyuYVN9zOWDBCs6k7SdQ2BcsQLiPg6feTsZelJDuO+DO65kKLMiz3
        mNPThErklRaKovNk47LSYakk6gsJXrpG6JWQ6nwsRenwplDwZ8Zs9mlRi7f3nChM
        3I1WlISN8y2kcQBQ94YZKk8wzH/lzmxsabcLa5ETNubxQ6ThDu1oYUIIUsQyNPm+
        DkW0VwECgYEA5MttelspKexWS39Y3sQYvZ/v8VZBQl4tRbpUWWc+PNEtcEwOBza/
        H4jBWYd2eWKTApJT1st58E4b34Mv88nQVElLb3sE7uJMkihPyNpABGbCvr63hDYw
        PyL53nKaPelY/aDnL0F8LmREfdKw/uy6+UChgkPfdo2VVk1oyvsZaRMCgYEAwIZ+
        lCmeXQ4mU6uxO+ChhDn7zw9rR5qlCyfJiLPe2lV20vaHV5ZfKIWGegsVJSpFr2ST
        5ghh+FVIneoNRtTHEKwNWCK7I6qeF+WAaci+KsLQigJQHsw58n9cdA7wHHc475n/
        pf7efoPcvk6qYOS2mpDgC87m+o3C4Dyspqp9TMECgYA4/ed+dBjT5Zg1ZDp5+zUC
        f0Wgw1CsPJNgbCK4xnv9YEnGUFuqNlvzefhX2eOMJx7hpBuYRMVSM9LDoYUfYCUx
        6bQNyAIZk2tpePsu2BbcQdC+/PjvySPJhmfhnoCHbYoKW7tazSAm2jkpcoM+bS/C
        CPRyY3/Voz0Q62VwMo5I2wKBgB4mMbZUGieqapgZwASHdeO2DNftKzioYAYyMd5F
        hLWeQqBg2Or/cmFvH5MHH0WVrBn+Xybb0zPHbzrDh1a7RX035FMUBUhdlKpbV1O5
        iwY5Qd0K5a8c/koaZckK+dELXpAvBpjhI8ieL7hhq07HIk1sOJnAye0cvBLPjZ3/
        /uVBAoGAVAs6tFpS0pFlxmg4tfGEm7/aP6FhyBHNhv2QGluw8vv/XVMzUItxGIef
        HcSMWBm08IJMRJLgmoo1cuQv6hBui7JpDeZk/20qoF2oZW9lJ9fdRObJqi61wufP
        BNiriqexq/eTy2uF9RCCjLItWxUscVMlVt4V65HLkCF5WxCQw+o=
        -----END RSA PRIVATE KEY-----
      '''
      public_key: "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCsEMW3nRo32N8gnrb2lEYgwDV8Ixv1HJMe30D6PHcU6wg60mx5oEim/3x2tsVVRGv5xSz8KuAZWTmTY0h6LPRsbg41XmdPDHfzPkLOotvtSvJlLeJr9NLXh9Y7G9ZNFHbtHvV49f3Qb9khF4oV5Ou5zD3L0+X7EDOyZ5uVHAsHG/9JYFdRqLaYcBlp6OUb10aSf1/af6g+ZuCTqSsswKMuGU0GeR2ugE1JcYD17As8UXjLnhCQGqYbd4vMKoAoDPDInk+nJu00YBZ83zWBj8/ksHMLrpZ20TOnCxgC/XAKKiqCC2DFVk3azRqPFCsLFqFGRey0EjYgNybapRPFoNtT Ryba Hadoop"
      bootstrap:
        username: "vagrant"
        password: "vagrant"
        host: "10.10.10.11"
        port: 22
        cmd: "su -"
        retry: 3
      username: "root"
      host: "10.10.10.11"
      port: 22
      private_key_location: "~/.ssh/id_rsa"
      retry: 3
      end: true
      wait: 1000
    mecano:
      cache_dir: "/home/pierrotws/workspace/ryba-cluster/conf/../resources/cache"
      log_serializer: true
    log:
      archive: true
      disabled: false
      basedir: "./log"
      fqdn_reversed: "ryba.master1"
      filename: "master1.log"
      elasticsearch:
        enable: false
        url: "http://localhost:9200"
        index: "masson"
    security:
      selinux: false
      limits: {}
    network:
      hosts_auto: true
      hosts:
        "127.0.0.1": "localhost localhost.localdomain localhost4 localhost4.localdomain4"
        "10.10.10.10": "repos.ryba ryba"
      resolv: '''
        search ryba
        nameserver 10.10.10.13
        nameserver 10.0.2.3
      '''
      hostname_disabled: false
    iptables:
      action: "stop"
      startup: false
      log: true
      rules: []
      log_prefix: "IPTables-Dropped: "
      log_level: 4
      log_rules: [
        {
          chain: "INPUT"
          command: "-A"
          jump: "LOGGING"
        }
        {
          chain: "LOGGING"
          command: "-A"
          "--limit": "2/min"
          jump: "LOG"
          "log-prefix": "IPTables-Dropped: "
          "log-level": 4
        }
        {
          chain: "LOGGING"
          command: "-A"
          jump: "DROP"
        }
      ]
    bind_server:
      zones: [
        "/home/pierrotws/workspace/ryba-cluster/conf/zones/ryba"
        "/home/pierrotws/workspace/ryba-cluster/conf/zones/10.10.10.in-addr.arpa"
      ]
      user:
        uid: 802
        gid: 802
      group:
        gid: 802
    ssh:
      banner:
        destination: "/etc/banner"
        content: "Welcome to Hadoop!"
      sshd_config:
        PermitRootLogin: "without-password"
    users:
      root:
        authorized_keys: [
          "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCWvEjSt2sAvRmkpkt9+u1EXuFDWJSuI1C8G/+NMcpMRDSUTary3Njqt/DC5mx7X36mVJdaq2KqgAVa28zzeuN6Yv7iuxCTw/4K7OKXYu+q0UG8BlIknWgLa8s7Nx2J69Prkb4oFgzw5IqK9EM6VMarUJUCXVNhb3zmamrF59OIxAIyQhV5i5SzoAxLIcD9EtxS/ZRf9t9fOBEhn42SVcpEWO09bUHZ11J2tw/Pwsxk+va83cH9qipVsEwIMDUCosfzV1G2zF5HhU/mhIHWRdAULpaRfd3IgNqTtI6BBi6FOFbJdrkHXPXKRybZwCxChncq1TZI2SXx6BCRpoJ/s887 m.sauvage.pierre@gmail.com"
        ]
        name: "root"
        home: "/root"
    yum:
      packages:
        tree: true
        git: true
        htop: true
        vim: true
        "yum-plugin-priorities": true
        man: true
        ksh: true
      config:
        proxy: null
        main:
          keepcache: "0"
          proxy: null
          proxy_username: null
          proxy_password: null
      copy: "/home/pierrotws/workspace/ryba-cluster/conf/user/offline/*.repo"
      clean: false
      merge: true
      update: true
      proxy: true
      epel: true
      epel_url: "http://download.fedoraproject.org/pub/epel/6/i386/epel-release-6-8.noarch.rpm"
    mysql:
      server:
        current_password: ""
        password: "test123"
        my_cnf:
          mysqld:
            innodb_file_per_table: "1"
    openldap_server:
      suffix: "dc=ryba"
      root_dn: "cn=Manager,dc=ryba"
      root_password: "test"
      config_dn: "cn=admin,cn=config"
      config_password: "test"
      users_dn: "ou=users,dc=ryba"
      groups_dn: "ou=groups,dc=ryba"
      ldapdelete: []
      ldapadd: []
      tls: true
      tls_ca_cert_file: "/home/pierrotws/workspace/ryba-cluster/conf/certs/cacert.pem"
      tls_cert_file: "/home/pierrotws/workspace/ryba-cluster/conf/certs/master3_cert.pem"
      tls_key_file: "/home/pierrotws/workspace/ryba-cluster/conf/certs/master3_key.pem"
      proxy_user:
        uidNumber: 801
        gidNumber: 801
      proxy_group:
        gidNumber: 801
    openldap_client:
      certificates: [
        "/home/pierrotws/workspace/ryba-cluster/conf/certs/master3_cert.pem"
      ]
      config:
        BASE: "dc=ryba"
        URI: "ldaps://master3.ryba"
        TLS_CACERTDIR: "/etc/openldap/cacerts"
        TLS_REQCERT: "allow"
        TIMELIMIT: "15"
        TIMEOUT: "20"
      suffix: "dc=ryba"
      root_dn: "cn=Manager,dc=ryba"
      root_password: "test"
    openldap_server_krb5:
      manager_dn: "cn=Manager,dc=ryba"
      manager_password: "test"
      krbadmin_user:
        mail: "david@adaltas.com"
        userPassword: "test"
        uidNumber: 800
        gidNumber: 800
      krbadmin_group:
        gidNumber: 800
    krb5:
      etc_krb5_conf:
        logging:
          default: "SYSLOG:INFO:LOCAL1"
          kdc: "SYSLOG:NOTICE:LOCAL1"
          admin_server: "SYSLOG:WARNING:LOCAL1"
        libdefaults:
          dns_lookup_realm: false
          dns_lookup_kdc: false
          ticket_lifetime: "24h"
          renew_lifetime: "7d"
          forwardable: true
          allow_weak_crypto: "false"
          clockskew: "300"
          rdns: "false"
          default_realm: "HADOOP.RYBA"
        realms:
          "USERS.RYBA":
            kadmin_principal: "wdavidw/admin@USERS.RYBA"
            kadmin_password: "test"
            principals: [
              {
                principal: "krbtgt/HADOOP.RYBA@USERS.RYBA"
                password: "test"
              }
            ]
            kdc: [
              "master3.ryba"
            ]
            admin_server: "master3.ryba"
            default_domain: "users.ryba"
          "HADOOP.RYBA":
            kadmin_principal: "wdavidw/admin@HADOOP.RYBA"
            kadmin_password: "test"
            principals: [
              {
                principal: "krbtgt/HADOOP.RYBA@USERS.RYBA"
                password: "test"
              }
            ]
            kdc: [
              "master1.ryba"
            ]
            admin_server: "master1.ryba"
            default_domain: "hadoop.ryba"
        domain_realm:
          ryba: "HADOOP.RYBA"
        appdefaults:
          pam:
            debug: false
            ticket_lifetime: 36000
            renew_lifetime: 36000
            forwardable: true
            krb4_convert: false
        dbmodules: {}
      kdc_conf:
        realms:
          "HADOOP.RYBA":
            max_life: "10h 0m 0s"
            max_renewable_life: "7d 0h 0m 0s"
            master_key_type: "aes256-cts-hmac-sha1-96"
            default_principal_flags: "+preauth"
            acl_file: "/var/kerberos/krb5kdc/kadm5.acl"
            dict_file: "/usr/share/dict/words"
            admin_keytab: "/var/kerberos/krb5kdc/kadm5.keytab"
            supported_enctypes: "aes256-cts-hmac-sha1-96:normal aes128-cts-hmac-sha1-96:normal des3-hmac-sha1:normal arcfour-hmac-md5:normal"
            database_module: "openldap_master3"
            principals: []
        dbmodules:
          openldap_master3:
            db_library: "kldap"
            ldap_kerberos_container_dn: "ou=kerberos,dc=ryba"
            ldap_kdc_dn: "cn=krbadmin,ou=users,dc=ryba"
            ldap_kdc_password: "test"
            ldap_kadmind_dn: "cn=krbadmin,ou=users,dc=ryba"
            ldap_kadmind_password: "test"
            ldap_service_password_file: "/etc/krb5.d/openldap_master3.stash.keyfile"
            ldap_servers: "ldap://master3.ryba"
            ldap_conns_per_server: 5
            manager_dn: "cn=Manager,dc=ryba"
            manager_password: "test"
            kdc_master_key: "test"
        kdcdefaults:
          kdc_ports: "88"
          kdc_tcp_ports: "88"
        logging:
          kdc: "FILE:/var/log/kdc.log"
      sshd: {}
      kinit: "/usr/bin/kinit"
    sssd:
      force_check: false
      certificates: [
        "/home/pierrotws/workspace/ryba-cluster/conf/certs/cacert.pem"
      ]
      config:
        sssd:
          config_file_version: "2"
          reconnection_retries: "3"
          sbus_timeout: "30"
          services: "nss, pam"
          debug_level: "1"
          domains: "hadoop,users"
        nss:
          filter_groups: "root"
          filter_users: "root"
          reconnection_retries: "3"
          entry_cache_timeout: "300"
          entry_cache_nowait_percentage: "75"
          debug_level: "1"
        pam:
          reconnection_retries: "3"
          offline_credentials_expiration: "2"
          offline_failed_login_attempts: "3"
          offline_failed_login_delay: "5"
          debug_level: "1"
        "domain/hadoop":
          debug_level: "1"
          cache_credentials: "True"
          ldap_search_base: "ou=users,dc=ryba"
          ldap_group_search_base: "ou=groups,dc=ryba"
          id_provider: "ldap"
          auth_provider: "ldap"
          chpass_provider: "ldap"
          ldap_uri: "ldaps://master3.ryba:636"
          ldap_tls_cacertdir: "/etc/openldap/cacerts"
          ldap_default_bind_dn: "cn=Manager,dc=ryba"
          ldap_default_authtok: "test"
          ldap_id_use_start_tls: "True"
        "domain/users":
          debug_level: "1"
          cache_credentials: "True"
          ldap_search_base: "ou=users,dc=ryba"
          ldap_group_search_base: "ou=groups,dc=ryba"
          id_provider: "ldap"
          auth_provider: "ldap"
          chpass_provider: "ldap"
          ldap_uri: "ldaps://master3.ryba:636"
          ldap_tls_cacertdir: "/etc/openldap/cacerts"
          ldap_default_bind_dn: "cn=Manager,dc=ryba"
          ldap_default_authtok: "test"
          ldap_id_use_start_tls: "False"
      merge: false
      test_user: null
    java:
      java_home: "/usr/lib/jvm/java"
      jre_home: "/usr/lib/jvm/java/jre"
      proxy: null
      openjdk: true
    ryba:
      clean_logs: true
      force_check: false
      check_hdfs_fsck: false
      security: "kerberos"
      realm: "HADOOP.RYBA"
      nameservice: "torval"
      krb5_user:
        password: "test123"
        password_sync: true
        principal: "ryba@HADOOP.RYBA"
      ssl:
        cacert: "/home/pierrotws/workspace/ryba-cluster/conf/certs/cacert.pem"
        cert: "/home/pierrotws/workspace/ryba-cluster/conf/certs/master1_cert.pem"
        key: "/home/pierrotws/workspace/ryba-cluster/conf/certs/master1_key.pem"
      ambari:
        repo: "/home/pierrotws/workspace/ryba-cluster/conf/resources/repos/ambari-2.0.0.repo"
      ssh_fencing:
        private_key: "/home/pierrotws/workspace/ryba-cluster/conf/hdfs_keys/id_rsa"
        public_key: "/home/pierrotws/workspace/ryba-cluster/conf/hdfs_keys/id_rsa.pub"
      hadoop_opts: "-Djava.net.preferIPv4Stack=true -Dsun.security.krb5.debug=false"
      core_site:
        "hadoop.ssl.exclude.cipher.suites": "SSL_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA,SSL_RSA_EXPORT_WITH_DES40_CBC_SHA,SSL_RSA_EXPORT_WITH_RC4_40_MD5,TLS_DHE_RSA_WITH_AES_128_CBC_SHA,TLS_DHE_RSA_WITH_AES_256_CBC_SHA"
        "io.compression.codecs": "org.apache.hadoop.io.compress.GzipCodec,org.apache.hadoop.io.compress.DefaultCodec,org.apache.hadoop.io.compress.SnappyCodec"
        "fs.defaultFS": "hdfs://torval:8020"
        "hadoop.security.authentication": "kerberos"
        "hadoop.security.authorization": "true"
        "hadoop.rpc.protection": "authentication"
        "hadoop.security.group.mapping": "org.apache.hadoop.security.JniBasedUnixGroupsMappingWithFallback"
        "ha.zookeeper.quorum": [
          "master1.ryba:2181"
          "master2.ryba:2181"
          "master3.ryba:2181"
        ]
        "net.topology.script.file.name": "/etc/hadoop/conf/rack_topology.sh"
        "hadoop.http.filter.initializers": "org.apache.hadoop.security.AuthenticationFilterInitializer"
        "hadoop.http.authentication.type": "kerberos"
        "hadoop.http.authentication.token.validity": "36000"
        "hadoop.http.authentication.signature.secret.file": "/etc/hadoop/hadoop-http-auth-signature-secret"
        "hadoop.http.authentication.simple.anonymous.allowed": "false"
        "hadoop.http.authentication.kerberos.principal": "HTTP/_HOST@HADOOP.RYBA"
        "hadoop.http.authentication.kerberos.keytab": "/etc/security/keytabs/spnego.service.keytab"
        "hadoop.http.authentication.cookie.domain": "ryba"
        "hadoop.security.auth_to_local": '''
          
          RULE:[2:$1@$0]([rn]m@HADOOP\\.RYBA)s/.*/yarn/
          RULE:[2:$1@$0](jhs@HADOOP\\.RYBA)s/.*/mapred/
          RULE:[2:$1@$0]([nd]n@HADOOP\\.RYBA)s/.*/hdfs/
          RULE:[2:$1@$0](hm@HADOOP\\.RYBA)s/.*/hbase/
          RULE:[2:$1@$0](rs@HADOOP\\.RYBA)s/.*/hbase/
          RULE:[2:$1@$0](opentsdb@HADOOP\\.RYBA)s/.*/hbase/
          DEFAULT
          RULE:[1:$1](yarn|mapred|hdfs|hive|hbase|oozie)s/.*/nobody/
          RULE:[2:$1](yarn|mapred|hdfs|hive|hbase|oozie)s/.*/nobody/
          RULE:[1:$1]
          RULE:[2:$1]
          
        '''
        "hadoop.proxyuser.HTTP.hosts": "*"
        "hadoop.proxyuser.HTTP.groups": "*"
        "hadoop.ssl.require.client.cert": "false"
        "hadoop.ssl.hostname.verifier": "DEFAULT"
        "hadoop.ssl.keystores.factory.class": "org.apache.hadoop.security.ssl.FileBasedKeyStoresFactory"
        "hadoop.ssl.server.conf": "ssl-server.xml"
        "hadoop.ssl.client.conf": "ssl-client.xml"
        "ha.zookeeper.acl": "@/etc/hadoop-hdfs-zkfc/conf/zk-acl.txt"
        "ha.zookeeper.auth": "@/etc/hadoop-hdfs-zkfc/conf/zk-auth.txt"
        "hadoop.proxyuser.httpfs.hosts": "master1.ryba,master2.ryba,master3.ryba"
        "hadoop.proxyuser.httpfs.groups": "*"
        "hadoop.proxyuser.hbase.hosts": "*"
        "hadoop.proxyuser.hbase.groups": "*"
        "hadoop.proxyuser.hive.groups": "*"
        "hadoop.proxyuser.hive.hosts": "*"
        "hadoop.proxyuser.oozie.hosts": "master3.ryba"
        "hadoop.proxyuser.oozie.groups": "*"
        "hadoop.proxyuser.falcon.groups": "*"
        "hadoop.proxyuser.falcon.hosts": "front1.ryba"
        "hadoop.proxyuser.knox.hosts": "front1.ryba"
        "hadoop.proxyuser.knox.groups": "*"
      hadoop_metrics:
        "*.sink.file.class": "org.apache.hadoop.metrics2.sink.FileSink"
        sinks:
          file: true
          ganglia: false
          graphite: false
        config:
          "*.period": "60"
          "*.sink.file.class": "org.apache.hadoop.metrics2.sink.FileSink"
          "*.sink.file.filename": "metrics.out"
          "namenode.sink.file.filename": "namenode-metrics.out"
          "datanode.sink.file.filename": "datanode-metrics.out"
          "resourcemanager.sink.file.filename": "resourcemanager-metrics.out"
          "nodemanager.sink.file.filename": "nodemanager-metrics.out"
          "mrappmaster.sink.file.filename": "mrappmaster-metrics.out"
          "jobhistoryserver.sink.file.filename": "jobhistoryserver-metrics.out"
      hadoop_heap: "512"
      hadoop_namenode_init_heap: "-Xms512m"
      hdfs:
        user:
          limits:
            nproc: 16384
            nofile: 16384
          uid: 2401
          gid: "hdfs"
          name: "hdfs"
          system: true
          groups: "hadoop"
          comment: "Hadoop HDFS User"
          home: "/var/lib/hadoop-hdfs"
        krb5_user:
          password: "hdfs123"
          password_sync: true
          principal: "hdfs@HADOOP.RYBA"
        sysctl:
          "vm.swappiness": 0
          "vm.overcommit_memory": 1
          "vm.overcommit_ratio": 100
          "net.core.somaxconn": 1024
        site:
          "dfs.namenode.safemode.extension": 1000
          "dfs.replication": 2
          "dfs.namenode.name.dir": [
            "file:///var/hdfs/name"
          ]
          "dfs.journalnode.rpc-address": "0.0.0.0:8485"
          "dfs.journalnode.http-address": "0.0.0.0:8480"
          "dfs.journalnode.https-address": "0.0.0.0:8481"
          "dfs.http.policy": "HTTPS_ONLY"
          "dfs.journalnode.kerberos.internal.spnego.principal": "HTTP/_HOST@HADOOP.RYBA"
          "dfs.journalnode.kerberos.principal": "HTTP/_HOST@HADOOP.RYBA"
          "dfs.journalnode.keytab.file": "/etc/security/keytabs/spnego.service.keytab"
          "dfs.journalnode.edits.dir": "/var/hdfs/edits"
          "dfs.namenode.shared.edits.dir": "qjournal://master1.ryba:8485;master2.ryba:8485;master3.ryba:8485/torval"
          "dfs.namenode.kerberos.principal.pattern": "*"
          "dfs.namenode.kerberos.principal": "nn/_HOST@HADOOP.RYBA"
          "dfs.namenode.kerberos.internal.spnego.principal": "HTTP/_HOST@HADOOP.RYBA"
          "dfs.namenode.kerberos.https.principal": "HTTP/_HOST@HADOOP.RYBA"
          "dfs.web.authentication.kerberos.principal": "HTTP/_HOST@HADOOP.RYBA"
          "dfs.ha.automatic-failover.enabled": "true"
          "dfs.nameservices": "torval"
          "dfs.internal.nameservices": "torval"
          "dfs.ha.namenodes.torval": "master1,master2"
          "dfs.namenode.http-address": null
          "dfs.namenode.https-address": null
          "dfs.namenode.rpc-address.torval.master1": "master1.ryba:8020"
          "dfs.namenode.http-address.torval.master1": "master1.ryba:50070"
          "dfs.namenode.https-address.torval.master1": "master1.ryba:50470"
          "dfs.namenode.rpc-address.torval.master2": "master2.ryba:8020"
          "dfs.namenode.http-address.torval.master2": "master2.ryba:50070"
          "dfs.namenode.https-address.torval.master2": "master2.ryba:50470"
          "dfs.client.failover.proxy.provider.torval": "org.apache.hadoop.hdfs.server.namenode.ha.ConfiguredFailoverProxyProvider"
          "dfs.datanode.kerberos.principal": "dn/_HOST@HADOOP.RYBA"
          "dfs.client.read.shortcircuit": "true"
          "dfs.domain.socket.path": "/var/lib/hadoop-hdfs/dn_socket"
        group:
          gid: 2401
          name: "hdfs"
          system: true
        log_dir: "/var/log/hadoop-hdfs"
        pid_dir: "/var/run/hadoop-hdfs"
        secure_dn_pid_dir: "/var/run/hadoop-hdfs"
        secure_dn_user: "hdfs"
        nn:
          conf_dir: "/etc/hadoop-hdfs-namenode/conf"
          core_site: {}
          site:
            "dfs.http.policy": "HTTPS_ONLY"
            "dfs.namenode.name.dir": "file:///var/hdfs/name"
            "dfs.hosts": "/etc/hadoop-hdfs-namenode/conf/dfs.include"
            "dfs.hosts.exclude": "/etc/hadoop-hdfs-namenode/conf/dfs.exclude"
            "fs.permissions.umask-mode": "027"
            "dfs.block.access.token.enable": "true"
            "dfs.namenode.kerberos.principal": "nn/_HOST@HADOOP.RYBA"
            "dfs.namenode.keytab.file": "/etc/security/keytabs/nn.service.keytab"
            "dfs.namenode.kerberos.internal.spnego.principal": "HTTP/_HOST@HADOOP.RYBA"
            "dfs.namenode.kerberos.https.principal": "HTTP/_HOST@HADOOP.RYBA"
            "dfs.web.authentication.kerberos.principal": "HTTP/_HOST@HADOOP.RYBA"
            "dfs.web.authentication.kerberos.keytab": "/etc/security/keytabs/spnego.service.keytab"
            "dfs.https.namenode.https-address": null
            "dfs.namenode.acls.enabled": "true"
            "dfs.namenode.accesstime.precision": null
            "dfs.journalnode.kerberos.principal": "HTTP/_HOST@HADOOP.RYBA"
            "dfs.nameservices": "torval"
            "dfs.internal.nameservices": "torval"
            "dfs.ha.namenodes.torval": "master1,master2"
            "dfs.namenode.http-address": null
            "dfs.namenode.https-address": null
            "dfs.namenode.rpc-address.torval.master1": "master1.ryba:8020"
            "dfs.namenode.http-address.torval.master1": "master1.ryba:50070"
            "dfs.namenode.https-address.torval.master1": "master1.ryba:50470"
            "dfs.namenode.rpc-address.torval.master2": "master2.ryba:8020"
            "dfs.namenode.http-address.torval.master2": "master2.ryba:50070"
            "dfs.namenode.https-address.torval.master2": "master2.ryba:50470"
            "dfs.client.failover.proxy.provider.torval": "org.apache.hadoop.hdfs.server.namenode.ha.ConfiguredFailoverProxyProvider"
            "dfs.ha.automatic-failover.enabled": "true"
            "dfs.namenode.shared.edits.dir": "qjournal://master1.ryba:8485;master2.ryba:8485;master3.ryba:8485/torval"
            "dfs.ha.fencing.methods": "sshfence(hdfs)"
            "dfs.ha.fencing.ssh.private-key-files": "/var/lib/hadoop-hdfs/.ssh/id_rsa"
            "dfs.ha.zkfc.port": "8019"
          heapsize: "1024m"
          newsize: "200m"
        include: [
          "worker1.ryba"
          "worker2.ryba"
        ]
        exclude: []
        namenode_opts: ""
        jn:
          conf_dir: "/etc/hadoop-hdfs-journalnode/conf"
        log4j: {}
      zkfc:
        digest:
          name: "zkfc"
          password: "zkfc123"
        conf_dir: "/etc/hadoop-hdfs-zkfc/conf"
        principal: "nn/_HOST@HADOOP.RYBA"
        keytab: "/etc/security/keytabs/nn.service.keytab"
        jaas_file: "/etc/hadoop-hdfs-zkfc/conf/zkfc.jaas"
        opts: "-Djava.security.auth.login.config=/etc/hadoop-hdfs-zkfc/conf/zkfc.jaas "
      yarn:
        user:
          limits:
            nproc: 16384
            nofile: 16384
          uid: 2403
          gid: "yarn"
          name: "yarn"
          system: true
          groups: "hadoop"
          comment: "Hadoop YARN User"
          home: "/var/lib/hadoop-yarn"
        opts: "-Dsun.net.spi.nameservice.provider.1=sun,dns"
        site:
          "yarn.scheduler.minimum-allocation-mb": 512
          "yarn.scheduler.maximum-allocation-mb": 1536
          "yarn.scheduler.minimum-allocation-vcores": 1
          "yarn.scheduler.maximum-allocation-vcores": 3
          "yarn.log.server.url": "https://master3.ryba:19889/jobhistory/logs/"
          "yarn.timeline-service.enabled": "true"
          "yarn.timeline-service.address": "master3.ryba:10200"
          "yarn.timeline-service.webapp.address": "master3.ryba:8188"
          "yarn.timeline-service.webapp.https.address": "master3.ryba:8190"
          "yarn.timeline-service.principal": "ats/_HOST@HADOOP.RYBA"
          "yarn.timeline-service.http-authentication.type": "kerberos"
          "yarn.timeline-service.http-authentication.kerberos.principal": "HTTP/_HOST@HADOOP.RYBA"
        group:
          gid: 2403
          name: "yarn"
          system: true
        capacity_scheduler:
          "yarn.scheduler.capacity.resource-calculator": "org.apache.hadoop.yarn.util.resource.DominantResourceCalculator"
        home: "/usr/hdp/current/hadoop-yarn-client"
        log_dir: "/var/log/hadoop-yarn"
        pid_dir: "/var/run/hadoop-yarn"
        rm:
          conf_dir: "/etc/hadoop-yarn-resourcemanager/conf"
          core_site: {}
          opts: "-Djava.security.auth.login.config=/etc/hadoop-yarn-resourcemanager/conf/yarn-rm.jaas "
          heapsize: "1024"
          site:
            "yarn.http.policy": "HTTPS_ONLY"
            "yarn.resourcemanager.ha.id": "master1"
            "yarn.resourcemanager.nodes.include-path": "/etc/hadoop-yarn-resourcemanager/conf/yarn.include"
            "yarn.resourcemanager.nodes.exclude-path": "/etc/hadoop-yarn-resourcemanager/conf/yarn.exclude"
            "yarn.resourcemanager.keytab": "/etc/security/keytabs/rm.service.keytab"
            "yarn.resourcemanager.principal": "rm/_HOST@HADOOP.RYBA"
            "yarn.resourcemanager.scheduler.class": "org.apache.hadoop.yarn.server.resourcemanager.scheduler.capacity.CapacityScheduler"
            "yarn.scheduler.minimum-allocation-mb": "256"
            "yarn.scheduler.maximum-allocation-mb": "2048"
            "yarn.scheduler.minimum-allocation-vcores": 1
            "yarn.scheduler.maximum-allocation-vcores": 32
            "yarn.resourcemanager.zk-address": "master1.ryba:2181,master2.ryba:2181,master3.ryba:2181"
            "mapreduce.jobhistory.principal": "jhs/master3.ryba@HADOOP.RYBA"
            "yarn.resourcemanager.bind-host": "0.0.0.0"
            "yarn.resourcemanager.ha.enabled": "true"
            "yarn.resourcemanager.cluster-id": "yarn_cluster_01"
            "yarn.resourcemanager.ha.rm-ids": "master1,master2"
            "yarn.resourcemanager.webapp.delegation-token-auth-filter.enabled": "true"
            "yarn.resourcemanager.address.master1": "master1.ryba:8050"
            "yarn.resourcemanager.scheduler.address.master1": "master1.ryba:8030"
            "yarn.resourcemanager.admin.address.master1": "master1.ryba:8141"
            "yarn.resourcemanager.webapp.address.master1": "master1.ryba:8088"
            "yarn.resourcemanager.webapp.https.address.master1": "master1.ryba:8090"
            "yarn.resourcemanager.resource-tracker.address.master1": "master1.ryba:8025"
            "yarn.resourcemanager.address.master2": "master2.ryba:8050"
            "yarn.resourcemanager.scheduler.address.master2": "master2.ryba:8030"
            "yarn.resourcemanager.admin.address.master2": "master2.ryba:8141"
            "yarn.resourcemanager.webapp.address.master2": "master2.ryba:8088"
            "yarn.resourcemanager.webapp.https.address.master2": "master2.ryba:8090"
            "yarn.resourcemanager.resource-tracker.address.master2": "master2.ryba:8025"
            "yarn.resourcemanager.ha.automatic-failover.enabled": "true"
            "yarn.resourcemanager.ha.automatic-failover.embedded": "true"
            "yarn.resourcemanager.ha.automatic-failover.zk-base-path": "/yarn-leader-election"
            "yarn.resourcemanager.scheduler.monitor.enable": "true"
            "yarn.resourcemanager.scheduler.monitor.policies": "org.apache.hadoop.yarn.server.resourcemanager.monitor.capacity.ProportionalCapacityPreemptionPolicy"
            "yarn.resourcemanager.monitor.capacity.preemption.monitoring_interva": "3000"
            "yarn.resourcemanager.monitor.capacity.preemption.max_wait_before_kill": "15000"
            "yarn.resourcemanager.monitor.capacity.preemption.total_preemption_per_round": "0.1"
            "yarn.resourcemanager.recovery.enabled": "true"
            "yarn.resourcemanager.work-preserving-recovery.enabled": "true"
            "yarn.resourcemanager.am.max-attempts": "2"
            "yarn.resourcemanager.store.class": "org.apache.hadoop.yarn.server.resourcemanager.recovery.ZKRMStateStore"
            "yarn.resourcemanager.zk-acl": "sasl:rm:rwcda"
            "yarn.resourcemanager.zk-state-store.parent-path": "/rmstore"
            "yarn.resourcemanager.zk-num-retries": "500"
            "yarn.resourcemanager.zk-retry-interval-ms": "2000"
            "yarn.resourcemanager.zk-timeout-ms": "10000"
      capacity_scheduler:
        "yarn.scheduler.capacity.maximum-am-resource-percent": ".5"
        "yarn.scheduler.capacity.default.minimum-user-limit-percent": "100"
        "yarn.scheduler.capacity.maximum-applications": "10000"
        "yarn.scheduler.capacity.node-locality-delay": "40"
        "yarn.scheduler.capacity.resource-calculator": "org.apache.hadoop.yarn.util.resource.DominantResourceCalculator"
        "yarn.scheduler.capacity.root.accessible-node-labels": null
        "yarn.scheduler.capacity.root.accessible-node-labels.default.capacity": null
        "yarn.scheduler.capacity.root.accessible-node-labels.default.maximum-capacity": null
        "yarn.scheduler.capacity.root.acl_administer_queue": "*"
        "yarn.scheduler.capacity.root.default-node-label-expression": " "
        "yarn.scheduler.capacity.root.default.acl_administer_jobs": "*"
        "yarn.scheduler.capacity.root.default.acl_submit_applications": "*"
        "yarn.scheduler.capacity.root.default.capacity": "100"
        "yarn.scheduler.capacity.root.default.maximum-capacity": "100"
        "yarn.scheduler.capacity.root.default.state": "RUNNING"
        "yarn.scheduler.capacity.root.default.user-limit-factor": "1"
        "yarn.scheduler.capacity.root.queues": "default"
        "yarn.scheduler.capacity.queue-mappings": ""
        "yarn.scheduler.capacity.queue-mappings-override.enable": "false"
      mapred:
        user:
          limits:
            nproc: 16384
            nofile: 16384
          uid: 2404
          gid: "mapred"
          name: "mapred"
          system: true
          groups: "hadoop"
          comment: "Hadoop MapReduce User"
          home: "/var/lib/hadoop-mapreduce"
        site:
          "mapreduce.job.counters.max": "10000"
          "mapreduce.job.counters.limit": "10000"
        group:
          gid: 2404
          name: "mapred"
          system: true
      hive:
        user:
          limits:
            nproc: 16384
            nofile: 16384
          uid: 2407
          gid: 2407
        site:
          "javax.jdo.option.ConnectionDriverName": "com.mysql.jdbc.Driver"
          "javax.jdo.option.ConnectionUserName": "hive"
          "javax.jdo.option.ConnectionPassword": "hive123"
        group:
          gid: 2407
      hue:
        ini:
          desktop:
            smtp:
              host: ""
            database:
              engine: "mysql"
              password: "hue123"
        ssl:
          certificate: "/home/pierrotws/workspace/ryba-cluster/conf/certs/master3_cert.pem"
          private_key: "/home/pierrotws/workspace/ryba-cluster/conf/certs/master3_key.pem"
          client_ca: "/home/pierrotws/workspace/ryba-cluster/conf/certs/cacert.pem"
        group:
          gid: 2410
        user:
          uid: 2410
          gid: 2410
      sqoop:
        libs: []
        user:
          uid: 2412
          gid: 2400
      hbase:
        regionserver_opts: "-Xmx512m"
        admin:
          password: "hbase123"
          name: "hbase"
          principal: "hbase@HADOOP.RYBA"
        metrics:
          "*.sink.file.class": "org.apache.hadoop.metrics2.sink.FileSink"
          sinks:
            file: true
            ganglia: false
            graphite: false
          config:
            "*.period": "60"
            "*.sink.file.class": "org.apache.hadoop.metrics2.sink.FileSink"
            "*.sink.file.filename": "metrics.out"
            "hbase.sink.file.filename": "hbase-metrics.out"
        group:
          gid: 2409
          name: "hbase"
          system: true
        user:
          uid: 2409
          gid: "hbase"
          name: "hbase"
          system: true
          comment: "HBase User"
          home: "/var/run/hbase"
          groups: "hadoop"
          limits:
            nofile: 64000
            nproc: true
        test:
          default_table: "ryba"
        conf_dir: "/etc/hbase/conf"
        log_dir: "/var/log/hbase"
        pid_dir: "/var/run/hbase"
        site:
          "zookeeper.znode.parent": "/hbase"
          "hbase.cluster.distributed": "true"
          "hbase.rootdir": "hdfs://torval:8020/apps/hbase/data"
          "hbase.zookeeper.quorum": "master1.ryba,master2.ryba,master3.ryba"
          "hbase.zookeeper.property.clientPort": "2181"
          "dfs.domain.socket.path": "/var/lib/hadoop-hdfs/dn_socket"
          "hbase.security.authentication": "kerberos"
          "hbase.security.authorization": "true"
          "hbase.rpc.engine": "org.apache.hadoop.hbase.ipc.SecureRpcEngine"
          "hbase.superuser": "hbase"
          "hbase.bulkload.staging.dir": "/apps/hbase/staging"
          "hbase.regionserver.storefile.refresh.all": "true"
          "hbase.regionserver.storefile.refresh.period": "30000"
          "hbase.region.replica.replication.enabled": "true"
          "hbase.master.hfilecleaner.ttl": "3600000"
          "hbase.master.loadbalancer.class": "org.apache.hadoop.hbase.master.balancer.StochasticLoadBalancer"
          "hbase.meta.replica.count": "3"
          "hbase.region.replica.wait.for.primary.flush": "true"
          "hbase.region.replica.storefile.refresh.memstore.multiplier": "4"
          "hbase.table.sanity.checks": "true"
          "hbase.defaults.for.version.skip": "true"
          "phoenix.functions.allowUserDefinedFunctions": "true"
          "hbase.rpc.controllerfactory.class": "org.apache.hadoop.hbase.ipc.controller.ServerRpcControllerFactory"
          "hbase.master.port": "60000"
          "hbase.master.info.port": "60010"
          "hbase.master.info.bindAddress": "0.0.0.0"
          "hbase.ssl.enabled": "true"
          "hbase.master.keytab.file": "/etc/security/keytabs/hm.service.keytab"
          "hbase.master.kerberos.principal": "hbase/_HOST@HADOOP.RYBA"
          "hbase.regionserver.kerberos.principal": "hbase/_HOST@HADOOP.RYBA"
          "hbase.coprocessor.master.classes": "org.apache.hadoop.hbase.security.access.AccessController"
          "hadoop.proxyuser.hbase_rest.groups": "*"
          "hadoop.proxyuser.hbase_rest.hosts": "*"
        env:
          JAVA_HOME: "/usr/lib/jvm/java"
          HBASE_LOG_DIR: "/var/log/hbase"
          HBASE_OPTS: "-ea -XX:+UseConcMarkSweepGC -XX:+CMSIncrementalMode"
          HBASE_MASTER_OPTS: "-Xmx2048m -Djava.security.auth.login.config=/etc/hbase/conf/hbase-master.jaas"
          HBASE_REGIONSERVER_OPTS: "-Xmn200m -Xms4096m -Xmx4096m"
        master_opts: "-Xmx2048m -Djava.security.auth.login.config=/etc/hbase/conf/hbase-master.jaas"
        log4j: {}
      kafka:
        broker:
          heapsize: 128
          "log.dirs": [
            "/data/1/kafka"
            "/data/2/kafka"
          ]
          conf_dir: "/etc/kafka-broker/conf"
          config:
            "log.dirs": "/data/1/kafka,/data/2/kafka"
            "zookeeper.connect": [
              "master1.ryba:2181"
              "master2.ryba:2181"
              "master3.ryba:2181"
            ]
            "log.retention.hours": "168"
            "super.users": "User:kafka"
            "num.partitions": 3
            "broker.id": "0"
            "ssl.keystore.location": "/etc/kafka-broker/conf/keystore"
            "ssl.keystore.password": "ryba123"
            "ssl.key.password": "ryba123"
            "ssl.truststore.location": "/etc/kafka-broker/conf/truststore"
            "ssl.truststore.password": "ryba123"
            "sasl.kerberos.service.name": "kafka"
            "allow.everyone.if.no.acl.found": "true"
            "zookeeper.set.acl": true
            listeners: "SASL_SSL://master1.ryba:9096"
            "replication.security.protocol": "SASL_SSL"
          env:
            KAFKA_HEAP_OPTS: "-Xmx128m -Xms128m"
            KAFKA_LOG4J_OPTS: "-Dlog4j.configuration=file:$base_dir/../config/log4j.properties"
            KAFKA_KERBEROS_PARAMS: "-Djava.security.auth.login.config=/etc/kafka-broker/conf/kafka-server.jaas"
          log4j:
            "log4j.rootLogger": "INFO, kafkaAppender"
            "log4j.additivity.kafka": "false"
          protocols: [
            "SASL_SSL"
          ]
          kerberos:
            principal: "kafka/master1.ryba@HADOOP.RYBA"
            keyTab: "/etc/security/keytabs/kafka.service.keytab"
        group:
          gid: 2424
          name: "kafka"
          system: true
        user:
          uid: 2424
          gid: "kafka"
          name: "kafka"
          system: true
          comment: "Kafka User"
          home: "/var/lib/kafka"
        admin:
          principal: "kafka"
          password: "kafka123"
        superusers: [
          "kafka"
        ]
        ports:
          PLAINTEXT: "9092"
          SSL: "9093"
          SASL_PLAINTEXT: "9094"
          SASL_SSL: "9096"
      opentsdb:
        version: "2.2.0RC3"
        group:
          gid: 2428
        user:
          uid: 2428
          gid: 2428
      nagios:
        users:
          nagiosadmin:
            password: "nagios123"
            alias: "Nagios Admin"
            email: ""
          guest:
            password: "guest123"
            alias: "Nagios Guest"
            email: ""
        groups:
          admins:
            alias: "Nagios Administrators"
            members: [
              "nagiosadmin"
              "guest"
            ]
        group:
          gid: 2418
        groupcmd:
          gid: 2419
        user:
          uid: 2418
          gid: 2418
      hadoop_group:
        gid: 2400
        name: "hadoop"
        system: true
      group:
        gid: 2414
        name: "ryba"
        system: true
      user:
        uid: 2414
        gid: 2414
        name: "ryba"
        password: "password"
        system: true
        comment: "ryba User"
        home: "/home/ryba"
      zookeeper:
        group:
          gid: 2402
          name: "zookeeper"
          system: true
        user:
          uid: 2402
          gid: 2400
          name: "zookeeper"
          system: true
          groups: "hadoop"
          comment: "Zookeeper User"
          home: "/var/lib/zookeeper"
        conf_dir: "/etc/zookeeper/conf"
        log_dir: "/var/log/zookeeper"
        port: 2181
        env:
          JAVA_HOME: "/usr/lib/jvm/java"
          CLIENT_JVMFLAGS: "-Djava.security.auth.login.config=/etc/zookeeper/conf/zookeeper-client.jaas"
          ZOOKEEPER_HOME: "/usr/hdp/current/zookeeper-client"
          ZOO_AUTH_TO_LOCAL: "RULE:[1:\\$1]RULE:[2:\\$1]"
          ZOO_LOG_DIR: "/var/log/zookeeper"
          ZOOPIDFILE: "/var/run/zookeeper/zookeeper_server.pid"
          SERVER_JVMFLAGS: "-Xmx1024m -Djava.security.auth.login.config=/etc/zookeeper/conf/zookeeper-server.jaas -Dzookeeper.security.auth_to_local=$ZOO_AUTH_TO_LOCAL"
          JAVA: "$JAVA_HOME/bin/java"
          CLASSPATH: "$CLASSPATH:/usr/share/zookeeper/*"
          ZOO_LOG4J_PROP: "INFO,CONSOLE,ROLLINGFILE"
        pid_dir: "/var/run/zookeeper"
        log4j: {}
        config:
          maxClientCnxns: "200"
          tickTime: "2000"
          initLimit: "10"
          syncLimit: "5"
          dataDir: "/var/zookeeper/data/"
          clientPort: "2181"
          "server.1": "master1.ryba:2888:3888"
          "server.2": "master2.ryba:2888:3888"
          "server.3": "master3.ryba:2888:3888"
          "authProvider.1": "org.apache.zookeeper.server.auth.SASLAuthenticationProvider"
          jaasLoginRenew: "3600000"
          "kerberos.removeHostFromPrincipal": "true"
          "kerberos.removeRealmFromPrincipal": "true"
        myid: null
        retention: 3
        purge: "@weekly"
        superuser: {}
      flume:
        group:
          gid: 2405
        user:
          uid: 2405
          gid: 2405
      ganglia:
        rrdcached_group:
          gid: 2406
          name: "rrdcached"
          system: true
        rrdcached_user:
          uid: 2406
          gid: "rrdcached"
          name: "rrdcached"
          system: true
          shell: false
          comment: "RRDtool User"
          home: "/var/rrdtool/rrdcached"
        collector_port: 8649
        slaves_port: 8660
        hbase_region_port: 8660
        nn_port: 8661
        jt_port: 8662
        hm_port: 8663
        hbase_master_port: 8663
        rm_port: 8664
        jhs_port: 8666
        spark_port: 8667
      oozie:
        group:
          gid: 2411
        user:
          uid: 2411
          gid: 2411
      pig:
        user:
          uid: 2413
          gid: 2400
      knox:
        group:
          gid: 2420
        user:
          uid: 2420
          gid: 2420
      falcon:
        group:
          gid: 2421
        user:
          uid: 2421
          gid: 2421
      elasticsearch:
        group:
          gid: 2422
        user:
          uid: 2422
          gid: 2422
      rexster:
        group:
          gid: 2423
        user:
          uid: 2423
          gid: 2423
      presto:
        group:
          gid: 2425
        user:
          uid: 2425
          gid: 2425
      spark:
        group:
          gid: 2426
        user:
          uid: 2426
          gid: 2426
      httpfs:
        group:
          gid: 2427
          name: "httpfs"
          system: true
        user:
          uid: 2427
          gid: "httpfs"
          name: "httpfs"
          system: true
          comment: "HttpFS User"
          home: "/var/lib/httpfs"
          groups: "hadoop"
        pid_dir: "/var/run/httpfs"
        conf_dir: "/etc/hadoop-httpfs/conf"
        log_dir: "/var/log/hadoop-httpfs"
        tmp_dir: "/var/tmp/hadoop-httpfs"
        http_port: "14000"
        http_admin_port: "14001"
        catalina_home: "/etc/hadoop-httpfs/tomcat-deployment"
        catalina_opts: ""
        env:
          HTTPFS_SSL_ENABLED: "true"
          HTTPFS_SSL_KEYSTORE_FILE: "/etc/hadoop-httpfs/conf/keystore"
          HTTPFS_SSL_KEYSTORE_PASS: "ryba123"
        site:
          "httpfs.hadoop.config.dir": "/etc/hadoop/conf"
          "kerberos.realm": "HADOOP.RYBA"
          "httpfs.hostname": "master1.ryba"
          "httpfs.authentication.type": "kerberos"
          "httpfs.authentication.kerberos.principal": "HTTP/master1.ryba@HADOOP.RYBA"
          "httpfs.authentication.kerberos.keytab": "/etc/security/keytabs/spnego.service.keytab"
          "httpfs.hadoop.authentication.type": "kerberos"
          "httpfs.hadoop.authentication.kerberos.keytab": "/etc/security/keytabs/httpfs.service.keytab"
          "httpfs.hadoop.authentication.kerberos.principal": "httpfs/master1.ryba@HADOOP.RYBA"
          "httpfs.authentication.kerberos.name.rules": '''
            
            RULE:[2:$1@$0]([rn]m@HADOOP\\.RYBA)s/.*/yarn/
            RULE:[2:$1@$0](jhs@HADOOP\\.RYBA)s/.*/mapred/
            RULE:[2:$1@$0]([nd]n@HADOOP\\.RYBA)s/.*/hdfs/
            RULE:[2:$1@$0](hm@HADOOP\\.RYBA)s/.*/hbase/
            RULE:[2:$1@$0](rs@HADOOP\\.RYBA)s/.*/hbase/
            RULE:[2:$1@$0](opentsdb@HADOOP\\.RYBA)s/.*/hbase/
            DEFAULT
            RULE:[1:$1](yarn|mapred|hdfs|hive|hbase|oozie)s/.*/nobody/
            RULE:[2:$1](yarn|mapred|hdfs|hive|hbase|oozie)s/.*/nobody/
            RULE:[1:$1]
            RULE:[2:$1]
            
          '''
          "httpfs.proxyuser.knox.hosts": "front1.ryba"
          "httpfs.proxyuser.knox.groups": "*"
      nagvis:
        group:
          gid: 2429
        user:
          uid: 2429
          gid: 2429
      hdp_repo: false
      titan:
        source: "http://10.10.10.1/titan-0.5.4-hadoop2.zip"
      active_nn: true
      proxy: null
      db_admin:
        engine: "mysql"
        host: "master3.ryba"
        path: "mysql"
        port: "3306"
        username: "root"
        password: "test123"
      graphite:
        carbon_port: 2023
        carbon_cache_port: 2003
        carbon_aggregator_port: 2023
        metrics_prefix: "hadoop"
        carbon_rewrite_rules: [
          "[pre]"
          "^(?P<cluster>w+).hbase.[a-zA-Z0-9_.,:;-=]*Context=(?P<context>w+).Hostname=(?P<host>w+).(?P<metric>.w+)*$ = g<cluster>.g<host>.hbase.g<context>g<metric>"
          "^(?P<cluster>w+).(?P<bean>w+).(?P<foobar>w+).Hostname=(?P<host>w+).(?P<metric>.w+)*$ = g<cluster>.g<host>.g<foobar>g<metric>"
          "^(?P<cluster>w+).(?P<bean>w+).[a-zA-Z0-9_.=]*port=(?P<port>w+).Context=(?P<context>w+).[a-zA-Z0-9_.=]*Hostname=(?P<host>w+).(?P<metric>.w+)*$ = g<cluster>.g<host>.g<context>.g<port>g<metric>"
          "^(?P<cluster>w+).(?P<bean>w+).[a-zA-Z0-9_.=]*Queue=root(?P<queue>.w+\b)*.Context=(?P<context>w+).[a-zA-Z0-9_.=]*Hostname=(?P<host>w+).(?P<metric>.w+)*$ = g<cluster>.g<host>.g<context>.queue.g<queue>g<metric>"
          "^(?P<cluster>w+).(?P<bean>w+).[a-zA-Z0-9_.=]*Context=(?P<context>w+).ProcessName=(?P<process>w+).[a-zA-Z0-9_.=]*Hostname=(?P<host>w+).(?P<metric>.w+)*$ = g<cluster>.g<host>.g<context>.g<process>g<metric>"
          "^(?P<cluster>w+).(?P<bean>w+).[a-zA-Z0-9_.=]*Context=(?P<context>w+).[a-zA-Z0-9_.=]*Hostname=(?P<host>w+).(?P<metric>.w+)*$ = g<cluster>.g<host>.g<context>g<metric>"
          "rpcdetailed = rpc"
        ]
        carbon_conf: [
          "[aggregator]"
          "LINE_RECEIVER_INTERFACE = 0.0.0.0"
          "LINE_RECEIVER_PORT = 2023"
          "PICKLE_RECEIVER_INTERFACE = 0.0.0.0"
          "PICKLE_RECEIVER_PORT = 2024"
          "LOG_LISTENER_CONNECTIONS = True"
          "FORWARD_ALL = True"
          "DESTINATIONS = 127.0.0.1:2004"
          "REPLICATION_FACTOR = 1"
          "MAX_QUEUE_SIZE = 10000"
          "USE_FLOW_CONTROL = True"
          "MAX_DATAPOINTS_PER_MESSAGE = 500"
          "MAX_AGGREGATION_INTERVALS = 5"
          "# WRITE_BACK_FREQUENCY = 0"
        ]
      hadoop_conf_dir: "/etc/hadoop/conf"
      hadoop_lib_home: "/usr/hdp/current/hadoop-client/lib"
      standby_nn_host: "master2.ryba"
      static_host: "_HOST"
      active_nn_host: "master1.ryba"
      core_jars: {}
      hadoop_classpath: ""
      hadoop_client_opts: "-Xmx2048m"
      hadoop_policy: {}
      ssl_client:
        "ssl.client.truststore.location": "/etc/hadoop/conf/truststore"
        "ssl.client.truststore.password": "ryba123"
        "ssl.client.truststore.type": "jks"
      ssl_server:
        "ssl.server.keystore.location": "/etc/hadoop/conf/keystore"
        "ssl.server.keystore.password": "ryba123"
        "ssl.server.keystore.type": "jks"
        "ssl.server.keystore.keypassword": "ryba123"
        "ssl.server.truststore.location": "/etc/hadoop/conf/truststore"
        "ssl.server.truststore.password": "ryba123"
        "ssl.server.truststore.type": "jks"
    httpd:
      user:
        uid: 2416
        gid: 2416
      group:
        gid: 2416
    xasecure:
      group:
        gid: 2417
      user:
        uid: 2417
        gid: 2417
    proxy:
      system: false
      system_file: "/etc/profile.d/phyla_proxy.sh"
      host: null
      port: null
      username: null
      password: null
      secure: null
      http_proxy: null
      https_proxy: null
      http_proxy_no_auth: null
      https_proxy_no_auth: null
    curl:
      check: false
      config:
        noproxy: "localhost,127.0.0.1,.ryba"
        proxy: null
      merge: true
      users: true
      proxy: true
      check_match: {}
    profile:
      "proxy.sh": ""
    ntp:
      servers: [
        "master3.ryba"
      ]
      fudge: 14
      lag: 2000
    hdp:
      hue_smtp_host: ""
    ambari: {}
    ip: "10.10.10.11"
    modules: [
      "masson/core/reload"
      "masson/core/fstab"
      "masson/core/network"
      "masson/core/network_check"
      "masson/core/users"
      "masson/core/ssh"
      "masson/core/ntp"
      "masson/core/proxy"
      "masson/core/yum"
      "masson/core/security"
      "masson/core/iptables"
      "masson/core/krb5_server"
      "masson/core/sssd"
      "ryba/zookeeper/server"
      "ryba/hadoop/hdfs_jn"
      "ryba/hadoop/hdfs_nn"
      "ryba/hadoop/zkfc"
      "ryba/hadoop/httpfs"
      "ryba/hadoop/yarn_rm"
      "ryba/phoenix/master"
      "ryba/hbase/master"
      "ryba/kafka/broker"
    ]
    host: "master1.ryba"
    shortname: "master1"
    hostname: "master1.ryba"
    groups: {}
    fstab:
      enabled: false
      exhaustive: false
      volumes: {}
    metrics_sinks:
      file:
        class: "org.apache.hadoop.metrics2.sink.FileSink"
        filename: "metrics.out"
      ganglia:
        class: "org.apache.hadoop.metrics2.sink.ganglia.GangliaSink31"
        period: "10"
        supportparse: "true"
        slope: "jvm.metrics.gcCount=zero,jvm.metrics.memHeapUsedM=both"
        dmax: "jvm.metrics.threadsBlocked=70,jvm.metrics.memHeapUsedM=40"
      graphite:
        class: "org.apache.hadoop.metrics2.sink.GraphiteSink"
        period: "10"
  "master2.ryba":
    connection:
      private_key: '''
        -----BEGIN RSA PRIVATE KEY-----
        MIIEogIBAAKCAQEArBDFt50aN9jfIJ629pRGIMA1fCMb9RyTHt9A+jx3FOsIOtJs
        eaBIpv98drbFVURr+cUs/CrgGVk5k2NIeiz0bG4ONV5nTwx38z5CzqLb7UryZS3i
        a/TS14fWOxvWTRR27R71ePX90G/ZIReKFeTrucw9y9Pl+xAzsmeblRwLBxv/SWBX
        Uai2mHAZaejlG9dGkn9f2n+oPmbgk6krLMCjLhlNBnkdroBNSXGA9ewLPFF4y54Q
        kBqmG3eLzCqAKAzwyJ5PpybtNGAWfN81gY/P5LBzC66WdtEzpwsYAv1wCioqggtg
        xVZN2s0ajxQrCxahRkXstBI2IDcm2qUTxaDbUwIDAQABAoIBAFruOi7AvXxKBhCt
        D6/bx/vC2AEUZM/yG+Wywhn8HkpVsvGzBlR4Wiy208XA7SQUlqNWimFxHyEGQCEd
        1M2MOFedCbE2hI4H3tQTUSb2dhc/Bj5mM0QuC8aPKK3wFh6B9B93vu3/wfSHR03v
        rK/JXLHBt96hyuYVN9zOWDBCs6k7SdQ2BcsQLiPg6feTsZelJDuO+DO65kKLMiz3
        mNPThErklRaKovNk47LSYakk6gsJXrpG6JWQ6nwsRenwplDwZ8Zs9mlRi7f3nChM
        3I1WlISN8y2kcQBQ94YZKk8wzH/lzmxsabcLa5ETNubxQ6ThDu1oYUIIUsQyNPm+
        DkW0VwECgYEA5MttelspKexWS39Y3sQYvZ/v8VZBQl4tRbpUWWc+PNEtcEwOBza/
        H4jBWYd2eWKTApJT1st58E4b34Mv88nQVElLb3sE7uJMkihPyNpABGbCvr63hDYw
        PyL53nKaPelY/aDnL0F8LmREfdKw/uy6+UChgkPfdo2VVk1oyvsZaRMCgYEAwIZ+
        lCmeXQ4mU6uxO+ChhDn7zw9rR5qlCyfJiLPe2lV20vaHV5ZfKIWGegsVJSpFr2ST
        5ghh+FVIneoNRtTHEKwNWCK7I6qeF+WAaci+KsLQigJQHsw58n9cdA7wHHc475n/
        pf7efoPcvk6qYOS2mpDgC87m+o3C4Dyspqp9TMECgYA4/ed+dBjT5Zg1ZDp5+zUC
        f0Wgw1CsPJNgbCK4xnv9YEnGUFuqNlvzefhX2eOMJx7hpBuYRMVSM9LDoYUfYCUx
        6bQNyAIZk2tpePsu2BbcQdC+/PjvySPJhmfhnoCHbYoKW7tazSAm2jkpcoM+bS/C
        CPRyY3/Voz0Q62VwMo5I2wKBgB4mMbZUGieqapgZwASHdeO2DNftKzioYAYyMd5F
        hLWeQqBg2Or/cmFvH5MHH0WVrBn+Xybb0zPHbzrDh1a7RX035FMUBUhdlKpbV1O5
        iwY5Qd0K5a8c/koaZckK+dELXpAvBpjhI8ieL7hhq07HIk1sOJnAye0cvBLPjZ3/
        /uVBAoGAVAs6tFpS0pFlxmg4tfGEm7/aP6FhyBHNhv2QGluw8vv/XVMzUItxGIef
        HcSMWBm08IJMRJLgmoo1cuQv6hBui7JpDeZk/20qoF2oZW9lJ9fdRObJqi61wufP
        BNiriqexq/eTy2uF9RCCjLItWxUscVMlVt4V65HLkCF5WxCQw+o=
        -----END RSA PRIVATE KEY-----
      '''
      public_key: "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCsEMW3nRo32N8gnrb2lEYgwDV8Ixv1HJMe30D6PHcU6wg60mx5oEim/3x2tsVVRGv5xSz8KuAZWTmTY0h6LPRsbg41XmdPDHfzPkLOotvtSvJlLeJr9NLXh9Y7G9ZNFHbtHvV49f3Qb9khF4oV5Ou5zD3L0+X7EDOyZ5uVHAsHG/9JYFdRqLaYcBlp6OUb10aSf1/af6g+ZuCTqSsswKMuGU0GeR2ugE1JcYD17As8UXjLnhCQGqYbd4vMKoAoDPDInk+nJu00YBZ83zWBj8/ksHMLrpZ20TOnCxgC/XAKKiqCC2DFVk3azRqPFCsLFqFGRey0EjYgNybapRPFoNtT Ryba Hadoop"
      bootstrap:
        username: "vagrant"
        password: "vagrant"
        host: "10.10.10.12"
        port: 22
        cmd: "su -"
        retry: 3
      username: "root"
      host: "10.10.10.12"
      port: 22
      private_key_location: "~/.ssh/id_rsa"
      retry: 3
      end: true
      wait: 1000
    mecano:
      cache_dir: "/home/pierrotws/workspace/ryba-cluster/conf/../resources/cache"
      log_serializer: true
    log:
      archive: true
      disabled: false
      basedir: "./log"
      fqdn_reversed: "ryba.master2"
      filename: "master2.log"
      elasticsearch:
        enable: false
        url: "http://localhost:9200"
        index: "masson"
    security:
      selinux: false
      limits: {}
    network:
      hosts_auto: true
      hosts:
        "127.0.0.1": "localhost localhost.localdomain localhost4 localhost4.localdomain4"
        "10.10.10.10": "repos.ryba ryba"
      resolv: '''
        search ryba
        nameserver 10.10.10.13
        nameserver 10.0.2.3
      '''
      hostname_disabled: false
    iptables:
      action: "stop"
      startup: false
      log: true
      rules: []
      log_prefix: "IPTables-Dropped: "
      log_level: 4
      log_rules: [
        {
          chain: "INPUT"
          command: "-A"
          jump: "LOGGING"
        }
        {
          chain: "LOGGING"
          command: "-A"
          "--limit": "2/min"
          jump: "LOG"
          "log-prefix": "IPTables-Dropped: "
          "log-level": 4
        }
        {
          chain: "LOGGING"
          command: "-A"
          jump: "DROP"
        }
      ]
    bind_server:
      zones: [
        "/home/pierrotws/workspace/ryba-cluster/conf/zones/ryba"
        "/home/pierrotws/workspace/ryba-cluster/conf/zones/10.10.10.in-addr.arpa"
      ]
      user:
        uid: 802
        gid: 802
      group:
        gid: 802
    ssh:
      banner:
        destination: "/etc/banner"
        content: "Welcome to Hadoop!"
      sshd_config:
        PermitRootLogin: "without-password"
    users:
      root:
        authorized_keys: [
          "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCWvEjSt2sAvRmkpkt9+u1EXuFDWJSuI1C8G/+NMcpMRDSUTary3Njqt/DC5mx7X36mVJdaq2KqgAVa28zzeuN6Yv7iuxCTw/4K7OKXYu+q0UG8BlIknWgLa8s7Nx2J69Prkb4oFgzw5IqK9EM6VMarUJUCXVNhb3zmamrF59OIxAIyQhV5i5SzoAxLIcD9EtxS/ZRf9t9fOBEhn42SVcpEWO09bUHZ11J2tw/Pwsxk+va83cH9qipVsEwIMDUCosfzV1G2zF5HhU/mhIHWRdAULpaRfd3IgNqTtI6BBi6FOFbJdrkHXPXKRybZwCxChncq1TZI2SXx6BCRpoJ/s887 m.sauvage.pierre@gmail.com"
        ]
        name: "root"
        home: "/root"
    yum:
      packages:
        tree: true
        git: true
        htop: true
        vim: true
        "yum-plugin-priorities": true
        man: true
        ksh: true
      config:
        proxy: null
        main:
          keepcache: "0"
          proxy: null
          proxy_username: null
          proxy_password: null
      copy: "/home/pierrotws/workspace/ryba-cluster/conf/user/offline/*.repo"
      clean: false
      merge: true
      update: true
      proxy: true
      epel: true
      epel_url: "http://download.fedoraproject.org/pub/epel/6/i386/epel-release-6-8.noarch.rpm"
    mysql:
      server:
        current_password: ""
        password: "test123"
        my_cnf:
          mysqld:
            innodb_file_per_table: "1"
            tmpdir: "/tmp/mysql"
        sql_on_install: []
        remove_anonymous: true
        disallow_remote_root_login: false
        remove_test_db: true
        reload_privileges: true
      user:
        name: "mysql"
      group:
        name: "mysql"
    openldap_server:
      suffix: "dc=ryba"
      root_dn: "cn=Manager,dc=ryba"
      root_password: "test"
      config_dn: "cn=admin,cn=config"
      config_password: "test"
      users_dn: "ou=users,dc=ryba"
      groups_dn: "ou=groups,dc=ryba"
      ldapdelete: []
      ldapadd: []
      tls: true
      tls_ca_cert_file: "/home/pierrotws/workspace/ryba-cluster/conf/certs/cacert.pem"
      tls_cert_file: "/home/pierrotws/workspace/ryba-cluster/conf/certs/master3_cert.pem"
      tls_key_file: "/home/pierrotws/workspace/ryba-cluster/conf/certs/master3_key.pem"
      proxy_user:
        uidNumber: 801
        gidNumber: 801
      proxy_group:
        gidNumber: 801
    openldap_client:
      certificates: [
        "/home/pierrotws/workspace/ryba-cluster/conf/certs/master3_cert.pem"
      ]
      config:
        BASE: "dc=ryba"
        URI: "ldaps://master3.ryba"
        TLS_CACERTDIR: "/etc/openldap/cacerts"
        TLS_REQCERT: "allow"
        TIMELIMIT: "15"
        TIMEOUT: "20"
      suffix: "dc=ryba"
      root_dn: "cn=Manager,dc=ryba"
      root_password: "test"
    openldap_server_krb5:
      manager_dn: "cn=Manager,dc=ryba"
      manager_password: "test"
      krbadmin_user:
        mail: "david@adaltas.com"
        userPassword: "test"
        uidNumber: 800
        gidNumber: 800
      krbadmin_group:
        gidNumber: 800
    krb5:
      etc_krb5_conf:
        logging:
          default: "SYSLOG:INFO:LOCAL1"
          kdc: "SYSLOG:NOTICE:LOCAL1"
          admin_server: "SYSLOG:WARNING:LOCAL1"
        libdefaults:
          dns_lookup_realm: false
          dns_lookup_kdc: false
          ticket_lifetime: "24h"
          renew_lifetime: "7d"
          forwardable: true
          allow_weak_crypto: "false"
          clockskew: "300"
          rdns: "false"
          default_realm: "HADOOP.RYBA"
        realms:
          "USERS.RYBA":
            kadmin_principal: "wdavidw/admin@USERS.RYBA"
            kadmin_password: "test"
            principals: [
              {
                principal: "krbtgt/HADOOP.RYBA@USERS.RYBA"
                password: "test"
              }
            ]
            kdc: [
              "master3.ryba"
            ]
            admin_server: "master3.ryba"
            default_domain: "users.ryba"
          "HADOOP.RYBA":
            kadmin_principal: "wdavidw/admin@HADOOP.RYBA"
            kadmin_password: "test"
            principals: [
              {
                principal: "krbtgt/HADOOP.RYBA@USERS.RYBA"
                password: "test"
              }
            ]
            kdc: [
              "master1.ryba"
            ]
            admin_server: "master1.ryba"
            default_domain: "hadoop.ryba"
        domain_realm:
          ryba: "HADOOP.RYBA"
        appdefaults:
          pam:
            debug: false
            ticket_lifetime: 36000
            renew_lifetime: 36000
            forwardable: true
            krb4_convert: false
        dbmodules: {}
      kdc_conf:
        realms: {}
      sshd: {}
      kinit: "/usr/bin/kinit"
    sssd:
      force_check: false
      certificates: [
        "/home/pierrotws/workspace/ryba-cluster/conf/certs/cacert.pem"
      ]
      config:
        sssd:
          config_file_version: "2"
          reconnection_retries: "3"
          sbus_timeout: "30"
          services: "nss, pam"
          debug_level: "1"
          domains: "hadoop,users"
        nss:
          filter_groups: "root"
          filter_users: "root"
          reconnection_retries: "3"
          entry_cache_timeout: "300"
          entry_cache_nowait_percentage: "75"
          debug_level: "1"
        pam:
          reconnection_retries: "3"
          offline_credentials_expiration: "2"
          offline_failed_login_attempts: "3"
          offline_failed_login_delay: "5"
          debug_level: "1"
        "domain/hadoop":
          debug_level: "1"
          cache_credentials: "True"
          ldap_search_base: "ou=users,dc=ryba"
          ldap_group_search_base: "ou=groups,dc=ryba"
          id_provider: "ldap"
          auth_provider: "ldap"
          chpass_provider: "ldap"
          ldap_uri: "ldaps://master3.ryba:636"
          ldap_tls_cacertdir: "/etc/openldap/cacerts"
          ldap_default_bind_dn: "cn=Manager,dc=ryba"
          ldap_default_authtok: "test"
          ldap_id_use_start_tls: "True"
        "domain/users":
          debug_level: "1"
          cache_credentials: "True"
          ldap_search_base: "ou=users,dc=ryba"
          ldap_group_search_base: "ou=groups,dc=ryba"
          id_provider: "ldap"
          auth_provider: "ldap"
          chpass_provider: "ldap"
          ldap_uri: "ldaps://master3.ryba:636"
          ldap_tls_cacertdir: "/etc/openldap/cacerts"
          ldap_default_bind_dn: "cn=Manager,dc=ryba"
          ldap_default_authtok: "test"
          ldap_id_use_start_tls: "False"
      merge: false
      test_user: null
    java:
      java_home: "/usr/lib/jvm/java"
      jre_home: "/usr/lib/jvm/java/jre"
      proxy: null
      openjdk: true
    ryba:
      clean_logs: true
      force_check: false
      check_hdfs_fsck: false
      security: "kerberos"
      realm: "HADOOP.RYBA"
      nameservice: "torval"
      krb5_user:
        password: "test123"
        password_sync: true
        principal: "ryba@HADOOP.RYBA"
      ssl:
        cacert: "/home/pierrotws/workspace/ryba-cluster/conf/certs/cacert.pem"
        cert: "/home/pierrotws/workspace/ryba-cluster/conf/certs/master2_cert.pem"
        key: "/home/pierrotws/workspace/ryba-cluster/conf/certs/master2_key.pem"
      ambari:
        repo: "/home/pierrotws/workspace/ryba-cluster/conf/resources/repos/ambari-2.0.0.repo"
      ssh_fencing:
        private_key: "/home/pierrotws/workspace/ryba-cluster/conf/hdfs_keys/id_rsa"
        public_key: "/home/pierrotws/workspace/ryba-cluster/conf/hdfs_keys/id_rsa.pub"
      hadoop_opts: "-Djava.net.preferIPv4Stack=true -Dsun.security.krb5.debug=false"
      core_site:
        "hadoop.ssl.exclude.cipher.suites": "SSL_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA,SSL_RSA_EXPORT_WITH_DES40_CBC_SHA,SSL_RSA_EXPORT_WITH_RC4_40_MD5,TLS_DHE_RSA_WITH_AES_128_CBC_SHA,TLS_DHE_RSA_WITH_AES_256_CBC_SHA"
        "io.compression.codecs": "org.apache.hadoop.io.compress.GzipCodec,org.apache.hadoop.io.compress.DefaultCodec,org.apache.hadoop.io.compress.SnappyCodec"
        "fs.defaultFS": "hdfs://torval:8020"
        "hadoop.security.authentication": "kerberos"
        "hadoop.security.authorization": "true"
        "hadoop.rpc.protection": "authentication"
        "hadoop.security.group.mapping": "org.apache.hadoop.security.JniBasedUnixGroupsMappingWithFallback"
        "ha.zookeeper.quorum": [
          "master1.ryba:2181"
          "master2.ryba:2181"
          "master3.ryba:2181"
        ]
        "net.topology.script.file.name": "/etc/hadoop/conf/rack_topology.sh"
        "hadoop.http.filter.initializers": "org.apache.hadoop.security.AuthenticationFilterInitializer"
        "hadoop.http.authentication.type": "kerberos"
        "hadoop.http.authentication.token.validity": "36000"
        "hadoop.http.authentication.signature.secret.file": "/etc/hadoop/hadoop-http-auth-signature-secret"
        "hadoop.http.authentication.simple.anonymous.allowed": "false"
        "hadoop.http.authentication.kerberos.principal": "HTTP/_HOST@HADOOP.RYBA"
        "hadoop.http.authentication.kerberos.keytab": "/etc/security/keytabs/spnego.service.keytab"
        "hadoop.http.authentication.cookie.domain": "ryba"
        "hadoop.security.auth_to_local": '''
          
          RULE:[2:$1@$0]([rn]m@HADOOP\\.RYBA)s/.*/yarn/
          RULE:[2:$1@$0](jhs@HADOOP\\.RYBA)s/.*/mapred/
          RULE:[2:$1@$0]([nd]n@HADOOP\\.RYBA)s/.*/hdfs/
          RULE:[2:$1@$0](hm@HADOOP\\.RYBA)s/.*/hbase/
          RULE:[2:$1@$0](rs@HADOOP\\.RYBA)s/.*/hbase/
          RULE:[2:$1@$0](opentsdb@HADOOP\\.RYBA)s/.*/hbase/
          DEFAULT
          RULE:[1:$1](yarn|mapred|hdfs|hive|hbase|oozie)s/.*/nobody/
          RULE:[2:$1](yarn|mapred|hdfs|hive|hbase|oozie)s/.*/nobody/
          RULE:[1:$1]
          RULE:[2:$1]
          
        '''
        "hadoop.proxyuser.HTTP.hosts": "*"
        "hadoop.proxyuser.HTTP.groups": "*"
        "hadoop.proxyuser.httpfs.hosts": "master1.ryba,master2.ryba,master3.ryba"
        "hadoop.proxyuser.httpfs.groups": "*"
        "hadoop.proxyuser.hbase.hosts": "*"
        "hadoop.proxyuser.hbase.groups": "*"
        "hadoop.ssl.require.client.cert": "false"
        "hadoop.ssl.hostname.verifier": "DEFAULT"
        "hadoop.ssl.keystores.factory.class": "org.apache.hadoop.security.ssl.FileBasedKeyStoresFactory"
        "hadoop.ssl.server.conf": "ssl-server.xml"
        "hadoop.ssl.client.conf": "ssl-client.xml"
        "ha.zookeeper.acl": "@/etc/hadoop-hdfs-zkfc/conf/zk-acl.txt"
        "ha.zookeeper.auth": "@/etc/hadoop-hdfs-zkfc/conf/zk-auth.txt"
        "hadoop.proxyuser.hive.groups": "*"
        "hadoop.proxyuser.hive.hosts": "*"
        "hadoop.proxyuser.oozie.hosts": "master3.ryba"
        "hadoop.proxyuser.oozie.groups": "*"
        "hadoop.proxyuser.falcon.groups": "*"
        "hadoop.proxyuser.falcon.hosts": "front1.ryba"
        "hadoop.proxyuser.knox.hosts": "front1.ryba"
        "hadoop.proxyuser.knox.groups": "*"
      hadoop_metrics:
        "*.sink.file.class": "org.apache.hadoop.metrics2.sink.FileSink"
        sinks:
          file: true
          ganglia: false
          graphite: false
        config:
          "*.period": "60"
          "*.sink.file.class": "org.apache.hadoop.metrics2.sink.FileSink"
          "*.sink.file.filename": "metrics.out"
          "namenode.sink.file.filename": "namenode-metrics.out"
          "datanode.sink.file.filename": "datanode-metrics.out"
          "resourcemanager.sink.file.filename": "resourcemanager-metrics.out"
          "nodemanager.sink.file.filename": "nodemanager-metrics.out"
          "mrappmaster.sink.file.filename": "mrappmaster-metrics.out"
          "jobhistoryserver.sink.file.filename": "jobhistoryserver-metrics.out"
      hadoop_heap: "512"
      hadoop_namenode_init_heap: "-Xms512m"
      hdfs:
        user:
          limits:
            nproc: 16384
            nofile: 16384
          uid: 2401
          gid: "hdfs"
          name: "hdfs"
          system: true
          groups: "hadoop"
          comment: "Hadoop HDFS User"
          home: "/var/lib/hadoop-hdfs"
        krb5_user:
          password: "hdfs123"
          password_sync: true
          principal: "hdfs@HADOOP.RYBA"
        sysctl:
          "vm.swappiness": 0
          "vm.overcommit_memory": 1
          "vm.overcommit_ratio": 100
          "net.core.somaxconn": 1024
        site:
          "dfs.namenode.safemode.extension": 1000
          "dfs.replication": 2
          "dfs.namenode.name.dir": [
            "file:///var/hdfs/name"
          ]
          "dfs.journalnode.rpc-address": "0.0.0.0:8485"
          "dfs.journalnode.http-address": "0.0.0.0:8480"
          "dfs.journalnode.https-address": "0.0.0.0:8481"
          "dfs.http.policy": "HTTPS_ONLY"
          "dfs.journalnode.kerberos.internal.spnego.principal": "HTTP/_HOST@HADOOP.RYBA"
          "dfs.journalnode.kerberos.principal": "HTTP/_HOST@HADOOP.RYBA"
          "dfs.journalnode.keytab.file": "/etc/security/keytabs/spnego.service.keytab"
          "dfs.journalnode.edits.dir": "/var/hdfs/edits"
          "dfs.namenode.shared.edits.dir": "qjournal://master1.ryba:8485;master2.ryba:8485;master3.ryba:8485/torval"
          "dfs.namenode.kerberos.principal.pattern": "*"
          "dfs.namenode.kerberos.principal": "nn/_HOST@HADOOP.RYBA"
          "dfs.namenode.kerberos.internal.spnego.principal": "HTTP/_HOST@HADOOP.RYBA"
          "dfs.namenode.kerberos.https.principal": "HTTP/_HOST@HADOOP.RYBA"
          "dfs.web.authentication.kerberos.principal": "HTTP/_HOST@HADOOP.RYBA"
          "dfs.ha.automatic-failover.enabled": "true"
          "dfs.nameservices": "torval"
          "dfs.internal.nameservices": "torval"
          "dfs.ha.namenodes.torval": "master1,master2"
          "dfs.namenode.http-address": null
          "dfs.namenode.https-address": null
          "dfs.namenode.rpc-address.torval.master1": "master1.ryba:8020"
          "dfs.namenode.http-address.torval.master1": "master1.ryba:50070"
          "dfs.namenode.https-address.torval.master1": "master1.ryba:50470"
          "dfs.namenode.rpc-address.torval.master2": "master2.ryba:8020"
          "dfs.namenode.http-address.torval.master2": "master2.ryba:50070"
          "dfs.namenode.https-address.torval.master2": "master2.ryba:50470"
          "dfs.client.failover.proxy.provider.torval": "org.apache.hadoop.hdfs.server.namenode.ha.ConfiguredFailoverProxyProvider"
          "dfs.datanode.kerberos.principal": "dn/_HOST@HADOOP.RYBA"
          "dfs.client.read.shortcircuit": "true"
          "dfs.domain.socket.path": "/var/lib/hadoop-hdfs/dn_socket"
        group:
          gid: 2401
          name: "hdfs"
          system: true
        log_dir: "/var/log/hadoop-hdfs"
        pid_dir: "/var/run/hadoop-hdfs"
        secure_dn_pid_dir: "/var/run/hadoop-hdfs"
        secure_dn_user: "hdfs"
        nn:
          conf_dir: "/etc/hadoop-hdfs-namenode/conf"
          core_site: {}
          site:
            "dfs.http.policy": "HTTPS_ONLY"
            "dfs.namenode.name.dir": "file:///var/hdfs/name"
            "dfs.hosts": "/etc/hadoop-hdfs-namenode/conf/dfs.include"
            "dfs.hosts.exclude": "/etc/hadoop-hdfs-namenode/conf/dfs.exclude"
            "fs.permissions.umask-mode": "027"
            "dfs.block.access.token.enable": "true"
            "dfs.namenode.kerberos.principal": "nn/_HOST@HADOOP.RYBA"
            "dfs.namenode.keytab.file": "/etc/security/keytabs/nn.service.keytab"
            "dfs.namenode.kerberos.internal.spnego.principal": "HTTP/_HOST@HADOOP.RYBA"
            "dfs.namenode.kerberos.https.principal": "HTTP/_HOST@HADOOP.RYBA"
            "dfs.web.authentication.kerberos.principal": "HTTP/_HOST@HADOOP.RYBA"
            "dfs.web.authentication.kerberos.keytab": "/etc/security/keytabs/spnego.service.keytab"
            "dfs.https.namenode.https-address": null
            "dfs.namenode.acls.enabled": "true"
            "dfs.namenode.accesstime.precision": null
            "dfs.journalnode.kerberos.principal": "HTTP/_HOST@HADOOP.RYBA"
            "dfs.nameservices": "torval"
            "dfs.internal.nameservices": "torval"
            "dfs.ha.namenodes.torval": "master1,master2"
            "dfs.namenode.http-address": null
            "dfs.namenode.https-address": null
            "dfs.namenode.rpc-address.torval.master1": "master1.ryba:8020"
            "dfs.namenode.http-address.torval.master1": "master1.ryba:50070"
            "dfs.namenode.https-address.torval.master1": "master1.ryba:50470"
            "dfs.namenode.rpc-address.torval.master2": "master2.ryba:8020"
            "dfs.namenode.http-address.torval.master2": "master2.ryba:50070"
            "dfs.namenode.https-address.torval.master2": "master2.ryba:50470"
            "dfs.client.failover.proxy.provider.torval": "org.apache.hadoop.hdfs.server.namenode.ha.ConfiguredFailoverProxyProvider"
            "dfs.ha.automatic-failover.enabled": "true"
            "dfs.namenode.shared.edits.dir": "qjournal://master1.ryba:8485;master2.ryba:8485;master3.ryba:8485/torval"
            "dfs.ha.fencing.methods": "sshfence(hdfs)"
            "dfs.ha.fencing.ssh.private-key-files": "/var/lib/hadoop-hdfs/.ssh/id_rsa"
            "dfs.ha.zkfc.port": "8019"
          heapsize: "1024m"
          newsize: "200m"
        include: [
          "worker1.ryba"
          "worker2.ryba"
        ]
        exclude: []
        namenode_opts: ""
        jn:
          conf_dir: "/etc/hadoop-hdfs-journalnode/conf"
        log4j: {}
      zkfc:
        digest:
          name: "zkfc"
          password: "zkfc123"
        conf_dir: "/etc/hadoop-hdfs-zkfc/conf"
        principal: "nn/_HOST@HADOOP.RYBA"
        keytab: "/etc/security/keytabs/nn.service.keytab"
        jaas_file: "/etc/hadoop-hdfs-zkfc/conf/zkfc.jaas"
        opts: "-Djava.security.auth.login.config=/etc/hadoop-hdfs-zkfc/conf/zkfc.jaas "
      yarn:
        user:
          limits:
            nproc: 16384
            nofile: 16384
          uid: 2403
          gid: "yarn"
          name: "yarn"
          system: true
          groups: "hadoop"
          comment: "Hadoop YARN User"
          home: "/var/lib/hadoop-yarn"
        opts: "-Dsun.net.spi.nameservice.provider.1=sun,dns"
        site:
          "yarn.scheduler.minimum-allocation-mb": 512
          "yarn.scheduler.maximum-allocation-mb": 1536
          "yarn.scheduler.minimum-allocation-vcores": 1
          "yarn.scheduler.maximum-allocation-vcores": 3
          "yarn.log.server.url": "https://master3.ryba:19889/jobhistory/logs/"
          "yarn.timeline-service.enabled": "true"
          "yarn.timeline-service.address": "master3.ryba:10200"
          "yarn.timeline-service.webapp.address": "master3.ryba:8188"
          "yarn.timeline-service.webapp.https.address": "master3.ryba:8190"
          "yarn.timeline-service.principal": "ats/_HOST@HADOOP.RYBA"
          "yarn.timeline-service.http-authentication.type": "kerberos"
          "yarn.timeline-service.http-authentication.kerberos.principal": "HTTP/_HOST@HADOOP.RYBA"
          "yarn.http.policy": "HTTPS_ONLY"
          "yarn.application.classpath": "$HADOOP_CONF_DIR,/usr/hdp/current/hadoop-client/*,/usr/hdp/current/hadoop-client/lib/*,/usr/hdp/current/hadoop-hdfs-client/*,/usr/hdp/current/hadoop-hdfs-client/lib/*,/usr/hdp/current/hadoop-yarn-client/*,/usr/hdp/current/hadoop-yarn-client/lib/*"
          "yarn.generic-application-history.save-non-am-container-meta-info": "true"
          "yarn.nodemanager.remote-app-log-dir": "/app-logs"
          "yarn.resourcemanager.principal": "rm/_HOST@HADOOP.RYBA"
          "yarn.resourcemanager.cluster-id": "yarn_cluster_01"
          "yarn.resourcemanager.ha.enabled": "true"
          "yarn.resourcemanager.ha.rm-ids": "master1,master2"
          "yarn.resourcemanager.webapp.delegation-token-auth-filter.enabled": "true"
          "yarn.resourcemanager.address.master1": "master1.ryba:8050"
          "yarn.resourcemanager.scheduler.address.master1": "master1.ryba:8030"
          "yarn.resourcemanager.admin.address.master1": "master1.ryba:8141"
          "yarn.resourcemanager.webapp.address.master1": "master1.ryba:8088"
          "yarn.resourcemanager.webapp.https.address.master1": "master1.ryba:8090"
          "yarn.resourcemanager.address.master2": "master2.ryba:8050"
          "yarn.resourcemanager.scheduler.address.master2": "master2.ryba:8030"
          "yarn.resourcemanager.admin.address.master2": "master2.ryba:8141"
          "yarn.resourcemanager.webapp.address.master2": "master2.ryba:8088"
          "yarn.resourcemanager.webapp.https.address.master2": "master2.ryba:8090"
        group:
          gid: 2403
          name: "yarn"
          system: true
        capacity_scheduler:
          "yarn.scheduler.capacity.resource-calculator": "org.apache.hadoop.yarn.util.resource.DominantResourceCalculator"
        home: "/usr/hdp/current/hadoop-yarn-client"
        log_dir: "/var/log/hadoop-yarn"
        pid_dir: "/var/run/hadoop-yarn"
        rm:
          conf_dir: "/etc/hadoop-yarn-resourcemanager/conf"
          core_site: {}
          opts: "-Djava.security.auth.login.config=/etc/hadoop-yarn-resourcemanager/conf/yarn-rm.jaas "
          heapsize: "1024"
          site:
            "yarn.http.policy": "HTTPS_ONLY"
            "yarn.resourcemanager.ha.id": "master2"
            "yarn.resourcemanager.nodes.include-path": "/etc/hadoop-yarn-resourcemanager/conf/yarn.include"
            "yarn.resourcemanager.nodes.exclude-path": "/etc/hadoop-yarn-resourcemanager/conf/yarn.exclude"
            "yarn.resourcemanager.keytab": "/etc/security/keytabs/rm.service.keytab"
            "yarn.resourcemanager.principal": "rm/_HOST@HADOOP.RYBA"
            "yarn.resourcemanager.scheduler.class": "org.apache.hadoop.yarn.server.resourcemanager.scheduler.capacity.CapacityScheduler"
            "yarn.scheduler.minimum-allocation-mb": "256"
            "yarn.scheduler.maximum-allocation-mb": "2048"
            "yarn.scheduler.minimum-allocation-vcores": 1
            "yarn.scheduler.maximum-allocation-vcores": 32
            "yarn.resourcemanager.zk-address": "master1.ryba:2181,master2.ryba:2181,master3.ryba:2181"
            "mapreduce.jobhistory.principal": "jhs/master3.ryba@HADOOP.RYBA"
            "yarn.resourcemanager.bind-host": "0.0.0.0"
            "yarn.resourcemanager.ha.enabled": "true"
            "yarn.resourcemanager.cluster-id": "yarn_cluster_01"
            "yarn.resourcemanager.ha.rm-ids": "master1,master2"
            "yarn.resourcemanager.webapp.delegation-token-auth-filter.enabled": "true"
            "yarn.resourcemanager.address.master1": "master1.ryba:8050"
            "yarn.resourcemanager.scheduler.address.master1": "master1.ryba:8030"
            "yarn.resourcemanager.admin.address.master1": "master1.ryba:8141"
            "yarn.resourcemanager.webapp.address.master1": "master1.ryba:8088"
            "yarn.resourcemanager.webapp.https.address.master1": "master1.ryba:8090"
            "yarn.resourcemanager.resource-tracker.address.master1": "master1.ryba:8025"
            "yarn.resourcemanager.address.master2": "master2.ryba:8050"
            "yarn.resourcemanager.scheduler.address.master2": "master2.ryba:8030"
            "yarn.resourcemanager.admin.address.master2": "master2.ryba:8141"
            "yarn.resourcemanager.webapp.address.master2": "master2.ryba:8088"
            "yarn.resourcemanager.webapp.https.address.master2": "master2.ryba:8090"
            "yarn.resourcemanager.resource-tracker.address.master2": "master2.ryba:8025"
            "yarn.resourcemanager.ha.automatic-failover.enabled": "true"
            "yarn.resourcemanager.ha.automatic-failover.embedded": "true"
            "yarn.resourcemanager.ha.automatic-failover.zk-base-path": "/yarn-leader-election"
            "yarn.resourcemanager.scheduler.monitor.enable": "true"
            "yarn.resourcemanager.scheduler.monitor.policies": "org.apache.hadoop.yarn.server.resourcemanager.monitor.capacity.ProportionalCapacityPreemptionPolicy"
            "yarn.resourcemanager.monitor.capacity.preemption.monitoring_interva": "3000"
            "yarn.resourcemanager.monitor.capacity.preemption.max_wait_before_kill": "15000"
            "yarn.resourcemanager.monitor.capacity.preemption.total_preemption_per_round": "0.1"
            "yarn.resourcemanager.recovery.enabled": "true"
            "yarn.resourcemanager.work-preserving-recovery.enabled": "true"
            "yarn.resourcemanager.am.max-attempts": "2"
            "yarn.resourcemanager.store.class": "org.apache.hadoop.yarn.server.resourcemanager.recovery.ZKRMStateStore"
            "yarn.resourcemanager.zk-acl": "sasl:rm:rwcda"
            "yarn.resourcemanager.zk-state-store.parent-path": "/rmstore"
            "yarn.resourcemanager.zk-num-retries": "500"
            "yarn.resourcemanager.zk-retry-interval-ms": "2000"
            "yarn.resourcemanager.zk-timeout-ms": "10000"
        conf_dir: "/etc/hadoop/conf"
        heapsize: "1024"
      capacity_scheduler:
        "yarn.scheduler.capacity.maximum-am-resource-percent": ".5"
        "yarn.scheduler.capacity.default.minimum-user-limit-percent": "100"
        "yarn.scheduler.capacity.maximum-applications": "10000"
        "yarn.scheduler.capacity.node-locality-delay": "40"
        "yarn.scheduler.capacity.resource-calculator": "org.apache.hadoop.yarn.util.resource.DominantResourceCalculator"
        "yarn.scheduler.capacity.root.accessible-node-labels": null
        "yarn.scheduler.capacity.root.accessible-node-labels.default.capacity": null
        "yarn.scheduler.capacity.root.accessible-node-labels.default.maximum-capacity": null
        "yarn.scheduler.capacity.root.acl_administer_queue": "*"
        "yarn.scheduler.capacity.root.default-node-label-expression": " "
        "yarn.scheduler.capacity.root.default.acl_administer_jobs": "*"
        "yarn.scheduler.capacity.root.default.acl_submit_applications": "*"
        "yarn.scheduler.capacity.root.default.capacity": "100"
        "yarn.scheduler.capacity.root.default.maximum-capacity": "100"
        "yarn.scheduler.capacity.root.default.state": "RUNNING"
        "yarn.scheduler.capacity.root.default.user-limit-factor": "1"
        "yarn.scheduler.capacity.root.queues": "default"
        "yarn.scheduler.capacity.queue-mappings": ""
        "yarn.scheduler.capacity.queue-mappings-override.enable": "false"
      mapred:
        user:
          limits:
            nproc: 16384
            nofile: 16384
          uid: 2404
          gid: "mapred"
          name: "mapred"
          system: true
          groups: "hadoop"
          comment: "Hadoop MapReduce User"
          home: "/var/lib/hadoop-mapreduce"
        site:
          "mapreduce.job.counters.max": "10000"
          "mapreduce.job.counters.limit": "10000"
          "yarn.app.mapreduce.am.resource.mb": 256
          "yarn.app.mapreduce.am.command-opts": "-Xmx204m"
          "mapreduce.map.memory.mb": "512"
          "mapreduce.reduce.memory.mb": "1024"
          "mapreduce.map.java.opts": "-Xmx409m"
          "mapreduce.reduce.java.opts": "-Xmx819m"
          "mapreduce.task.io.sort.mb": "204"
          "mapreduce.map.cpu.vcores": 1
          "mapreduce.reduce.cpu.vcores": 1
        group:
          gid: 2404
          name: "mapred"
          system: true
      hive:
        user:
          limits:
            nproc: 16384
            nofile: 16384
          uid: 2407
          gid: "hive"
          name: "hive"
          system: true
          groups: "hadoop"
          comment: "Hive User"
          home: "/var/lib/hive"
        site:
          "javax.jdo.option.ConnectionDriverName": "com.mysql.jdbc.Driver"
          "javax.jdo.option.ConnectionUserName": "hive"
          "javax.jdo.option.ConnectionPassword": "hive123"
          " hive.metastore.uris ": null
          " hive.cluster.delegation.token.store.class ": null
          "hive.metastore.local": null
          "fs.hdfs.impl.disable.cache": "false"
          "fs.file.impl.disable.cache": "false"
          "hive.server2.thrift.sasl.qop": "auth"
          "hive.metastore.sasl.enabled": "true"
          "hive.metastore.kerberos.keytab.file": "/etc/hive/conf/hive.service.keytab"
          "hive.metastore.kerberos.principal": "hive/_HOST@HADOOP.RYBA"
          "hive.metastore.cache.pinobjtypes": "Table,Database,Type,FieldSchema,Order"
          "hive.security.authorization.manager": "org.apache.hadoop.hive.ql.security.authorization.StorageBasedAuthorizationProvider"
          "hive.security.metastore.authorization.manager": "org.apache.hadoop.hive.ql.security.authorization.StorageBasedAuthorizationProvider"
          "hive.security.authenticator.manager": "org.apache.hadoop.hive.ql.security.ProxyUserAuthenticator"
          "hive.security.metastore.authenticator.manager": "org.apache.hadoop.hive.ql.security.HadoopDefaultMetastoreAuthenticator"
          "hive.metastore.pre.event.listeners": "org.apache.hadoop.hive.ql.security.authorization.AuthorizationPreEventListener"
          "hive.optimize.mapjoin.mapreduce": null
          "hive.heapsize": null
          "hive.auto.convert.sortmerge.join.noconditionaltask": null
          "hive.exec.max.created.files": "100000"
          "hive.metastore.uris": "thrift://master2.ryba:9083,thrift://master3.ryba:9083"
          "datanucleus.autoCreateTables": "true"
          "hive.security.authorization.enabled": "true"
          "javax.jdo.option.ConnectionURL": "jdbc:mysql://master3.ryba:3306/hive?createDatabaseIfNotExist=true"
          "hive.support.concurrency": "true"
          "hive.zookeeper.quorum": "master1.ryba:2181,master2.ryba:2181,master3.ryba:2181"
          "hive.enforce.bucketing": "true"
          "hive.exec.dynamic.partition.mode": "nonstrict"
          "hive.txn.manager": "org.apache.hadoop.hive.ql.lockmgr.DbTxnManager"
          "hive.txn.timeout": "300"
          "hive.txn.max.open.batch": "1000"
          "hive.compactor.initiator.on": "true"
          "hive.compactor.worker.threads": "1"
          "hive.compactor.worker.timeout": "86400L"
          "hive.compactor.cleaner.run.interval": "5000"
          "hive.compactor.check.interval": "300L"
          "hive.compactor.delta.num.threshold": "10"
          "hive.compactor.delta.pct.threshold": "0.1f"
          "hive.compactor.abortedtxn.threshold": "1000"
          "hive.cluster.delegation.token.store.class": "org.apache.hadoop.hive.thrift.DBTokenStore"
          "hive.exec.compress.intermediate": "true"
          "hive.auto.convert.join": "true"
          "hive.cli.print.header": "false"
          "hive.execution.engine": "tez"
          "hive.tez.container.size": 256
          "hive.tez.java.opts": "-Xmx204m"
          "hive.exec.reducers.bytes.per.reducer": "268435456"
          "hive.server2.authentication": "KERBEROS"
          "hive.server2.enable.doAs": "true"
          "hive.server2.allow.user.substitution": "true"
          "hive.server2.transport.mode": "http"
          "hive.server2.thrift.port": "10001"
          "hive.server2.thrift.http.port": "10001"
          "hive.server2.thrift.http.path": "cliservice"
          "hive.server2.logging.operation.log.location": "/tmp/hive/operation_logs"
          "hive.server2.tez.default.queues": "default"
          "hive.server2.tez.sessions.per.default.queue": "1"
          "hive.server2.tez.initialize.default.sessions": "false"
          "hive.server2.authentication.kerberos.keytab": "/etc/hive/conf/hive.service.keytab"
          "hive.server2.authentication.kerberos.principal": "hive/_HOST@HADOOP.RYBA"
          "hive.server2.authentication.spnego.principal": "HTTP/_HOST@HADOOP.RYBA"
          "hive.server2.authentication.spnego.keytab": "/etc/security/keytabs/spnego.service.keytab"
          "hive.server2.use.SSL": "true"
          "hive.server2.keystore.path": "/etc/conf/hive/keystore"
          "hive.server2.keystore.password": "ryba123"
          "hive.server2.support.dynamic.service.discovery": "true"
          "hive.zookeeper.session.timeout": "600000"
          "hive.server2.zookeeper.namespace": "hiveserver2"
        group:
          gid: 2407
          name: "hive"
          system: true
        conf_dir: "/etc/hive/conf"
        aux_jars: [
          "/usr/hdp/current/hive-webhcat/share/hcatalog/hive-hcatalog-core.jar"
        ]
        hcatalog:
          log_dir: "/var/log/hive-hcatalog"
          pid_dir: "/var/run/hive-hcatalog"
          opts: ""
          heapsize: 1024
        libs: []
        client:
          opts: ""
          heapsize: 1024
          truststore_location: "/etc/hive/conf/truststore"
          truststore_password: "ryba123"
        server2:
          conf_dir: "/etc/conf/hive"
          log_dir: "/var/log/hive-server2"
          pid_dir: "/var/run/hive-server2"
          opts: ""
          heapsize: 1024
      hue:
        ini:
          desktop:
            smtp:
              host: ""
            database:
              engine: "mysql"
              password: "hue123"
        ssl:
          certificate: "/home/pierrotws/workspace/ryba-cluster/conf/certs/master3_cert.pem"
          private_key: "/home/pierrotws/workspace/ryba-cluster/conf/certs/master3_key.pem"
          client_ca: "/home/pierrotws/workspace/ryba-cluster/conf/certs/cacert.pem"
        group:
          gid: 2410
        user:
          uid: 2410
          gid: 2410
      sqoop:
        libs: []
        user:
          uid: 2412
          gid: 2400
      hbase:
        regionserver_opts: "-Xmx512m"
        admin:
          password: "hbase123"
          name: "hbase"
          principal: "hbase@HADOOP.RYBA"
        metrics:
          "*.sink.file.class": "org.apache.hadoop.metrics2.sink.FileSink"
          sinks:
            file: true
            ganglia: false
            graphite: false
          config:
            "*.period": "60"
            "*.sink.file.class": "org.apache.hadoop.metrics2.sink.FileSink"
            "*.sink.file.filename": "metrics.out"
            "hbase.sink.file.filename": "hbase-metrics.out"
        group:
          gid: 2409
          name: "hbase"
          system: true
        user:
          uid: 2409
          gid: "hbase"
          name: "hbase"
          system: true
          comment: "HBase User"
          home: "/var/run/hbase"
          groups: "hadoop"
          limits:
            nofile: 64000
            nproc: true
        test:
          default_table: "ryba"
        conf_dir: "/etc/hbase/conf"
        log_dir: "/var/log/hbase"
        pid_dir: "/var/run/hbase"
        site:
          "zookeeper.znode.parent": "/hbase"
          "hbase.cluster.distributed": "true"
          "hbase.rootdir": "hdfs://torval:8020/apps/hbase/data"
          "hbase.zookeeper.quorum": "master1.ryba,master2.ryba,master3.ryba"
          "hbase.zookeeper.property.clientPort": "2181"
          "dfs.domain.socket.path": "/var/lib/hadoop-hdfs/dn_socket"
          "hbase.security.authentication": "kerberos"
          "hbase.security.authorization": "true"
          "hbase.rpc.engine": "org.apache.hadoop.hbase.ipc.SecureRpcEngine"
          "hbase.superuser": "hbase"
          "hbase.bulkload.staging.dir": "/apps/hbase/staging"
          "hbase.regionserver.storefile.refresh.all": "true"
          "hbase.regionserver.storefile.refresh.period": "30000"
          "hbase.region.replica.replication.enabled": "true"
          "hbase.master.hfilecleaner.ttl": "3600000"
          "hbase.master.loadbalancer.class": "org.apache.hadoop.hbase.master.balancer.StochasticLoadBalancer"
          "hbase.meta.replica.count": "3"
          "hbase.region.replica.wait.for.primary.flush": "true"
          "hbase.region.replica.storefile.refresh.memstore.multiplier": "4"
          "hbase.table.sanity.checks": "true"
          "hbase.defaults.for.version.skip": "true"
          "phoenix.functions.allowUserDefinedFunctions": "true"
          "hbase.rpc.controllerfactory.class": "org.apache.hadoop.hbase.ipc.controller.ServerRpcControllerFactory"
          "hbase.master.port": "60000"
          "hbase.master.info.port": "60010"
          "hbase.master.info.bindAddress": "0.0.0.0"
          "hbase.ssl.enabled": "true"
          "hbase.master.keytab.file": "/etc/security/keytabs/hm.service.keytab"
          "hbase.master.kerberos.principal": "hbase/_HOST@HADOOP.RYBA"
          "hbase.regionserver.kerberos.principal": "hbase/_HOST@HADOOP.RYBA"
          "hbase.coprocessor.master.classes": "org.apache.hadoop.hbase.security.access.AccessController"
          "hadoop.proxyuser.hbase_rest.groups": "*"
          "hadoop.proxyuser.hbase_rest.hosts": "*"
        env:
          JAVA_HOME: "/usr/lib/jvm/java"
          HBASE_LOG_DIR: "/var/log/hbase"
          HBASE_OPTS: "-ea -XX:+UseConcMarkSweepGC -XX:+CMSIncrementalMode"
          HBASE_MASTER_OPTS: "-Xmx2048m -Djava.security.auth.login.config=/etc/hbase/conf/hbase-master.jaas"
          HBASE_REGIONSERVER_OPTS: "-Xmn200m -Xms4096m -Xmx4096m"
        master_opts: "-Xmx2048m -Djava.security.auth.login.config=/etc/hbase/conf/hbase-master.jaas"
        log4j: {}
      kafka:
        broker:
          heapsize: 128
          "log.dirs": [
            "/data/1/kafka"
            "/data/2/kafka"
          ]
          conf_dir: "/etc/kafka-broker/conf"
          config:
            "log.dirs": "/data/1/kafka,/data/2/kafka"
            "zookeeper.connect": [
              "master1.ryba:2181"
              "master2.ryba:2181"
              "master3.ryba:2181"
            ]
            "log.retention.hours": "168"
            "super.users": "User:kafka"
            "num.partitions": 3
            "broker.id": "1"
            "ssl.keystore.location": "/etc/kafka-broker/conf/keystore"
            "ssl.keystore.password": "ryba123"
            "ssl.key.password": "ryba123"
            "ssl.truststore.location": "/etc/kafka-broker/conf/truststore"
            "ssl.truststore.password": "ryba123"
            "sasl.kerberos.service.name": "kafka"
            "allow.everyone.if.no.acl.found": "true"
            "zookeeper.set.acl": true
            listeners: "SASL_SSL://master2.ryba:9096"
            "replication.security.protocol": "SASL_SSL"
          env:
            KAFKA_HEAP_OPTS: "-Xmx128m -Xms128m"
            KAFKA_LOG4J_OPTS: "-Dlog4j.configuration=file:$base_dir/../config/log4j.properties"
            KAFKA_KERBEROS_PARAMS: "-Djava.security.auth.login.config=/etc/kafka-broker/conf/kafka-server.jaas"
          log4j:
            "log4j.rootLogger": "INFO, kafkaAppender"
            "log4j.additivity.kafka": "false"
          protocols: [
            "SASL_SSL"
          ]
          kerberos:
            principal: "kafka/master2.ryba@HADOOP.RYBA"
            keyTab: "/etc/security/keytabs/kafka.service.keytab"
        group:
          gid: 2424
          name: "kafka"
          system: true
        user:
          uid: 2424
          gid: "kafka"
          name: "kafka"
          system: true
          comment: "Kafka User"
          home: "/var/lib/kafka"
        admin:
          principal: "kafka"
          password: "kafka123"
        superusers: [
          "kafka"
        ]
        ports:
          PLAINTEXT: "9092"
          SSL: "9093"
          SASL_PLAINTEXT: "9094"
          SASL_SSL: "9096"
      opentsdb:
        version: "2.2.0RC3"
        group:
          gid: 2428
        user:
          uid: 2428
          gid: 2428
      nagios:
        users:
          nagiosadmin:
            password: "nagios123"
            alias: "Nagios Admin"
            email: ""
          guest:
            password: "guest123"
            alias: "Nagios Guest"
            email: ""
        groups:
          admins:
            alias: "Nagios Administrators"
            members: [
              "nagiosadmin"
              "guest"
            ]
        group:
          gid: 2418
        groupcmd:
          gid: 2419
        user:
          uid: 2418
          gid: 2418
      hadoop_group:
        gid: 2400
        name: "hadoop"
        system: true
      group:
        gid: 2414
        name: "ryba"
        system: true
      user:
        uid: 2414
        gid: 2414
        name: "ryba"
        password: "password"
        system: true
        comment: "ryba User"
        home: "/home/ryba"
      zookeeper:
        group:
          gid: 2402
          name: "zookeeper"
          system: true
        user:
          uid: 2402
          gid: 2400
          name: "zookeeper"
          system: true
          groups: "hadoop"
          comment: "Zookeeper User"
          home: "/var/lib/zookeeper"
        conf_dir: "/etc/zookeeper/conf"
        log_dir: "/var/log/zookeeper"
        port: 2181
        env:
          JAVA_HOME: "/usr/lib/jvm/java"
          CLIENT_JVMFLAGS: "-Djava.security.auth.login.config=/etc/zookeeper/conf/zookeeper-client.jaas"
          ZOOKEEPER_HOME: "/usr/hdp/current/zookeeper-client"
          ZOO_AUTH_TO_LOCAL: "RULE:[1:\\$1]RULE:[2:\\$1]"
          ZOO_LOG_DIR: "/var/log/zookeeper"
          ZOOPIDFILE: "/var/run/zookeeper/zookeeper_server.pid"
          SERVER_JVMFLAGS: "-Xmx1024m -Djava.security.auth.login.config=/etc/zookeeper/conf/zookeeper-server.jaas -Dzookeeper.security.auth_to_local=$ZOO_AUTH_TO_LOCAL"
          JAVA: "$JAVA_HOME/bin/java"
          CLASSPATH: "$CLASSPATH:/usr/share/zookeeper/*"
          ZOO_LOG4J_PROP: "INFO,CONSOLE,ROLLINGFILE"
        pid_dir: "/var/run/zookeeper"
        log4j: {}
        config:
          maxClientCnxns: "200"
          tickTime: "2000"
          initLimit: "10"
          syncLimit: "5"
          dataDir: "/var/zookeeper/data/"
          clientPort: "2181"
          "server.1": "master1.ryba:2888:3888"
          "server.2": "master2.ryba:2888:3888"
          "server.3": "master3.ryba:2888:3888"
          "authProvider.1": "org.apache.zookeeper.server.auth.SASLAuthenticationProvider"
          jaasLoginRenew: "3600000"
          "kerberos.removeHostFromPrincipal": "true"
          "kerberos.removeRealmFromPrincipal": "true"
        myid: null
        retention: 3
        purge: "@weekly"
        superuser: {}
      flume:
        group:
          gid: 2405
        user:
          uid: 2405
          gid: 2405
      ganglia:
        rrdcached_group:
          gid: 2406
          name: "rrdcached"
          system: true
        rrdcached_user:
          uid: 2406
          gid: "rrdcached"
          name: "rrdcached"
          system: true
          shell: false
          comment: "RRDtool User"
          home: "/var/rrdtool/rrdcached"
        collector_port: 8649
        slaves_port: 8660
        hbase_region_port: 8660
        nn_port: 8661
        jt_port: 8662
        hm_port: 8663
        hbase_master_port: 8663
        rm_port: 8664
        jhs_port: 8666
        spark_port: 8667
      oozie:
        group:
          gid: 2411
        user:
          uid: 2411
          gid: 2411
      pig:
        user:
          uid: 2413
          gid: 2400
      knox:
        group:
          gid: 2420
        user:
          uid: 2420
          gid: 2420
      falcon:
        group:
          gid: 2421
        user:
          uid: 2421
          gid: 2421
      elasticsearch:
        group:
          gid: 2422
        user:
          uid: 2422
          gid: 2422
      rexster:
        group:
          gid: 2423
        user:
          uid: 2423
          gid: 2423
      presto:
        group:
          gid: 2425
        user:
          uid: 2425
          gid: 2425
      spark:
        group:
          gid: 2426
        user:
          uid: 2426
          gid: 2426
      httpfs:
        group:
          gid: 2427
          name: "httpfs"
          system: true
        user:
          uid: 2427
          gid: "httpfs"
          name: "httpfs"
          system: true
          comment: "HttpFS User"
          home: "/var/lib/httpfs"
          groups: "hadoop"
        pid_dir: "/var/run/httpfs"
        conf_dir: "/etc/hadoop-httpfs/conf"
        log_dir: "/var/log/hadoop-httpfs"
        tmp_dir: "/var/tmp/hadoop-httpfs"
        http_port: "14000"
        http_admin_port: "14001"
        catalina_home: "/etc/hadoop-httpfs/tomcat-deployment"
        catalina_opts: ""
        env:
          HTTPFS_SSL_ENABLED: "true"
          HTTPFS_SSL_KEYSTORE_FILE: "/etc/hadoop-httpfs/conf/keystore"
          HTTPFS_SSL_KEYSTORE_PASS: "ryba123"
        site:
          "httpfs.hadoop.config.dir": "/etc/hadoop/conf"
          "kerberos.realm": "HADOOP.RYBA"
          "httpfs.hostname": "master2.ryba"
          "httpfs.authentication.type": "kerberos"
          "httpfs.authentication.kerberos.principal": "HTTP/master2.ryba@HADOOP.RYBA"
          "httpfs.authentication.kerberos.keytab": "/etc/security/keytabs/spnego.service.keytab"
          "httpfs.hadoop.authentication.type": "kerberos"
          "httpfs.hadoop.authentication.kerberos.keytab": "/etc/security/keytabs/httpfs.service.keytab"
          "httpfs.hadoop.authentication.kerberos.principal": "httpfs/master2.ryba@HADOOP.RYBA"
          "httpfs.authentication.kerberos.name.rules": '''
            
            RULE:[2:$1@$0]([rn]m@HADOOP\\.RYBA)s/.*/yarn/
            RULE:[2:$1@$0](jhs@HADOOP\\.RYBA)s/.*/mapred/
            RULE:[2:$1@$0]([nd]n@HADOOP\\.RYBA)s/.*/hdfs/
            RULE:[2:$1@$0](hm@HADOOP\\.RYBA)s/.*/hbase/
            RULE:[2:$1@$0](rs@HADOOP\\.RYBA)s/.*/hbase/
            RULE:[2:$1@$0](opentsdb@HADOOP\\.RYBA)s/.*/hbase/
            DEFAULT
            RULE:[1:$1](yarn|mapred|hdfs|hive|hbase|oozie)s/.*/nobody/
            RULE:[2:$1](yarn|mapred|hdfs|hive|hbase|oozie)s/.*/nobody/
            RULE:[1:$1]
            RULE:[2:$1]
            
          '''
          "httpfs.proxyuser.knox.hosts": "front1.ryba"
          "httpfs.proxyuser.knox.groups": "*"
      nagvis:
        group:
          gid: 2429
        user:
          uid: 2429
          gid: 2429
      hdp_repo: false
      titan:
        source: "http://10.10.10.1/titan-0.5.4-hadoop2.zip"
      tez:
        site:
          "tez.am.resource.memory.mb": 256
          "tez.task.resource.memory.mb": "512"
          "tez.runtime.io.sort.mb": "204"
          "tez.lib.uris": "/hdp/apps/${hdp.version}/tez/tez.tar.gz"
          "hive.tez.java.opts": "-Xmx204m"
        env:
          TEZ_CONF_DIR: "/etc/tez/conf"
          TEZ_JARS: "/usr/hdp/current/tez-client/*:/usr/hdp/current/tez-client/lib/*"
          HADOOP_CLASSPATH: "$TEZ_CONF_DIR:$TEZ_JARS:$HADOOP_CLASSPATH"
      graphite:
        carbon_port: 2023
        carbon_cache_port: 2003
        carbon_aggregator_port: 2023
        metrics_prefix: "hadoop"
        carbon_rewrite_rules: [
          "[pre]"
          "^(?P<cluster>w+).hbase.[a-zA-Z0-9_.,:;-=]*Context=(?P<context>w+).Hostname=(?P<host>w+).(?P<metric>.w+)*$ = g<cluster>.g<host>.hbase.g<context>g<metric>"
          "^(?P<cluster>w+).(?P<bean>w+).(?P<foobar>w+).Hostname=(?P<host>w+).(?P<metric>.w+)*$ = g<cluster>.g<host>.g<foobar>g<metric>"
          "^(?P<cluster>w+).(?P<bean>w+).[a-zA-Z0-9_.=]*port=(?P<port>w+).Context=(?P<context>w+).[a-zA-Z0-9_.=]*Hostname=(?P<host>w+).(?P<metric>.w+)*$ = g<cluster>.g<host>.g<context>.g<port>g<metric>"
          "^(?P<cluster>w+).(?P<bean>w+).[a-zA-Z0-9_.=]*Queue=root(?P<queue>.w+\b)*.Context=(?P<context>w+).[a-zA-Z0-9_.=]*Hostname=(?P<host>w+).(?P<metric>.w+)*$ = g<cluster>.g<host>.g<context>.queue.g<queue>g<metric>"
          "^(?P<cluster>w+).(?P<bean>w+).[a-zA-Z0-9_.=]*Context=(?P<context>w+).ProcessName=(?P<process>w+).[a-zA-Z0-9_.=]*Hostname=(?P<host>w+).(?P<metric>.w+)*$ = g<cluster>.g<host>.g<context>.g<process>g<metric>"
          "^(?P<cluster>w+).(?P<bean>w+).[a-zA-Z0-9_.=]*Context=(?P<context>w+).[a-zA-Z0-9_.=]*Hostname=(?P<host>w+).(?P<metric>.w+)*$ = g<cluster>.g<host>.g<context>g<metric>"
          "rpcdetailed = rpc"
        ]
        carbon_conf: [
          "[aggregator]"
          "LINE_RECEIVER_INTERFACE = 0.0.0.0"
          "LINE_RECEIVER_PORT = 2023"
          "PICKLE_RECEIVER_INTERFACE = 0.0.0.0"
          "PICKLE_RECEIVER_PORT = 2024"
          "LOG_LISTENER_CONNECTIONS = True"
          "FORWARD_ALL = True"
          "DESTINATIONS = 127.0.0.1:2004"
          "REPLICATION_FACTOR = 1"
          "MAX_QUEUE_SIZE = 10000"
          "USE_FLOW_CONTROL = True"
          "MAX_DATAPOINTS_PER_MESSAGE = 500"
          "MAX_AGGREGATION_INTERVALS = 5"
          "# WRITE_BACK_FREQUENCY = 0"
        ]
      proxy: null
      db_admin:
        engine: "mysql"
        host: "master3.ryba"
        path: "mysql"
        port: "3306"
        username: "root"
        password: "test123"
      hadoop_conf_dir: "/etc/hadoop/conf"
      hadoop_lib_home: "/usr/hdp/current/hadoop-client/lib"
      active_nn: false
      standby_nn_host: "master2.ryba"
      static_host: "_HOST"
      active_nn_host: "master1.ryba"
      core_jars: {}
      hadoop_classpath: ""
      hadoop_client_opts: "-Xmx2048m"
      hadoop_policy: {}
      ssl_client:
        "ssl.client.truststore.location": "/etc/hadoop/conf/truststore"
        "ssl.client.truststore.password": "ryba123"
        "ssl.client.truststore.type": "jks"
      ssl_server:
        "ssl.server.keystore.location": "/etc/hadoop/conf/keystore"
        "ssl.server.keystore.password": "ryba123"
        "ssl.server.keystore.type": "jks"
        "ssl.server.keystore.keypassword": "ryba123"
        "ssl.server.truststore.location": "/etc/hadoop/conf/truststore"
        "ssl.server.truststore.password": "ryba123"
        "ssl.server.truststore.type": "jks"
    httpd:
      user:
        uid: 2416
        gid: 2416
      group:
        gid: 2416
    xasecure:
      group:
        gid: 2417
      user:
        uid: 2417
        gid: 2417
    proxy:
      system: false
      system_file: "/etc/profile.d/phyla_proxy.sh"
      host: null
      port: null
      username: null
      password: null
      secure: null
      http_proxy: null
      https_proxy: null
      http_proxy_no_auth: null
      https_proxy_no_auth: null
    curl:
      check: false
      config:
        noproxy: "localhost,127.0.0.1,.ryba"
        proxy: null
      merge: true
      users: true
      proxy: true
      check_match: {}
    profile:
      "proxy.sh": ""
    ntp:
      servers: [
        "master3.ryba"
      ]
      fudge: 14
      lag: 2000
    hdp:
      hue_smtp_host: ""
    ambari: {}
    ip: "10.10.10.12"
    modules: [
      "masson/core/reload"
      "masson/core/fstab"
      "masson/core/network"
      "masson/core/network_check"
      "masson/core/users"
      "masson/core/ssh"
      "masson/core/ntp"
      "masson/core/proxy"
      "masson/core/yum"
      "masson/core/security"
      "masson/core/iptables"
      "masson/core/krb5_client"
      "masson/core/sssd"
      "ryba/zookeeper/server"
      "ryba/hadoop/hdfs_jn"
      "ryba/hadoop/hdfs_nn"
      "ryba/hadoop/zkfc"
      "ryba/hadoop/httpfs"
      "ryba/hadoop/yarn_rm"
      "ryba/phoenix/master"
      "ryba/hbase/master"
      "ryba/hive/hcatalog"
      "ryba/hive/server2"
      "ryba/kafka/broker"
    ]
    host: "master2.ryba"
    shortname: "master2"
    metrics_sinks:
      file:
        class: "org.apache.hadoop.metrics2.sink.FileSink"
        filename: "metrics.out"
      ganglia:
        class: "org.apache.hadoop.metrics2.sink.ganglia.GangliaSink31"
        period: "10"
        supportparse: "true"
        slope: "jvm.metrics.gcCount=zero,jvm.metrics.memHeapUsedM=both"
        dmax: "jvm.metrics.threadsBlocked=70,jvm.metrics.memHeapUsedM=40"
      graphite:
        class: "org.apache.hadoop.metrics2.sink.GraphiteSink"
        period: "10"
    hostname: "master2.ryba"
    groups: {}
    fstab:
      enabled: false
      exhaustive: false
      volumes: {}
  "master3.ryba":
    connection:
      private_key: '''
        -----BEGIN RSA PRIVATE KEY-----
        MIIEogIBAAKCAQEArBDFt50aN9jfIJ629pRGIMA1fCMb9RyTHt9A+jx3FOsIOtJs
        eaBIpv98drbFVURr+cUs/CrgGVk5k2NIeiz0bG4ONV5nTwx38z5CzqLb7UryZS3i
        a/TS14fWOxvWTRR27R71ePX90G/ZIReKFeTrucw9y9Pl+xAzsmeblRwLBxv/SWBX
        Uai2mHAZaejlG9dGkn9f2n+oPmbgk6krLMCjLhlNBnkdroBNSXGA9ewLPFF4y54Q
        kBqmG3eLzCqAKAzwyJ5PpybtNGAWfN81gY/P5LBzC66WdtEzpwsYAv1wCioqggtg
        xVZN2s0ajxQrCxahRkXstBI2IDcm2qUTxaDbUwIDAQABAoIBAFruOi7AvXxKBhCt
        D6/bx/vC2AEUZM/yG+Wywhn8HkpVsvGzBlR4Wiy208XA7SQUlqNWimFxHyEGQCEd
        1M2MOFedCbE2hI4H3tQTUSb2dhc/Bj5mM0QuC8aPKK3wFh6B9B93vu3/wfSHR03v
        rK/JXLHBt96hyuYVN9zOWDBCs6k7SdQ2BcsQLiPg6feTsZelJDuO+DO65kKLMiz3
        mNPThErklRaKovNk47LSYakk6gsJXrpG6JWQ6nwsRenwplDwZ8Zs9mlRi7f3nChM
        3I1WlISN8y2kcQBQ94YZKk8wzH/lzmxsabcLa5ETNubxQ6ThDu1oYUIIUsQyNPm+
        DkW0VwECgYEA5MttelspKexWS39Y3sQYvZ/v8VZBQl4tRbpUWWc+PNEtcEwOBza/
        H4jBWYd2eWKTApJT1st58E4b34Mv88nQVElLb3sE7uJMkihPyNpABGbCvr63hDYw
        PyL53nKaPelY/aDnL0F8LmREfdKw/uy6+UChgkPfdo2VVk1oyvsZaRMCgYEAwIZ+
        lCmeXQ4mU6uxO+ChhDn7zw9rR5qlCyfJiLPe2lV20vaHV5ZfKIWGegsVJSpFr2ST
        5ghh+FVIneoNRtTHEKwNWCK7I6qeF+WAaci+KsLQigJQHsw58n9cdA7wHHc475n/
        pf7efoPcvk6qYOS2mpDgC87m+o3C4Dyspqp9TMECgYA4/ed+dBjT5Zg1ZDp5+zUC
        f0Wgw1CsPJNgbCK4xnv9YEnGUFuqNlvzefhX2eOMJx7hpBuYRMVSM9LDoYUfYCUx
        6bQNyAIZk2tpePsu2BbcQdC+/PjvySPJhmfhnoCHbYoKW7tazSAm2jkpcoM+bS/C
        CPRyY3/Voz0Q62VwMo5I2wKBgB4mMbZUGieqapgZwASHdeO2DNftKzioYAYyMd5F
        hLWeQqBg2Or/cmFvH5MHH0WVrBn+Xybb0zPHbzrDh1a7RX035FMUBUhdlKpbV1O5
        iwY5Qd0K5a8c/koaZckK+dELXpAvBpjhI8ieL7hhq07HIk1sOJnAye0cvBLPjZ3/
        /uVBAoGAVAs6tFpS0pFlxmg4tfGEm7/aP6FhyBHNhv2QGluw8vv/XVMzUItxGIef
        HcSMWBm08IJMRJLgmoo1cuQv6hBui7JpDeZk/20qoF2oZW9lJ9fdRObJqi61wufP
        BNiriqexq/eTy2uF9RCCjLItWxUscVMlVt4V65HLkCF5WxCQw+o=
        -----END RSA PRIVATE KEY-----
      '''
      public_key: "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCsEMW3nRo32N8gnrb2lEYgwDV8Ixv1HJMe30D6PHcU6wg60mx5oEim/3x2tsVVRGv5xSz8KuAZWTmTY0h6LPRsbg41XmdPDHfzPkLOotvtSvJlLeJr9NLXh9Y7G9ZNFHbtHvV49f3Qb9khF4oV5Ou5zD3L0+X7EDOyZ5uVHAsHG/9JYFdRqLaYcBlp6OUb10aSf1/af6g+ZuCTqSsswKMuGU0GeR2ugE1JcYD17As8UXjLnhCQGqYbd4vMKoAoDPDInk+nJu00YBZ83zWBj8/ksHMLrpZ20TOnCxgC/XAKKiqCC2DFVk3azRqPFCsLFqFGRey0EjYgNybapRPFoNtT Ryba Hadoop"
      bootstrap:
        username: "vagrant"
        password: "vagrant"
        host: "10.10.10.13"
        port: 22
        cmd: "su -"
        retry: 3
      username: "root"
      host: "10.10.10.13"
      port: 22
      private_key_location: "~/.ssh/id_rsa"
      retry: 3
      end: true
      wait: 1000
    mecano:
      cache_dir: "/home/pierrotws/workspace/ryba-cluster/conf/../resources/cache"
      log_serializer: true
    log:
      archive: true
      disabled: false
      basedir: "./log"
      fqdn_reversed: "ryba.master3"
      filename: "master3.log"
      elasticsearch:
        enable: false
        url: "http://localhost:9200"
        index: "masson"
    security:
      selinux: false
      limits: {}
    network:
      hosts_auto: true
      hosts:
        "127.0.0.1": "localhost localhost.localdomain localhost4 localhost4.localdomain4"
        "10.10.10.10": "repos.ryba ryba"
      resolv: '''
        search ryba
        nameserver 10.10.10.13
        nameserver 10.0.2.3
      '''
      hostname_disabled: false
    iptables:
      action: "stop"
      startup: false
      log: true
      rules: []
      log_prefix: "IPTables-Dropped: "
      log_level: 4
      log_rules: [
        {
          chain: "INPUT"
          command: "-A"
          jump: "LOGGING"
        }
        {
          chain: "LOGGING"
          command: "-A"
          "--limit": "2/min"
          jump: "LOG"
          "log-prefix": "IPTables-Dropped: "
          "log-level": 4
        }
        {
          chain: "LOGGING"
          command: "-A"
          jump: "DROP"
        }
      ]
    bind_server:
      zones: [
        "/home/pierrotws/workspace/ryba-cluster/conf/zones/ryba"
        "/home/pierrotws/workspace/ryba-cluster/conf/zones/10.10.10.in-addr.arpa"
      ]
      user:
        uid: 802
        gid: "named"
        name: "named"
        system: true
        shell: false
        comment: "Named"
        home: "/var/named"
      group:
        gid: 802
        name: "named"
        system: true
    ssh:
      banner:
        destination: "/etc/banner"
        content: "Welcome to Hadoop!"
      sshd_config:
        PermitRootLogin: "without-password"
    users:
      root:
        authorized_keys: [
          "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCWvEjSt2sAvRmkpkt9+u1EXuFDWJSuI1C8G/+NMcpMRDSUTary3Njqt/DC5mx7X36mVJdaq2KqgAVa28zzeuN6Yv7iuxCTw/4K7OKXYu+q0UG8BlIknWgLa8s7Nx2J69Prkb4oFgzw5IqK9EM6VMarUJUCXVNhb3zmamrF59OIxAIyQhV5i5SzoAxLIcD9EtxS/ZRf9t9fOBEhn42SVcpEWO09bUHZ11J2tw/Pwsxk+va83cH9qipVsEwIMDUCosfzV1G2zF5HhU/mhIHWRdAULpaRfd3IgNqTtI6BBi6FOFbJdrkHXPXKRybZwCxChncq1TZI2SXx6BCRpoJ/s887 m.sauvage.pierre@gmail.com"
        ]
        name: "root"
        home: "/root"
    yum:
      packages:
        tree: true
        git: true
        htop: true
        vim: true
        "yum-plugin-priorities": true
        man: true
        ksh: true
      config:
        proxy: null
        main:
          keepcache: "0"
          proxy: null
          proxy_username: null
          proxy_password: null
      copy: "/home/pierrotws/workspace/ryba-cluster/conf/user/offline/*.repo"
      clean: false
      merge: true
      update: true
      proxy: true
      epel: true
      epel_url: "http://download.fedoraproject.org/pub/epel/6/i386/epel-release-6-8.noarch.rpm"
    mysql:
      server:
        current_password: ""
        password: "test123"
        my_cnf:
          mysqld:
            innodb_file_per_table: "1"
            tmpdir: "/tmp/mysql"
        sql_on_install: []
        remove_anonymous: true
        disallow_remote_root_login: false
        remove_test_db: true
        reload_privileges: true
      user:
        name: "mysql"
      group:
        name: "mysql"
    openldap_server:
      suffix: "dc=ryba"
      root_dn: "cn=Manager,dc=ryba"
      root_password: "test"
      config_dn: "cn=admin,cn=config"
      config_password: "test"
      users_dn: "ou=users,dc=ryba"
      groups_dn: "ou=groups,dc=ryba"
      ldapdelete: []
      ldapadd: []
      tls: true
      tls_ca_cert_file: "/home/pierrotws/workspace/ryba-cluster/conf/certs/cacert.pem"
      tls_cert_file: "/home/pierrotws/workspace/ryba-cluster/conf/certs/master3_cert.pem"
      tls_key_file: "/home/pierrotws/workspace/ryba-cluster/conf/certs/master3_key.pem"
      proxy_user:
        uidNumber: 801
        gidNumber: 801
        dn: "cn=nssproxy,ou=users,dc=ryba"
        uid: "nssproxy"
        gecos: "Network Service Switch Proxy User"
        objectClass: [
          "top"
          "account"
          "posixAccount"
          "shadowAccount"
        ]
        userPassword: "test"
        shadowLastChange: "15140"
        shadowMin: "0"
        shadowMax: "99999"
        shadowWarning: "7"
        loginShell: "/bin/false"
        homeDirectory: "/home/nssproxy"
      proxy_group:
        gidNumber: 801
        dn: "cn=nssproxy,ou=groups,dc=ryba"
        objectClass: [
          "top"
          "posixGroup"
        ]
        description: "Network Service Switch Proxy"
      log_level: 256
      config_file: "/etc/openldap/slapd.d/cn=config/olcDatabase={0}config.ldif"
      monitor_file: "/etc/openldap/slapd.d/cn=config/olcDatabase={1}monitor.ldif"
      bdb_file: "/etc/openldap/slapd.d/cn=config/olcDatabase={2}bdb.ldif"
      uri: "ldaps://master3.ryba"
    openldap_client:
      certificates: [
        "/home/pierrotws/workspace/ryba-cluster/conf/certs/master3_cert.pem"
      ]
      config:
        BASE: "dc=ryba"
        URI: "ldaps://master3.ryba"
        TLS_CACERTDIR: "/etc/openldap/cacerts"
        TLS_REQCERT: "allow"
        TIMELIMIT: "15"
        TIMEOUT: "20"
      suffix: "dc=ryba"
      root_dn: "cn=Manager,dc=ryba"
      root_password: "test"
    openldap_server_krb5:
      manager_dn: "cn=Manager,dc=ryba"
      manager_password: "test"
      krbadmin_user:
        dn: "cn=krbadmin,ou=users,dc=ryba"
        objectClass: [
          "top"
          "inetOrgPerson"
          "organizationalPerson"
          "person"
          "posixAccount"
        ]
        givenName: "Kerberos Administrator"
        mail: "david@adaltas.com"
        sn: "krbadmin"
        uid: "krbadmin"
        uidNumber: 800
        gidNumber: 800
        homeDirectory: "/home/krbadmin"
        loginShell: "/bin/false"
        displayname: "Kerberos Administrator"
        userPassword: "test"
      krbadmin_group:
        dn: "cn=krbadmin,ou=groups,dc=ryba"
        objectClass: [
          "top"
          "posixGroup"
        ]
        gidNumber: 800
        description: "Kerberos administrator's group."
      kerberos_dn: "ou=kerberos,dc=ryba"
      kdc_user:
        dn: "cn=krbadmin,ou=users,dc=ryba"
        objectClass: [
          "top"
          "inetOrgPerson"
          "organizationalPerson"
          "person"
          "posixAccount"
        ]
        givenName: "Kerberos Administrator"
        mail: "kerberos.admin@company.com"
        sn: "krbadmin"
        uid: "krbadmin"
        uidNumber: "800"
        gidNumber: "800"
        homeDirectory: "/home/krbadmin"
        loginShell: "/bin/false"
        displayname: "Kerberos Administrator"
        userPassword: "test"
    krb5:
      etc_krb5_conf:
        logging:
          default: "SYSLOG:INFO:LOCAL1"
          kdc: "SYSLOG:NOTICE:LOCAL1"
          admin_server: "SYSLOG:WARNING:LOCAL1"
        libdefaults:
          dns_lookup_realm: false
          dns_lookup_kdc: false
          ticket_lifetime: "24h"
          renew_lifetime: "7d"
          forwardable: true
          allow_weak_crypto: "false"
          clockskew: "300"
          rdns: "false"
          default_realm: "HADOOP.RYBA"
        realms:
          "USERS.RYBA":
            kadmin_principal: "wdavidw/admin@USERS.RYBA"
            kadmin_password: "test"
            principals: [
              {
                principal: "krbtgt/HADOOP.RYBA@USERS.RYBA"
                password: "test"
              }
            ]
            kdc: [
              "master3.ryba"
            ]
            admin_server: "master3.ryba"
            default_domain: "users.ryba"
          "HADOOP.RYBA":
            kadmin_principal: "wdavidw/admin@HADOOP.RYBA"
            kadmin_password: "test"
            principals: [
              {
                principal: "krbtgt/HADOOP.RYBA@USERS.RYBA"
                password: "test"
              }
            ]
            kdc: [
              "master1.ryba"
            ]
            admin_server: "master1.ryba"
            default_domain: "hadoop.ryba"
        domain_realm:
          ryba: "HADOOP.RYBA"
        appdefaults:
          pam:
            debug: false
            ticket_lifetime: 36000
            renew_lifetime: 36000
            forwardable: true
            krb4_convert: false
        dbmodules: {}
      kdc_conf:
        realms:
          "USERS.RYBA":
            max_life: "10h 0m 0s"
            max_renewable_life: "7d 0h 0m 0s"
            master_key_type: "aes256-cts-hmac-sha1-96"
            default_principal_flags: "+preauth"
            acl_file: "/var/kerberos/krb5kdc/kadm5.acl"
            dict_file: "/usr/share/dict/words"
            admin_keytab: "/var/kerberos/krb5kdc/kadm5.keytab"
            supported_enctypes: "aes256-cts-hmac-sha1-96:normal aes128-cts-hmac-sha1-96:normal des3-hmac-sha1:normal arcfour-hmac-md5:normal"
            database_module: "openldap_master3"
            principals: []
        dbmodules:
          openldap_master3:
            db_library: "kldap"
            ldap_kerberos_container_dn: "ou=kerberos,dc=ryba"
            ldap_kdc_dn: "cn=krbadmin,ou=users,dc=ryba"
            ldap_kdc_password: "test"
            ldap_kadmind_dn: "cn=krbadmin,ou=users,dc=ryba"
            ldap_kadmind_password: "test"
            ldap_service_password_file: "/etc/krb5.d/openldap_master3.stash.keyfile"
            ldap_servers: "ldap://master3.ryba"
            ldap_conns_per_server: 5
            manager_dn: "cn=Manager,dc=ryba"
            manager_password: "test"
            kdc_master_key: "test"
        kdcdefaults:
          kdc_ports: "88"
          kdc_tcp_ports: "88"
        logging:
          kdc: "FILE:/var/log/kdc.log"
      sshd: {}
      kinit: "/usr/bin/kinit"
    sssd:
      force_check: false
      certificates: [
        "/home/pierrotws/workspace/ryba-cluster/conf/certs/cacert.pem"
      ]
      config:
        sssd:
          config_file_version: "2"
          reconnection_retries: "3"
          sbus_timeout: "30"
          services: "nss, pam"
          debug_level: "1"
          domains: "hadoop,users"
        nss:
          filter_groups: "root"
          filter_users: "root"
          reconnection_retries: "3"
          entry_cache_timeout: "300"
          entry_cache_nowait_percentage: "75"
          debug_level: "1"
        pam:
          reconnection_retries: "3"
          offline_credentials_expiration: "2"
          offline_failed_login_attempts: "3"
          offline_failed_login_delay: "5"
          debug_level: "1"
        "domain/hadoop":
          debug_level: "1"
          cache_credentials: "True"
          ldap_search_base: "ou=users,dc=ryba"
          ldap_group_search_base: "ou=groups,dc=ryba"
          id_provider: "ldap"
          auth_provider: "ldap"
          chpass_provider: "ldap"
          ldap_uri: "ldaps://master3.ryba:636"
          ldap_tls_cacertdir: "/etc/openldap/cacerts"
          ldap_default_bind_dn: "cn=Manager,dc=ryba"
          ldap_default_authtok: "test"
          ldap_id_use_start_tls: "True"
        "domain/users":
          debug_level: "1"
          cache_credentials: "True"
          ldap_search_base: "ou=users,dc=ryba"
          ldap_group_search_base: "ou=groups,dc=ryba"
          id_provider: "ldap"
          auth_provider: "ldap"
          chpass_provider: "ldap"
          ldap_uri: "ldaps://master3.ryba:636"
          ldap_tls_cacertdir: "/etc/openldap/cacerts"
          ldap_default_bind_dn: "cn=Manager,dc=ryba"
          ldap_default_authtok: "test"
          ldap_id_use_start_tls: "False"
      merge: false
      test_user: null
    java:
      java_home: "/usr/lib/jvm/java"
      jre_home: "/usr/lib/jvm/java/jre"
      proxy: null
      openjdk: true
    ryba:
      clean_logs: true
      force_check: false
      check_hdfs_fsck: false
      security: "kerberos"
      realm: "HADOOP.RYBA"
      nameservice: "torval"
      krb5_user:
        password: "test123"
        password_sync: true
        principal: "ryba@HADOOP.RYBA"
      ssl:
        cacert: "/home/pierrotws/workspace/ryba-cluster/conf/certs/cacert.pem"
        cert: "/home/pierrotws/workspace/ryba-cluster/conf/certs/master3_cert.pem"
        key: "/home/pierrotws/workspace/ryba-cluster/conf/certs/master3_key.pem"
      ambari:
        repo: "/home/pierrotws/workspace/ryba-cluster/conf/resources/repos/ambari-2.0.0.repo"
      ssh_fencing:
        private_key: "/home/pierrotws/workspace/ryba-cluster/conf/hdfs_keys/id_rsa"
        public_key: "/home/pierrotws/workspace/ryba-cluster/conf/hdfs_keys/id_rsa.pub"
      hadoop_opts: "-Djava.net.preferIPv4Stack=true -Dsun.security.krb5.debug=false"
      core_site:
        "hadoop.ssl.exclude.cipher.suites": "SSL_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA,SSL_RSA_EXPORT_WITH_DES40_CBC_SHA,SSL_RSA_EXPORT_WITH_RC4_40_MD5,TLS_DHE_RSA_WITH_AES_128_CBC_SHA,TLS_DHE_RSA_WITH_AES_256_CBC_SHA"
        "io.compression.codecs": "org.apache.hadoop.io.compress.GzipCodec,org.apache.hadoop.io.compress.DefaultCodec,org.apache.hadoop.io.compress.SnappyCodec"
        "fs.defaultFS": "hdfs://torval:8020"
        "hadoop.security.authentication": "kerberos"
        "hadoop.security.authorization": "true"
        "hadoop.rpc.protection": "authentication"
        "hadoop.security.group.mapping": "org.apache.hadoop.security.JniBasedUnixGroupsMappingWithFallback"
        "ha.zookeeper.quorum": [
          "master1.ryba:2181"
          "master2.ryba:2181"
          "master3.ryba:2181"
        ]
        "net.topology.script.file.name": "/etc/hadoop/conf/rack_topology.sh"
        "hadoop.http.filter.initializers": "org.apache.hadoop.security.AuthenticationFilterInitializer"
        "hadoop.http.authentication.type": "kerberos"
        "hadoop.http.authentication.token.validity": "36000"
        "hadoop.http.authentication.signature.secret.file": "/etc/hadoop/hadoop-http-auth-signature-secret"
        "hadoop.http.authentication.simple.anonymous.allowed": "false"
        "hadoop.http.authentication.kerberos.principal": "HTTP/_HOST@HADOOP.RYBA"
        "hadoop.http.authentication.kerberos.keytab": "/etc/security/keytabs/spnego.service.keytab"
        "hadoop.http.authentication.cookie.domain": "ryba"
        "hadoop.security.auth_to_local": '''
          
          RULE:[2:$1@$0]([rn]m@HADOOP\\.RYBA)s/.*/yarn/
          RULE:[2:$1@$0](jhs@HADOOP\\.RYBA)s/.*/mapred/
          RULE:[2:$1@$0]([nd]n@HADOOP\\.RYBA)s/.*/hdfs/
          RULE:[2:$1@$0](hm@HADOOP\\.RYBA)s/.*/hbase/
          RULE:[2:$1@$0](rs@HADOOP\\.RYBA)s/.*/hbase/
          RULE:[2:$1@$0](opentsdb@HADOOP\\.RYBA)s/.*/hbase/
          DEFAULT
          RULE:[1:$1](yarn|mapred|hdfs|hive|hbase|oozie)s/.*/nobody/
          RULE:[2:$1](yarn|mapred|hdfs|hive|hbase|oozie)s/.*/nobody/
          RULE:[1:$1]
          RULE:[2:$1]
          
        '''
        "hadoop.proxyuser.HTTP.hosts": "*"
        "hadoop.proxyuser.HTTP.groups": "*"
        "hadoop.ssl.require.client.cert": "false"
        "hadoop.ssl.hostname.verifier": "DEFAULT"
        "hadoop.ssl.keystores.factory.class": "org.apache.hadoop.security.ssl.FileBasedKeyStoresFactory"
        "hadoop.ssl.server.conf": "ssl-server.xml"
        "hadoop.ssl.client.conf": "ssl-client.xml"
      hadoop_metrics:
        "*.sink.file.class": "org.apache.hadoop.metrics2.sink.FileSink"
        sinks:
          file: true
          ganglia: false
          graphite: false
        config:
          "*.period": "60"
          "*.sink.file.class": "org.apache.hadoop.metrics2.sink.FileSink"
          "*.sink.file.filename": "metrics.out"
          "namenode.sink.file.filename": "namenode-metrics.out"
          "datanode.sink.file.filename": "datanode-metrics.out"
          "resourcemanager.sink.file.filename": "resourcemanager-metrics.out"
          "nodemanager.sink.file.filename": "nodemanager-metrics.out"
          "mrappmaster.sink.file.filename": "mrappmaster-metrics.out"
          "jobhistoryserver.sink.file.filename": "jobhistoryserver-metrics.out"
      hadoop_heap: "512"
      hadoop_namenode_init_heap: "-Xms512m"
      hdfs:
        user:
          limits:
            nproc: 16384
            nofile: 16384
          uid: 2401
          gid: "hdfs"
          name: "hdfs"
          system: true
          groups: "hadoop"
          comment: "Hadoop HDFS User"
          home: "/var/lib/hadoop-hdfs"
        krb5_user:
          password: "hdfs123"
          password_sync: true
          principal: "hdfs@HADOOP.RYBA"
        sysctl:
          "vm.swappiness": 0
          "vm.overcommit_memory": 1
          "vm.overcommit_ratio": 100
          "net.core.somaxconn": 1024
        site:
          "dfs.namenode.safemode.extension": 1000
          "dfs.replication": 2
          "dfs.journalnode.rpc-address": "0.0.0.0:8485"
          "dfs.journalnode.http-address": "0.0.0.0:8480"
          "dfs.journalnode.https-address": "0.0.0.0:8481"
          "dfs.http.policy": "HTTPS_ONLY"
          "dfs.journalnode.kerberos.internal.spnego.principal": "HTTP/_HOST@HADOOP.RYBA"
          "dfs.journalnode.kerberos.principal": "HTTP/_HOST@HADOOP.RYBA"
          "dfs.journalnode.keytab.file": "/etc/security/keytabs/spnego.service.keytab"
          "dfs.journalnode.edits.dir": "/var/hdfs/edits"
          "dfs.namenode.shared.edits.dir": "qjournal://master1.ryba:8485;master2.ryba:8485;master3.ryba:8485/torval"
          "dfs.namenode.kerberos.principal.pattern": "*"
          "dfs.namenode.kerberos.principal": "nn/_HOST@HADOOP.RYBA"
          "dfs.namenode.kerberos.internal.spnego.principal": "HTTP/_HOST@HADOOP.RYBA"
          "dfs.namenode.kerberos.https.principal": "HTTP/_HOST@HADOOP.RYBA"
          "dfs.web.authentication.kerberos.principal": "HTTP/_HOST@HADOOP.RYBA"
          "dfs.ha.automatic-failover.enabled": "true"
          "dfs.nameservices": "torval"
          "dfs.internal.nameservices": "torval"
          "dfs.ha.namenodes.torval": "master1,master2"
          "dfs.namenode.http-address": null
          "dfs.namenode.https-address": null
          "dfs.namenode.rpc-address.torval.master1": "master1.ryba:8020"
          "dfs.namenode.http-address.torval.master1": "master1.ryba:50070"
          "dfs.namenode.https-address.torval.master1": "master1.ryba:50470"
          "dfs.namenode.rpc-address.torval.master2": "master2.ryba:8020"
          "dfs.namenode.http-address.torval.master2": "master2.ryba:50070"
          "dfs.namenode.https-address.torval.master2": "master2.ryba:50470"
          "dfs.client.failover.proxy.provider.torval": "org.apache.hadoop.hdfs.server.namenode.ha.ConfiguredFailoverProxyProvider"
          "dfs.datanode.kerberos.principal": "dn/_HOST@HADOOP.RYBA"
          "dfs.client.read.shortcircuit": "true"
          "dfs.domain.socket.path": "/var/lib/hadoop-hdfs/dn_socket"
        group:
          gid: 2401
          name: "hdfs"
          system: true
        log_dir: "/var/log/hadoop-hdfs"
        pid_dir: "/var/run/hadoop-hdfs"
        secure_dn_pid_dir: "/var/run/hadoop-hdfs"
        secure_dn_user: "hdfs"
        jn:
          conf_dir: "/etc/hadoop-hdfs-journalnode/conf"
        nn:
          site:
            "dfs.http.policy": "HTTPS_ONLY"
      zkfc:
        digest:
          name: "zkfc"
          password: "zkfc123"
      yarn:
        user:
          limits:
            nproc: 16384
            nofile: 16384
          uid: 2403
          gid: "yarn"
          name: "yarn"
          system: true
          groups: "hadoop"
          comment: "Hadoop YARN User"
          home: "/var/lib/hadoop-yarn"
        opts: "-Dsun.net.spi.nameservice.provider.1=sun,dns"
        site:
          "yarn.timeline-service.hostname": "master3.ryba"
          "yarn.http.policy": "HTTPS_ONLY"
          "yarn.timeline-service.address": "master3.ryba:10200"
          "yarn.timeline-service.webapp.address": "master3.ryba:8188"
          "yarn.timeline-service.webapp.https.address": "master3.ryba:8190"
          "yarn.timeline-service.handler-thread-count": "100"
          "yarn.timeline-service.http-cross-origin.enabled": "true"
          "yarn.timeline-service.http-cross-origin.allowed-origins": "*"
          "yarn.timeline-service.http-cross-origin.allowed-methods": "GET,POST,HEAD"
          "yarn.timeline-service.http-cross-origin.allowed-headers": "X-Requested-With,Content-Type,Accept,Origin"
          "yarn.timeline-service.http-cross-origin.max-age": "1800"
          "yarn.timeline-service.generic-application-history.store-class": "org.apache.hadoop.yarn.server.applicationhistoryservice.FileSystemApplicationHistoryStore"
          "yarn.timeline-service.fs-history-store.uri": "/apps/ats"
          "yarn.resourcemanager.system-metrics-publisher.enabled": "true"
          "yarn.timeline-service.enabled": "true"
          "yarn.timeline-service.store-class": "org.apache.hadoop.yarn.server.timeline.LeveldbTimelineStore"
          "yarn.timeline-service.leveldb-timeline-store.path": "/var/yarn/timeline"
          "yarn.timeline-service.ttl-enable": "true"
          "yarn.timeline-service.ttl-ms": "1209600000"
          "yarn.timeline-service.principal": "ats/_HOST@HADOOP.RYBA"
          "yarn.timeline-service.keytab": "/etc/security/keytabs/ats.service.keytab"
          "yarn.timeline-service.http-authentication.type": "kerberos"
          "yarn.timeline-service.http-authentication.kerberos.principal": "HTTP/_HOST@HADOOP.RYBA"
          "yarn.timeline-service.http-authentication.kerberos.keytab": "/etc/security/keytabs/spnego.service.keytab"
          "yarn.acl.enable": "true"
          "yarn.admin.acl": "yarn"
          "yarn.application.classpath": "$HADOOP_CONF_DIR,/usr/hdp/current/hadoop-client/*,/usr/hdp/current/hadoop-client/lib/*,/usr/hdp/current/hadoop-hdfs-client/*,/usr/hdp/current/hadoop-hdfs-client/lib/*,/usr/hdp/current/hadoop-yarn-client/*,/usr/hdp/current/hadoop-yarn-client/lib/*"
          "yarn.generic-application-history.save-non-am-container-meta-info": "true"
          "yarn.nodemanager.remote-app-log-dir": "/app-logs"
          "yarn.resourcemanager.principal": "rm/_HOST@HADOOP.RYBA"
          "yarn.resourcemanager.cluster-id": "yarn_cluster_01"
          "yarn.resourcemanager.ha.enabled": "true"
          "yarn.resourcemanager.ha.rm-ids": "master1,master2"
          "yarn.resourcemanager.webapp.delegation-token-auth-filter.enabled": "true"
          "yarn.resourcemanager.address.master1": "master1.ryba:8050"
          "yarn.resourcemanager.scheduler.address.master1": "master1.ryba:8030"
          "yarn.resourcemanager.admin.address.master1": "master1.ryba:8141"
          "yarn.resourcemanager.webapp.address.master1": "master1.ryba:8088"
          "yarn.resourcemanager.webapp.https.address.master1": "master1.ryba:8090"
          "yarn.resourcemanager.address.master2": "master2.ryba:8050"
          "yarn.resourcemanager.scheduler.address.master2": "master2.ryba:8030"
          "yarn.resourcemanager.admin.address.master2": "master2.ryba:8141"
          "yarn.resourcemanager.webapp.address.master2": "master2.ryba:8088"
          "yarn.resourcemanager.webapp.https.address.master2": "master2.ryba:8090"
          "yarn.scheduler.minimum-allocation-mb": null
          "yarn.scheduler.maximum-allocation-mb": null
        group:
          gid: 2403
          name: "yarn"
          system: true
        ats:
          log_dir: "/var/log/hadoop-yarn"
          pid_dir: "/var/run/hadoop-yarn"
          conf_dir: "/etc/hadoop-yarn-timelineserver/conf"
          opts: ""
          heapsize: "1024"
        log_dir: "/var/log/hadoop-yarn"
        pid_dir: "/var/run/hadoop-yarn"
        conf_dir: "/etc/hadoop/conf"
        heapsize: "1024"
        home: "/usr/hdp/current/hadoop-yarn-client"
      capacity_scheduler:
        "yarn.scheduler.capacity.maximum-am-resource-percent": ".5"
      mapred:
        user:
          limits:
            nproc: 16384
            nofile: 16384
          uid: 2404
          gid: "mapred"
          name: "mapred"
          system: true
          groups: "hadoop"
          comment: "Hadoop MapReduce User"
          home: "/var/lib/hadoop-mapreduce"
        site:
          "mapreduce.job.counters.max": "10000"
          "mapreduce.job.counters.limit": "10000"
          "yarn.app.mapreduce.am.resource.mb": "256"
          "yarn.app.mapreduce.am.command-opts": "-Xmx204m"
          "mapreduce.map.memory.mb": "512"
          "mapreduce.reduce.memory.mb": "1024"
          "mapreduce.map.java.opts": "-Xmx409m"
          "mapreduce.reduce.java.opts": "-Xmx819m"
          "mapreduce.task.io.sort.mb": "204"
          "mapreduce.map.cpu.vcores": "1"
          "mapreduce.reduce.cpu.vcores": "1"
          "mapreduce.jobhistory.keytab": "/etc/security/keytabs/jhs.service.keytab"
          "mapreduce.jobhistory.principal": "jhs/master3.ryba@HADOOP.RYBA"
          "mapreduce.shuffle.port": "13562"
          "mapreduce.jobhistory.address": "master3.ryba:10020"
          "mapreduce.jobhistory.webapp.address": "master3.ryba:19888"
          "mapreduce.jobhistory.webapp.https.address": "master3.ryba:19889"
          "mapreduce.jobhistory.admin.address": "master3.ryba:10033"
          "mapreduce.jobhistory.http.policy": "HTTPS_ONLY"
          "yarn.app.mapreduce.am.staging-dir": "/user"
          "mapreduce.jobhistory.done-dir": null
          "mapreduce.jobhistory.intermediate-done-dir": null
          "mapreduce.jobhistory.recovery.enable": "true"
          "mapreduce.jobhistory.recovery.store.class": "org.apache.hadoop.mapreduce.v2.hs.HistoryServerLeveldbStateStoreService"
          "mapreduce.jobhistory.recovery.store.leveldb.path": "/var/mapred/jhs"
          "mapreduce.reduce.shuffle.parallelcopies": "50"
          "mapreduce.admin.map.child.java.opts": "-server -Djava.net.preferIPv4Stack=true -Dhdp.version=${hdp.version}"
          "mapreduce.admin.reduce.child.java.opts": null
          "mapreduce.task.io.sort.factor": 100
          "mapreduce.admin.user.env": "LD_LIBRARY_PATH=/usr/hdp/${hdp.version}/hadoop/lib/native:/usr/hdp/${hdp.version}/hadoop/lib/native/Linux-amd64-64"
          "mapreduce.application.framework.path": "/hdp/apps/${hdp.version}/mapreduce/mapreduce.tar.gz#mr-framework"
          "mapreduce.application.classpath": "$PWD/mr-framework/hadoop/share/hadoop/mapreduce/*:$PWD/mr-framework/hadoop/share/hadoop/mapreduce/lib/*:$PWD/mr-framework/hadoop/share/hadoop/common/*:$PWD/mr-framework/hadoop/share/hadoop/common/lib/*:$PWD/mr-framework/hadoop/share/hadoop/yarn/*:$PWD/mr-framework/hadoop/share/hadoop/yarn/lib/*:$PWD/mr-framework/hadoop/share/hadoop/hdfs/*:$PWD/mr-framework/hadoop/share/hadoop/hdfs/lib/*:/usr/hdp/current/share/lzo/0.6.0/lib/hadoop-lzo-0.6.0.jar:/etc/hadoop/conf/secure"
          "yarn.app.mapreduce.am.job.client.port-range": "59100-59200"
          "mapreduce.framework.name": "yarn"
          "mapreduce.cluster.local.dir": null
          "mapreduce.jobtracker.system.dir": null
        group:
          gid: 2404
          name: "mapred"
          system: true
        jhs:
          conf_dir: "/etc/hadoop-mapreduce-historyserver/conf"
        heapsize: "900"
        pid_dir: "/var/run/hadoop-mapreduce"
        log_dir: "/var/log/hadoop-mapreduce"
      hive:
        user:
          limits:
            nproc: 16384
            nofile: 16384
          uid: 2407
          gid: "hive"
          name: "hive"
          system: true
          groups: "hadoop"
          comment: "Hive User"
          home: "/var/lib/hive"
        site:
          "javax.jdo.option.ConnectionDriverName": "com.mysql.jdbc.Driver"
          "javax.jdo.option.ConnectionUserName": "hive"
          "javax.jdo.option.ConnectionPassword": "hive123"
          "hive.tez.container.size": "512"
          "hive.tez.java.opts": "-Xmx409m"
          " hive.metastore.uris ": null
          " hive.cluster.delegation.token.store.class ": null
          "hive.metastore.local": null
          "fs.hdfs.impl.disable.cache": "false"
          "fs.file.impl.disable.cache": "false"
          "hive.server2.thrift.sasl.qop": "auth"
          "hive.metastore.sasl.enabled": "true"
          "hive.metastore.kerberos.keytab.file": "/etc/hive/conf/hive.service.keytab"
          "hive.metastore.kerberos.principal": "hive/_HOST@HADOOP.RYBA"
          "hive.metastore.cache.pinobjtypes": "Table,Database,Type,FieldSchema,Order"
          "hive.security.authorization.manager": "org.apache.hadoop.hive.ql.security.authorization.StorageBasedAuthorizationProvider"
          "hive.security.metastore.authorization.manager": "org.apache.hadoop.hive.ql.security.authorization.StorageBasedAuthorizationProvider"
          "hive.security.authenticator.manager": "org.apache.hadoop.hive.ql.security.ProxyUserAuthenticator"
          "hive.security.metastore.authenticator.manager": "org.apache.hadoop.hive.ql.security.HadoopDefaultMetastoreAuthenticator"
          "hive.metastore.pre.event.listeners": "org.apache.hadoop.hive.ql.security.authorization.AuthorizationPreEventListener"
          "hive.optimize.mapjoin.mapreduce": null
          "hive.heapsize": null
          "hive.auto.convert.sortmerge.join.noconditionaltask": null
          "hive.exec.max.created.files": "100000"
          "hive.metastore.uris": "thrift://master2.ryba:9083,thrift://master3.ryba:9083"
          "datanucleus.autoCreateTables": "true"
          "hive.security.authorization.enabled": "true"
          "javax.jdo.option.ConnectionURL": "jdbc:mysql://master3.ryba:3306/hive?createDatabaseIfNotExist=true"
          "hive.support.concurrency": "true"
          "hive.zookeeper.quorum": "master1.ryba:2181,master2.ryba:2181,master3.ryba:2181"
          "hive.enforce.bucketing": "true"
          "hive.exec.dynamic.partition.mode": "nonstrict"
          "hive.txn.manager": "org.apache.hadoop.hive.ql.lockmgr.DbTxnManager"
          "hive.txn.timeout": "300"
          "hive.txn.max.open.batch": "1000"
          "hive.compactor.initiator.on": "true"
          "hive.compactor.worker.threads": "1"
          "hive.compactor.worker.timeout": "86400L"
          "hive.compactor.cleaner.run.interval": "5000"
          "hive.compactor.check.interval": "300L"
          "hive.compactor.delta.num.threshold": "10"
          "hive.compactor.delta.pct.threshold": "0.1f"
          "hive.compactor.abortedtxn.threshold": "1000"
          "hive.cluster.delegation.token.store.class": "org.apache.hadoop.hive.thrift.DBTokenStore"
          "hive.exec.compress.intermediate": "true"
          "hive.auto.convert.join": "true"
          "hive.cli.print.header": "false"
          "hive.execution.engine": "tez"
          "hive.exec.reducers.bytes.per.reducer": "268435456"
          "hive.server2.authentication": "KERBEROS"
          "hive.server2.enable.doAs": "true"
          "hive.server2.allow.user.substitution": "true"
          "hive.server2.transport.mode": "http"
          "hive.server2.thrift.port": "10001"
          "hive.server2.thrift.http.port": "10001"
          "hive.server2.thrift.http.path": "cliservice"
          "hive.server2.logging.operation.log.location": "/tmp/hive/operation_logs"
          "hive.server2.tez.default.queues": "default"
          "hive.server2.tez.sessions.per.default.queue": "1"
          "hive.server2.tez.initialize.default.sessions": "false"
          "hive.server2.authentication.kerberos.keytab": "/etc/hive/conf/hive.service.keytab"
          "hive.server2.authentication.kerberos.principal": "hive/_HOST@HADOOP.RYBA"
          "hive.server2.authentication.spnego.principal": "HTTP/_HOST@HADOOP.RYBA"
          "hive.server2.authentication.spnego.keytab": "/etc/security/keytabs/spnego.service.keytab"
          "hive.server2.use.SSL": "true"
          "hive.server2.keystore.path": "/etc/conf/hive/keystore"
          "hive.server2.keystore.password": "ryba123"
          "hive.server2.support.dynamic.service.discovery": "true"
          "hive.zookeeper.session.timeout": "600000"
          "hive.server2.zookeeper.namespace": "hiveserver2"
        group:
          gid: 2407
          name: "hive"
          system: true
        conf_dir: "/etc/hive/conf"
        aux_jars: [
          "/usr/hdp/current/hive-webhcat/share/hcatalog/hive-hcatalog-core.jar"
        ]
        hcatalog:
          log_dir: "/var/log/hive-hcatalog"
          pid_dir: "/var/run/hive-hcatalog"
          opts: ""
          heapsize: 1024
        libs: []
        client:
          opts: ""
          heapsize: 1024
          truststore_location: "/etc/hive/conf/truststore"
          truststore_password: "ryba123"
        server2:
          conf_dir: "/etc/conf/hive"
          log_dir: "/var/log/hive-server2"
          pid_dir: "/var/run/hive-server2"
          opts: ""
          heapsize: 1024
      hue:
        ini:
          desktop:
            smtp:
              host: ""
            database:
              engine: "mysql"
              password: "hue123"
        ssl:
          certificate: "/home/pierrotws/workspace/ryba-cluster/conf/certs/master3_cert.pem"
          private_key: "/home/pierrotws/workspace/ryba-cluster/conf/certs/master3_key.pem"
          client_ca: "/home/pierrotws/workspace/ryba-cluster/conf/certs/cacert.pem"
        group:
          gid: 2410
        user:
          uid: 2410
          gid: 2410
      sqoop:
        libs: []
        user:
          uid: 2412
          gid: 2400
          name: "sqoop"
          system: true
          comment: "Sqoop User"
          home: "/var/lib/sqoop"
        conf_dir: "/etc/sqoop/conf"
        site: {}
      hbase:
        regionserver_opts: "-Xmx512m"
        admin:
          password: "hbase123"
          name: "hbase"
          principal: "hbase@HADOOP.RYBA"
        metrics:
          "*.sink.file.class": "org.apache.hadoop.metrics2.sink.FileSink"
          sinks:
            file: true
            ganglia: false
            graphite: false
          config:
            "*.period": "60"
            "*.sink.file.class": "org.apache.hadoop.metrics2.sink.FileSink"
            "*.sink.file.filename": "metrics.out"
            "hbase.sink.file.filename": "hbase-metrics.out"
        group:
          gid: 2409
          name: "hbase"
          system: true
        user:
          uid: 2409
          gid: "hbase"
          name: "hbase"
          system: true
          comment: "HBase User"
          home: "/var/run/hbase"
          groups: "hadoop"
          limits:
            nofile: 64000
            nproc: true
        test:
          default_table: "ryba"
        conf_dir: "/etc/hbase/conf"
        log_dir: "/var/log/hbase"
        pid_dir: "/var/run/hbase"
        site:
          "zookeeper.znode.parent": "/hbase"
          "hbase.cluster.distributed": "true"
          "hbase.rootdir": "hdfs://torval:8020/apps/hbase/data"
          "hbase.zookeeper.quorum": "master1.ryba,master2.ryba,master3.ryba"
          "hbase.zookeeper.property.clientPort": "2181"
          "dfs.domain.socket.path": "/var/lib/hadoop-hdfs/dn_socket"
          "hbase.security.authentication": "kerberos"
          "hbase.security.authorization": "true"
          "hbase.rpc.engine": "org.apache.hadoop.hbase.ipc.SecureRpcEngine"
          "hbase.superuser": "hbase"
          "hbase.bulkload.staging.dir": "/apps/hbase/staging"
          "hbase.ipc.client.specificThreadForWriting": "true"
          "hbase.client.primaryCallTimeout.get": "10000"
          "hbase.client.primaryCallTimeout. multiget": "10000"
          "hbase.client.primaryCallTimeout.scan": "1000000"
          "hbase.meta.replicas.use": "true"
          "hbase.rest.port": "60080"
          "hbase.rest.info.port": "60085"
          "hbase.rest.ssl.enabled": "true"
          "hbase.rest.ssl.keystore.store": "/etc/hadoop/conf/keystore"
          "hbase.rest.ssl.keystore.password": "ryba123"
          "hbase.rest.ssl.keystore.keypassword": "ryba123"
          "hbase.rest.kerberos.principal": "hbase_rest/_HOST@HADOOP.RYBA"
          "hbase.rest.keytab.file": "/etc/security/keytabs/hbase_rest.service.keytab"
          "hbase.rest.authentication.type": "kerberos"
          "hbase.rest.support.proxyuser": "true"
          "hbase.rest.authentication.kerberos.principal": "HTTP/_HOST@HADOOP.RYBA"
          "hbase.rest.authentication.kerberos.keytab": "/etc/security/keytabs/spnego.service.keytab"
          "hbase.master.kerberos.principal": "hbase/_HOST@HADOOP.RYBA"
          "hbase.regionserver.kerberos.principal": "hbase/_HOST@HADOOP.RYBA"
          "hbase.regionserver.port": "60020"
          "hbase.regionserver.info.port": "60030"
          "hbase.ssl.enabled": "true"
          "hbase.regionserver.handler.count": 60
          "hbase.regionserver.keytab.file": "/etc/security/keytabs/rs.service.keytab"
          "hbase.regionserver.global.memstore.upperLimit": null
          "hbase.regionserver.global.memstore.size": "0.4"
          "hbase.coprocessor.region.classes": [
            "org.apache.hadoop.hbase.security.token.TokenProvider"
            "org.apache.hadoop.hbase.security.access.SecureBulkLoadEndpoint"
            "org.apache.hadoop.hbase.security.access.AccessController"
          ]
          "hadoop.proxyuser.hbase_rest.groups": "*"
          "hadoop.proxyuser.hbase_rest.hosts": "*"
          "hbase.master.port": "60000"
          "hbase.master.info.port": "60010"
          "hbase.master.info.bindAddress": "0.0.0.0"
          "hbase.master.keytab.file": "/etc/security/keytabs/hm.service.keytab"
          "hbase.coprocessor.master.classes": "org.apache.hadoop.hbase.security.access.AccessController"
        env:
          JAVA_HOME: "/usr/lib/jvm/java"
          HBASE_LOG_DIR: "/var/log/hbase"
          HBASE_OPTS: "-ea -XX:+UseConcMarkSweepGC -XX:+CMSIncrementalMode -Djava.security.auth.login.config=/etc/hbase/conf/hbase-client.jaas"
          HBASE_MASTER_OPTS: "-Xmx2048m"
          HBASE_REGIONSERVER_OPTS: "-Xmn200m -Xms4096m -Xmx4096m"
        master_opts: "-Xmx2048m"
        log4j: {}
      kafka:
        broker:
          heapsize: 128
          "log.dirs": [
            "/data/1/kafka"
            "/data/2/kafka"
          ]
          conf_dir: "/etc/kafka-broker/conf"
          config:
            "log.dirs": "/data/1/kafka,/data/2/kafka"
            "zookeeper.connect": [
              "master1.ryba:2181"
              "master2.ryba:2181"
              "master3.ryba:2181"
            ]
            "log.retention.hours": "168"
            "super.users": "User:kafka"
            "num.partitions": 3
            "broker.id": "2"
            "ssl.keystore.location": "/etc/kafka-broker/conf/keystore"
            "ssl.keystore.password": "ryba123"
            "ssl.key.password": "ryba123"
            "ssl.truststore.location": "/etc/kafka-broker/conf/truststore"
            "ssl.truststore.password": "ryba123"
            "sasl.kerberos.service.name": "kafka"
            "allow.everyone.if.no.acl.found": "true"
            "zookeeper.set.acl": true
            listeners: "SASL_SSL://master3.ryba:9096"
            "replication.security.protocol": "SASL_SSL"
          env:
            KAFKA_HEAP_OPTS: "-Xmx128m -Xms128m"
            KAFKA_LOG4J_OPTS: "-Dlog4j.configuration=file:$base_dir/../config/log4j.properties"
            KAFKA_KERBEROS_PARAMS: "-Djava.security.auth.login.config=/etc/kafka-broker/conf/kafka-server.jaas"
          log4j:
            "log4j.rootLogger": "INFO, kafkaAppender"
            "log4j.additivity.kafka": "false"
          protocols: [
            "SASL_SSL"
          ]
          kerberos:
            principal: "kafka/master3.ryba@HADOOP.RYBA"
            keyTab: "/etc/security/keytabs/kafka.service.keytab"
        group:
          gid: 2424
          name: "kafka"
          system: true
        user:
          uid: 2424
          gid: "kafka"
          name: "kafka"
          system: true
          comment: "Kafka User"
          home: "/var/lib/kafka"
        admin:
          principal: "kafka"
          password: "kafka123"
        superusers: [
          "kafka"
        ]
        ports:
          PLAINTEXT: "9092"
          SSL: "9093"
          SASL_PLAINTEXT: "9094"
          SASL_SSL: "9096"
      opentsdb:
        version: "2.2.0RC3"
        group:
          gid: 2428
          name: "opentsdb"
          system: true
        user:
          uid: 2428
          gid: "opentsdb"
          name: "opentsdb"
          system: true
          comment: "OpenTSDB User"
          home: "/usr/share/opentsdb"
        source: "https://github.com/OpenTSDB/opentsdb/releases/download/v2.2.0RC3/opentsdb-2.2.0RC3.noarch.rpm"
        hbase:
          bloomfilter: "ROW"
          compression: "SNAPPY"
        config:
          "tsd.http.staticroot": "/usr/share/opentsdb/static/"
          "tsd.http.cachedir": "/tmp/opentsdb"
          "tsd.core.plugin_path": "/usr/share/opentsdb/plugins"
          "tsd.core.meta.enable_realtime_ts": "true"
          "tsd.http.request.cors_domains": "*"
          "tsd.network.port": 4242
          "tsd.storage.hbase.zk_quorum": "master1.ryba:2181,master2.ryba:2181,master3.ryba:2181"
          "tsd.storage.hbase.zk_basedir": "/hbase"
          "tsd.storage.hbase.data_table": "tsdb"
          "tsd.storage.hbase.uid_table": "tsdb-uid"
          "tsd.storage.hbase.tree_table": "tsdb-tree"
          "tsd.storage.hbase.meta_table": "tsdb-meta"
          "tsd.query.allow_simultaneous_duplicates": "true"
          "hbase.security.authentication": "kerberos"
          "hbase.security.auth.enable": "true"
          "hbase.kerberos.regionserver.principal": "hbase/_HOST@HADOOP.RYBA"
          "java.security.auth.login.config": "/etc/opentsdb/opentsdb.jaas"
          "hbase.sasl.clientconfig": "Client"
        env:
          "java.security.auth.login.config": "/etc/opentsdb/opentsdb.jaas"
        java_opts: ""
      nagios:
        users:
          nagiosadmin:
            password: "nagios123"
            alias: "Nagios Admin"
            email: ""
          guest:
            password: "guest123"
            alias: "Nagios Guest"
            email: ""
        groups:
          admins:
            alias: "Nagios Administrators"
            members: [
              "nagiosadmin"
              "guest"
            ]
        group:
          gid: 2418
          name: "nagios"
          system: true
        groupcmd:
          gid: 2419
          name: "nagiocmd"
          system: true
        user:
          uid: 2418
          gid: "nagios"
          name: "nagios"
          system: true
          comment: "Nagios User"
          home: "/var/log/nagios"
          shell: "/bin/sh"
        overwrite: false
        log_dir: "/var/log/nagios"
        keytab: "/etc/security/keytabs/nagios.service.keytab"
        principal: "nagios/master3.ryba@HADOOP.RYBA"
        kinit: "/usr/bin/kinit"
        plugin_dir: "/usr/lib64/nagios/plugins"
        hostgroups:
          namenode: [
            "master1.ryba"
            "master2.ryba"
          ]
          snamenode: []
          slaves: [
            "worker1.ryba"
            "worker2.ryba"
          ]
          "agent-servers": []
          "nagios-server": [
            "master3.ryba"
          ]
          "ganglia-server": []
          "flume-servers": []
          "zookeeper-servers": []
          hbasemasters: [
            "master1.ryba"
            "master2.ryba"
          ]
          hiveserver: [
            "master2.ryba"
            "master3.ryba"
          ]
          "region-servers": [
            "worker1.ryba"
            "worker2.ryba"
          ]
          "oozie-server": [
            "master3.ryba"
          ]
          "webhcat-server": [
            "master3.ryba"
          ]
          resourcemanager: [
            "master1.ryba"
            "master2.ryba"
          ]
          nodemanagers: [
            "worker1.ryba"
            "worker2.ryba"
          ]
          historyserver2: []
          journalnodes: [
            "master1.ryba"
            "master2.ryba"
            "master3.ryba"
          ]
          nimbus: []
          "drpc-server": []
          storm_ui: []
          supervisors: []
          storm_rest_api: []
          "falcon-server": []
          "ats-servers": []
      hadoop_group:
        gid: 2400
        name: "hadoop"
        system: true
      group:
        gid: 2414
        name: "ryba"
        system: true
      user:
        uid: 2414
        gid: 2414
        name: "ryba"
        password: "password"
        system: true
        comment: "ryba User"
        home: "/home/ryba"
      zookeeper:
        group:
          gid: 2402
          name: "zookeeper"
          system: true
        user:
          uid: 2402
          gid: 2400
          name: "zookeeper"
          system: true
          groups: "hadoop"
          comment: "Zookeeper User"
          home: "/var/lib/zookeeper"
        conf_dir: "/etc/zookeeper/conf"
        log_dir: "/var/log/zookeeper"
        port: 2181
        env:
          JAVA_HOME: "/usr/lib/jvm/java"
          CLIENT_JVMFLAGS: "-Djava.security.auth.login.config=/etc/zookeeper/conf/zookeeper-client.jaas"
          ZOOKEEPER_HOME: "/usr/hdp/current/zookeeper-client"
          ZOO_AUTH_TO_LOCAL: "RULE:[1:\\$1]RULE:[2:\\$1]"
          ZOO_LOG_DIR: "/var/log/zookeeper"
          ZOOPIDFILE: "/var/run/zookeeper/zookeeper_server.pid"
          SERVER_JVMFLAGS: "-Xmx1024m -Djava.security.auth.login.config=/etc/zookeeper/conf/zookeeper-server.jaas -Dzookeeper.security.auth_to_local=$ZOO_AUTH_TO_LOCAL"
          JAVA: "$JAVA_HOME/bin/java"
          CLASSPATH: "$CLASSPATH:/usr/share/zookeeper/*"
          ZOO_LOG4J_PROP: "INFO,CONSOLE,ROLLINGFILE"
        pid_dir: "/var/run/zookeeper"
        log4j: {}
        config:
          maxClientCnxns: "200"
          tickTime: "2000"
          initLimit: "10"
          syncLimit: "5"
          dataDir: "/var/zookeeper/data/"
          clientPort: "2181"
          "server.1": "master1.ryba:2888:3888"
          "server.2": "master2.ryba:2888:3888"
          "server.3": "master3.ryba:2888:3888"
          "authProvider.1": "org.apache.zookeeper.server.auth.SASLAuthenticationProvider"
          jaasLoginRenew: "3600000"
          "kerberos.removeHostFromPrincipal": "true"
          "kerberos.removeRealmFromPrincipal": "true"
        myid: null
        retention: 3
        purge: "@weekly"
        superuser: {}
      flume:
        group:
          gid: 2405
        user:
          uid: 2405
          gid: 2405
      ganglia:
        rrdcached_group:
          gid: 2406
          name: "rrdcached"
          system: true
        rrdcached_user:
          uid: 2406
          gid: "rrdcached"
          name: "rrdcached"
          system: true
          shell: false
          comment: "RRDtool User"
          home: "/var/rrdtool/rrdcached"
        collector_port: 8649
        slaves_port: 8660
        hbase_region_port: 8660
        nn_port: 8661
        jt_port: 8662
        hm_port: 8663
        hbase_master_port: 8663
        rm_port: 8664
        jhs_port: 8666
        spark_port: 8667
      oozie:
        group:
          gid: 2411
          name: "oozie"
          system: true
        user:
          uid: 2411
          gid: 2411
          name: "oozie"
          system: true
          comment: "Oozie User"
          home: "/var/lib/oozie"
        conf_dir: "/etc/oozie/conf"
        data: "/var/db/oozie"
        log_dir: "/var/log/oozie"
        pid_dir: "/var/run/oozie"
        tmp_dir: "/var/tmp/oozie"
        server_dir: "/usr/hdp/current/oozie-client/oozie-server"
        secure: true
        keystore_file: "/etc/hadoop/conf/keystore"
        keystore_pass: "ryba123"
        site:
          "oozie.base.url": "https://master3.ryba:11443/oozie"
          "oozie.service.JPAService.jdbc.url": "jdbc:mysql://master3.ryba:3306/oozie?createDatabaseIfNotExist=true"
          "oozie.service.JPAService.jdbc.driver": "com.mysql.jdbc.Driver"
          "oozie.service.JPAService.jdbc.username": "oozie"
          "oozie.service.JPAService.jdbc.password": "oozie123"
          "oozie.service.HadoopAccessorService.hadoop.configurations": "*=/etc/hadoop/conf"
          "oozie.service.AuthorizationService.security.enabled": "true"
          "oozie.service.AuthorizationService.authorization.enabled": "true"
          "oozie.service.HadoopAccessorService.kerberos.enabled": "true"
          "local.realm": "HADOOP.RYBA"
          "oozie.service.HadoopAccessorService.keytab.file": "/etc/oozie/conf/oozie.service.keytab"
          "oozie.service.HadoopAccessorService.kerberos.principal": "oozie/master3.ryba@HADOOP.RYBA"
          "oozie.authentication.type": "kerberos"
          "oozie.authentication.kerberos.principal": "HTTP/master3.ryba@HADOOP.RYBA"
          "oozie.authentication.kerberos.keytab": "/etc/oozie/conf/spnego.service.keytab"
          "oozie.authentication.kerberos.name.rules": '''
            
            RULE:[2:$1@$0]([rn]m@HADOOP\\.RYBA)s/.*/yarn/
            RULE:[2:$1@$0](jhs@HADOOP\\.RYBA)s/.*/mapred/
            RULE:[2:$1@$0]([nd]n@HADOOP\\.RYBA)s/.*/hdfs/
            RULE:[2:$1@$0](hm@HADOOP\\.RYBA)s/.*/hbase/
            RULE:[2:$1@$0](rs@HADOOP\\.RYBA)s/.*/hbase/
            RULE:[2:$1@$0](opentsdb@HADOOP\\.RYBA)s/.*/hbase/
            DEFAULT
            RULE:[1:$1](yarn|mapred|hdfs|hive|hbase|oozie)s/.*/nobody/
            RULE:[2:$1](yarn|mapred|hdfs|hive|hbase|oozie)s/.*/nobody/
            RULE:[1:$1]
            RULE:[2:$1]
            
          '''
          "oozie.service.HadoopAccessorService.nameNode.whitelist": ""
          "oozie.services": "org.apache.oozie.service.SchedulerService,org.apache.oozie.service.InstrumentationService,org.apache.oozie.service.MemoryLocksService,org.apache.oozie.service.UUIDService,org.apache.oozie.service.ELService,org.apache.oozie.service.AuthorizationService,org.apache.oozie.service.UserGroupInformationService,org.apache.oozie.service.HadoopAccessorService,org.apache.oozie.service.JobsConcurrencyService,org.apache.oozie.service.URIHandlerService,org.apache.oozie.service.DagXLogInfoService,org.apache.oozie.service.SchemaService,org.apache.oozie.service.LiteWorkflowAppService,org.apache.oozie.service.JPAService,org.apache.oozie.service.StoreService,org.apache.oozie.service.SLAStoreService,org.apache.oozie.service.DBLiteWorkflowStoreService,org.apache.oozie.service.CallbackService,org.apache.oozie.service.ActionService,org.apache.oozie.service.ShareLibService,org.apache.oozie.service.CallableQueueService,org.apache.oozie.service.ActionCheckerService,org.apache.oozie.service.RecoveryService,org.apache.oozie.service.PurgeService,org.apache.oozie.service.CoordinatorEngineService,org.apache.oozie.service.BundleEngineService,org.apache.oozie.service.DagEngineService,org.apache.oozie.service.CoordMaterializeTriggerService,org.apache.oozie.service.StatusTransitService,org.apache.oozie.service.PauseTransitService,org.apache.oozie.service.GroupsService,org.apache.oozie.service.ProxyUserService,org.apache.oozie.service.XLogStreamingService,org.apache.oozie.service.JvmPauseMonitorService,org.apache.oozie.service.SparkConfigurationService"
          "oozie.service.ProxyUserService.proxyuser.falcon.hosts": "front1.ryba"
          "oozie.service.ProxyUserService.proxyuser.falcon.groups": "*"
          "oozie.service.URIHandlerService.uri.handlers": "org.apache.oozie.dependency.FSURIHandler,org.apache.oozie.dependency.HCatURIHandler"
          "oozie.service.ELService.ext.functions.coord-job-submit-instances": '''
            now=org.apache.oozie.extensions.OozieELExtensions#ph1_now_echo,
            today=org.apache.oozie.extensions.OozieELExtensions#ph1_today_echo,
            yesterday=org.apache.oozie.extensions.OozieELExtensions#ph1_yesterday_echo,
            currentMonth=org.apache.oozie.extensions.OozieELExtensions#ph1_currentMonth_echo,
            lastMonth=org.apache.oozie.extensions.OozieELExtensions#ph1_lastMonth_echo,
            currentYear=org.apache.oozie.extensions.OozieELExtensions#ph1_currentYear_echo,
            lastYear=org.apache.oozie.extensions.OozieELExtensions#ph1_lastYear_echo,
            formatTime=org.apache.oozie.coord.CoordELFunctions#ph1_coord_formatTime_echo,
            latest=org.apache.oozie.coord.CoordELFunctions#ph2_coord_latest_echo,
            future=org.apache.oozie.coord.CoordELFunctions#ph2_coord_future_echo
          '''
          "oozie.service.ELService.ext.functions.coord-action-create-inst": '''
            now=org.apache.oozie.extensions.OozieELExtensions#ph2_now_inst,
            today=org.apache.oozie.extensions.OozieELExtensions#ph2_today_inst,
            yesterday=org.apache.oozie.extensions.OozieELExtensions#ph2_yesterday_inst,
            currentMonth=org.apache.oozie.extensions.OozieELExtensions#ph2_currentMonth_inst,
            lastMonth=org.apache.oozie.extensions.OozieELExtensions#ph2_lastMonth_inst,
            currentYear=org.apache.oozie.extensions.OozieELExtensions#ph2_currentYear_inst,
            lastYear=org.apache.oozie.extensions.OozieELExtensions#ph2_lastYear_inst,
            latest=org.apache.oozie.coord.CoordELFunctions#ph2_coord_latest_echo,
            future=org.apache.oozie.coord.CoordELFunctions#ph2_coord_future_echo,
            formatTime=org.apache.oozie.coord.CoordELFunctions#ph2_coord_formatTime,
            user=org.apache.oozie.coord.CoordELFunctions#coord_user
          '''
          "oozie.service.ELService.ext.functions.coord-action-start": '''
            now=org.apache.oozie.extensions.OozieELExtensions#ph2_now,
            today=org.apache.oozie.extensions.OozieELExtensions#ph2_today,
            yesterday=org.apache.oozie.extensions.OozieELExtensions#ph2_yesterday,
            currentMonth=org.apache.oozie.extensions.OozieELExtensions#ph2_currentMonth,
            lastMonth=org.apache.oozie.extensions.OozieELExtensions#ph2_lastMonth,
            currentYear=org.apache.oozie.extensions.OozieELExtensions#ph2_currentYear,
            lastYear=org.apache.oozie.extensions.OozieELExtensions#ph2_lastYear,
            latest=org.apache.oozie.coord.CoordELFunctions#ph3_coord_latest,
            future=org.apache.oozie.coord.CoordELFunctions#ph3_coord_future,
            dataIn=org.apache.oozie.extensions.OozieELExtensions#ph3_dataIn,
            instanceTime=org.apache.oozie.coord.CoordELFunctions#ph3_coord_nominalTime,
            dateOffset=org.apache.oozie.coord.CoordELFunctions#ph3_coord_dateOffset,
            formatTime=org.apache.oozie.coord.CoordELFunctions#ph3_coord_formatTime,
            user=org.apache.oozie.coord.CoordELFunctions#coord_user
          '''
          "oozie.service.ELService.ext.functions.coord-sla-submit": '''
            instanceTime=org.apache.oozie.coord.CoordELFunctions#ph1_coord_nominalTime_echo_fixed,
            user=org.apache.oozie.coord.CoordELFunctions#coord_user
          '''
          "oozie.service.ELService.ext.functions.coord-sla-create": '''
            instanceTime=org.apache.oozie.coord.CoordELFunctions#ph2_coord_nominalTime,
            user=org.apache.oozie.coord.CoordELFunctions#coord_user
          '''
          "oozie.service.ProxyUserService.proxyuser.knox.hosts": "front1.ryba"
          "oozie.service.ProxyUserService.proxyuser.knox.groups": "*"
        http_port: 11443
        admin_port: 11001
        hadoop_config:
          "mapreduce.jobtracker.kerberos.principal": "mapred/_HOST@HADOOP.RYBA"
          "yarn.resourcemanager.principal": "yarn/_HOST@HADOOP.RYBA"
          "dfs.namenode.kerberos.principal": "hdfs/_HOST@HADOOP.RYBA"
          "mapreduce.framework.name": "yarn"
        log4j: {}
      pig:
        user:
          uid: 2413
          gid: 2400
          name: "pig"
          system: true
          comment: "Pig User"
          home: "/home/pig"
        conf_dir: "/etc/pig/conf"
        config: {}
      knox:
        group:
          gid: 2420
        user:
          uid: 2420
          gid: 2420
      falcon:
        group:
          gid: 2421
        user:
          uid: 2421
          gid: 2421
      elasticsearch:
        group:
          gid: 2422
          name: "elasticsearch"
          system: true
        user:
          uid: 2422
          gid: 2422
          name: "elasticsearch"
          system: true
          comment: "ElasticSearch User"
        version: "1.7.1"
        principal: "elasticsearch/master3.ryba@HADOOP.RYBA"
        keytab: "/etc/security/keytabs/elasticsearch.service.keytab"
        cluster:
          name: "elasticsearch"
        number_of_shards: 1
        number_of_replicas: 1
        source: "https://download.elasticsearch.org/elasticsearch/elasticsearch/elasticsearch-1.7.1.noarch.rpm"
      rexster:
        group:
          gid: 2423
          name: "rexster"
          system: true
        user:
          uid: 2423
          gid: 2423
          name: "rexster"
          system: true
          comment: "Rexster User"
          home: "/opt/titan/current/rexhome"
        krb5_user:
          principal: "rexster/master3.ryba@HADOOP.RYBA"
          keytab: "/etc/security/keytabs/rexster.service.keytab"
        admin:
          name: "rexster"
          password: "rexster123"
        log_dir: "/var/log/rexster"
        config:
          http:
            "server-port": 8182
            "server-host": "0.0.0.0"
            "base-uri": "http://master3.ryba"
            "web-root": "public"
            "character-set": "UTF-8"
            "enable-jmx": false
            "enable-doghouse": true
            "max-post-size": 2097152
            "max-header-size": 8192
            "upload-timeout-millis": 30000
            "thread-pool":
              worker:
                "core-size": 8
                "max-size": 8
              kernal:
                "core-size": 4
                "max-size": 4
            "io-strategy": "leader-follower"
          rexpro:
            "server-port": 8184
            "server-host": "0.0.0.0"
            "session-max-idle": 1790000
            "session-check-interval": 3000000
            "connection-max-idle": 180000
            "connection-check-interval": 3000000
            "read-buffer": 65536
            "enable-jmx": false
            "thread-pool":
              worker:
                "core-size": 8
                "max-size": 8
              kernal:
                "core-size": 4
                "max-size": 4
            "io-strategy": "leader-follower"
          security:
            authentication:
              type: "default"
              configuration:
                users:
                  user: [
                    {
                      username: "rexster"
                      password: "rexster123"
                    }
                  ]
          "shutdown-port": 8183
          "shutdown-host": "127.0.0.1"
          "config-check-interval": 10000
          "script-engines": [
            {
              "script-engine":
                name: "gremlin-groovy"
                "reset-threshold": 500
                imports: "com.tinkerpop.gremlin.*,com.tinkerpop.gremlin.java.*,com.tinkerpop.gremlin.pipes.filter.*,com.tinkerpop.gremlin.pipes.sideeffect.*,com.tinkerpop.gremlin.pipes.transform.*,com.tinkerpop.blueprints.*,com.tinkerpop.blueprints.impls.*,com.tinkerpop.blueprints.impls.tg.*,com.tinkerpop.blueprints.impls.neo4j.*,com.tinkerpop.blueprints.impls.neo4j.batch.*,com.tinkerpop.blueprints.impls.neo4j2.*,com.tinkerpop.blueprints.impls.neo4j2.batch.*,com.tinkerpop.blueprints.impls.orient.*,com.tinkerpop.blueprints.impls.orient.batch.*,com.tinkerpop.blueprints.impls.dex.*,com.tinkerpop.blueprints.impls.rexster.*,com.tinkerpop.blueprints.impls.sail.*,com.tinkerpop.blueprints.impls.sail.impls.*,com.tinkerpop.blueprints.util.*,com.tinkerpop.blueprints.util.io.*,com.tinkerpop.blueprints.util.io.gml.*,com.tinkerpop.blueprints.util.io.graphml.*,com.tinkerpop.blueprints.util.io.graphson.*,com.tinkerpop.blueprints.util.wrappers.*,com.tinkerpop.blueprints.util.wrappers.batch.*,com.tinkerpop.blueprints.util.wrappers.batch.cache.*,com.tinkerpop.blueprints.util.wrappers.event.*,com.tinkerpop.blueprints.util.wrappers.event.listener.*,com.tinkerpop.blueprints.util.wrappers.id.*,com.tinkerpop.blueprints.util.wrappers.partition.*,com.tinkerpop.blueprints.util.wrappers.readonly.*,com.tinkerpop.blueprints.oupls.sail.*,com.tinkerpop.blueprints.oupls.sail.pg.*,com.tinkerpop.blueprints.oupls.jung.*,com.tinkerpop.pipes.*,com.tinkerpop.pipes.branch.*,com.tinkerpop.pipes.filter.*,com.tinkerpop.pipes.sideeffect.*,com.tinkerpop.pipes.transform.*,com.tinkerpop.pipes.util.*,com.tinkerpop.pipes.util.iterators.*,com.tinkerpop.pipes.util.structures.*,org.apache.commons.configuration.*,com.thinkaurelius.titan.core.*,com.thinkaurelius.titan.core.attribute.*,com.thinkaurelius.titan.core.log.*,com.thinkaurelius.titan.core.olap.*,com.thinkaurelius.titan.core.schema.*,com.thinkaurelius.titan.core.util.*,com.thinkaurelius.titan.example.*,org.apache.commons.configuration.*,com.tinkerpop.gremlin.Tokens.T,com.tinkerpop.gremlin.groovy.*"
                "static-imports": "com.tinkerpop.blueprints.Direction.*,com.tinkerpop.blueprints.TransactionalGraph$Conclusion.*,com.tinkerpop.blueprints.Compare.*,com.thinkaurelius.titan.core.attribute.Geo.*,com.thinkaurelius.titan.core.attribute.Text.*,com.thinkaurelius.titan.core.Cardinality.*,com.thinkaurelius.titan.core.Multiplicity.*,com.tinkerpop.blueprints.Query$Compare.*"
            }
          ]
          metrics: [
            {
              reporter:
                type: "jmx"
            }
            {
              reporter:
                type: "http"
            }
            {
              reporter:
                type: "console"
                properties:
                  "rates-time-unit": "SECONDS"
                  "duration-time-unit": "SECONDS"
                  "report-period": 10
                  "report-time-unit": "MINUTES"
                  includes: "http.rest.*"
                  excludes: "http.rest.*.delete"
            }
          ]
          graphs: [
            {
              graph:
                "graph-name": "titan"
                "graph-type": "com.thinkaurelius.titan.tinkerpop.rexster.TitanGraphConfiguration"
                "graph-read-only": false
                properties:
                  "storage.backend": "hbase"
                  "storage.hostname": "master1.ryba,master2.ryba,master3.ryba"
                  "storage.hbase.table": "titan"
                  "storage.hbase.short-cf-names": true
                  "index.search.backend": "elasticsearch"
                  "index.search.hostname": "master3.ryba"
                  "index.search.elasticsearch.client-only": true
                  "index.search.elasticsearch.cluster-name": "elasticsearch"
                  "cache.db-cache": true
                  "cache.db-cache-clean-wait": 20
                  "cache.db-cache-time": 180000
                  "cache.db-cache-size": 0.5
                extensions:
                  allows:
                    allow: [
                      "tp:gremlin"
                    ]
            }
          ]
      presto:
        group:
          gid: 2425
        user:
          uid: 2425
          gid: 2425
      spark:
        group:
          gid: 2426
        user:
          uid: 2426
          gid: 2426
      httpfs:
        group:
          gid: 2427
          name: "httpfs"
          system: true
        user:
          uid: 2427
          gid: "httpfs"
          name: "httpfs"
          system: true
          comment: "HttpFS User"
          home: "/var/lib/httpfs"
          groups: "hadoop"
        pid_dir: "/var/run/httpfs"
        conf_dir: "/etc/hadoop-httpfs/conf"
        log_dir: "/var/log/hadoop-httpfs"
        tmp_dir: "/var/tmp/hadoop-httpfs"
        http_port: "14000"
        http_admin_port: "14001"
        catalina_home: "/etc/hadoop-httpfs/tomcat-deployment"
        catalina_opts: ""
        env:
          HTTPFS_SSL_ENABLED: "true"
          HTTPFS_SSL_KEYSTORE_FILE: "/etc/hadoop-httpfs/conf/keystore"
          HTTPFS_SSL_KEYSTORE_PASS: "ryba123"
        site:
          "httpfs.hadoop.config.dir": "/etc/hadoop/conf"
          "kerberos.realm": "HADOOP.RYBA"
          "httpfs.hostname": "master3.ryba"
          "httpfs.authentication.type": "kerberos"
          "httpfs.authentication.kerberos.principal": "HTTP/master3.ryba@HADOOP.RYBA"
          "httpfs.authentication.kerberos.keytab": "/etc/security/keytabs/spnego.service.keytab"
          "httpfs.hadoop.authentication.type": "kerberos"
          "httpfs.hadoop.authentication.kerberos.keytab": "/etc/security/keytabs/httpfs.service.keytab"
          "httpfs.hadoop.authentication.kerberos.principal": "httpfs/master3.ryba@HADOOP.RYBA"
          "httpfs.authentication.kerberos.name.rules": '''
            
            RULE:[2:$1@$0]([rn]m@HADOOP\\.RYBA)s/.*/yarn/
            RULE:[2:$1@$0](jhs@HADOOP\\.RYBA)s/.*/mapred/
            RULE:[2:$1@$0]([nd]n@HADOOP\\.RYBA)s/.*/hdfs/
            RULE:[2:$1@$0](hm@HADOOP\\.RYBA)s/.*/hbase/
            RULE:[2:$1@$0](rs@HADOOP\\.RYBA)s/.*/hbase/
            RULE:[2:$1@$0](opentsdb@HADOOP\\.RYBA)s/.*/hbase/
            DEFAULT
            RULE:[1:$1](yarn|mapred|hdfs|hive|hbase|oozie)s/.*/nobody/
            RULE:[2:$1](yarn|mapred|hdfs|hive|hbase|oozie)s/.*/nobody/
            RULE:[1:$1]
            RULE:[2:$1]
            
          '''
          "httpfs.proxyuser.knox.hosts": "front1.ryba"
          "httpfs.proxyuser.knox.groups": "*"
      nagvis:
        group:
          gid: 2429
        user:
          uid: 2429
          gid: 2429
      hdp_repo: false
      titan:
        source: "http://10.10.10.1/titan-0.5.4-hadoop2.zip"
        install_dir: "/opt/titan"
        home: "/opt/titan/current"
        version: "0.5.4"
        config:
          "storage.backend": "hbase"
          "storage.hostname": "master1.ryba,master2.ryba,master3.ryba"
          "storage.hbase.table": "titan"
          "storage.hbase.short-cf-names": true
          "index.search.backend": "elasticsearch"
          "index.search.hostname": "master3.ryba"
          "index.search.elasticsearch.client-only": true
          "index.search.elasticsearch.cluster-name": "elasticsearch"
          "cache.db-cache": true
          "cache.db-cache-clean-wait": 20
          "cache.db-cache-time": 180000
          "cache.db-cache-size": 0.5
      tez:
        site:
          "tez.am.resource.memory.mb": 256
          "tez.task.resource.memory.mb": "512"
          "tez.runtime.io.sort.mb": "204"
          "tez.lib.uris": "/hdp/apps/${hdp.version}/tez/tez.tar.gz"
          "hive.tez.java.opts": "-Xmx204m"
        env:
          TEZ_CONF_DIR: "/etc/tez/conf"
          TEZ_JARS: "/usr/hdp/current/tez-client/*:/usr/hdp/current/tez-client/lib/*"
          HADOOP_CLASSPATH: "$TEZ_CONF_DIR:$TEZ_JARS:$HADOOP_CLASSPATH"
      graphite:
        carbon_port: 2023
        carbon_cache_port: 2003
        carbon_aggregator_port: 2023
        metrics_prefix: "hadoop"
        carbon_rewrite_rules: [
          "[pre]"
          "^(?P<cluster>w+).hbase.[a-zA-Z0-9_.,:;-=]*Context=(?P<context>w+).Hostname=(?P<host>w+).(?P<metric>.w+)*$ = g<cluster>.g<host>.hbase.g<context>g<metric>"
          "^(?P<cluster>w+).(?P<bean>w+).(?P<foobar>w+).Hostname=(?P<host>w+).(?P<metric>.w+)*$ = g<cluster>.g<host>.g<foobar>g<metric>"
          "^(?P<cluster>w+).(?P<bean>w+).[a-zA-Z0-9_.=]*port=(?P<port>w+).Context=(?P<context>w+).[a-zA-Z0-9_.=]*Hostname=(?P<host>w+).(?P<metric>.w+)*$ = g<cluster>.g<host>.g<context>.g<port>g<metric>"
          "^(?P<cluster>w+).(?P<bean>w+).[a-zA-Z0-9_.=]*Queue=root(?P<queue>.w+\b)*.Context=(?P<context>w+).[a-zA-Z0-9_.=]*Hostname=(?P<host>w+).(?P<metric>.w+)*$ = g<cluster>.g<host>.g<context>.queue.g<queue>g<metric>"
          "^(?P<cluster>w+).(?P<bean>w+).[a-zA-Z0-9_.=]*Context=(?P<context>w+).ProcessName=(?P<process>w+).[a-zA-Z0-9_.=]*Hostname=(?P<host>w+).(?P<metric>.w+)*$ = g<cluster>.g<host>.g<context>.g<process>g<metric>"
          "^(?P<cluster>w+).(?P<bean>w+).[a-zA-Z0-9_.=]*Context=(?P<context>w+).[a-zA-Z0-9_.=]*Hostname=(?P<host>w+).(?P<metric>.w+)*$ = g<cluster>.g<host>.g<context>g<metric>"
          "rpcdetailed = rpc"
        ]
        carbon_conf: [
          "[aggregator]"
          "LINE_RECEIVER_INTERFACE = 0.0.0.0"
          "LINE_RECEIVER_PORT = 2023"
          "PICKLE_RECEIVER_INTERFACE = 0.0.0.0"
          "PICKLE_RECEIVER_PORT = 2024"
          "LOG_LISTENER_CONNECTIONS = True"
          "FORWARD_ALL = True"
          "DESTINATIONS = 127.0.0.1:2004"
          "REPLICATION_FACTOR = 1"
          "MAX_QUEUE_SIZE = 10000"
          "USE_FLOW_CONTROL = True"
          "MAX_DATAPOINTS_PER_MESSAGE = 500"
          "MAX_AGGREGATION_INTERVALS = 5"
          "# WRITE_BACK_FREQUENCY = 0"
        ]
      proxy: null
      db_admin:
        engine: "mysql"
        host: "master3.ryba"
        path: "mysql"
        port: "3306"
        username: "root"
        password: "test123"
      hadoop_conf_dir: "/etc/hadoop/conf"
      hadoop_lib_home: "/usr/hdp/current/hadoop-client/lib"
      active_nn: false
      standby_nn_host: "master2.ryba"
      static_host: "_HOST"
      active_nn_host: "master1.ryba"
      core_jars: {}
      hadoop_classpath: ""
      hadoop_client_opts: "-Xmx2048m"
      hadoop_policy: {}
      ssl_client:
        "ssl.client.truststore.location": "/etc/hadoop/conf/truststore"
        "ssl.client.truststore.password": "ryba123"
        "ssl.client.truststore.type": "jks"
      ssl_server:
        "ssl.server.keystore.location": "/etc/hadoop/conf/keystore"
        "ssl.server.keystore.password": "ryba123"
        "ssl.server.keystore.type": "jks"
        "ssl.server.keystore.keypassword": "ryba123"
        "ssl.server.truststore.location": "/etc/hadoop/conf/truststore"
        "ssl.server.truststore.password": "ryba123"
        "ssl.server.truststore.type": "jks"
      webhcat:
        conf_dir: "/etc/hive-webhcat/conf"
        log_dir: "/var/log/webhcat"
        pid_dir: "/var/run/webhcat"
        site:
          "templeton.storage.class": "org.apache.hive.hcatalog.templeton.tool.ZooKeeperStorage"
          "templeton.jar": "/usr/lib/hive-hcatalog/share/webhcat/svr/lib/hive-webhcat-0.13.0.2.1.2.0-402.jar"
          "templeton.hive.properties": "hive.metastore.local=false,hive.metastore.uris=thrift://master2.ryba:9083,thrift://master3.ryba:9083,hive.metastore.sasl.enabled=yes,hive.metastore.execute.setugi=true,hive.metastore.warehouse.dir=/apps/hive/warehouse,hive.metastore.kerberos.principal=HTTP/_HOST@hive/_HOST@HADOOP.RYBA"
          "templeton.kerberos.principal": "HTTP/master3.ryba@HADOOP.RYBA"
          "templeton.kerberos.keytab": "/etc/security/keytabs/spnego.service.keytab"
          "templeton.kerberos.secret": "secret"
          "webhcat.proxyuser.hue.groups": "*"
          "webhcat.proxyuser.hue.hosts": "*"
          "webhcat.proxyuser.knox.groups": "*"
          "webhcat.proxyuser.knox.hosts": "*"
          "templeton.port": 50111
          "templeton.controller.map.mem": 1600
      force_war: false
    httpd:
      user:
        uid: 2416
        gid: 2416
        name: "apache"
        system: true
        comment: "Apache HTTPD User"
        home: "/var/www"
        shell: false
      group:
        gid: 2416
        name: "apache"
        system: true
      startup: "235"
      action: "start"
    xasecure:
      group:
        gid: 2417
      user:
        uid: 2417
        gid: 2417
    proxy:
      system: false
      system_file: "/etc/profile.d/phyla_proxy.sh"
      host: null
      port: null
      username: null
      password: null
      secure: null
      http_proxy: null
      https_proxy: null
      http_proxy_no_auth: null
      https_proxy_no_auth: null
    curl:
      check: false
      config:
        noproxy: "localhost,127.0.0.1,.ryba"
        proxy: null
      merge: true
      users: true
      proxy: true
      check_match: {}
    profile:
      "proxy.sh": ""
    ntp:
      servers: [
        "master3.ryba"
      ]
      fudge: 10
      lag: 2000
    hdp:
      hue_smtp_host: ""
    ambari: {}
    ip: "10.10.10.13"
    modules: [
      "masson/core/reload"
      "masson/core/bind_server"
      "masson/core/fstab"
      "masson/core/network"
      "masson/core/network_check"
      "masson/core/users"
      "masson/core/ssh"
      "masson/core/ntp"
      "masson/core/proxy"
      "masson/core/yum"
      "masson/core/security"
      "masson/core/iptables"
      "masson/core/openldap_server"
      "masson/core/openldap_server/install_tls"
      "masson/core/openldap_server/install_acl"
      "masson/core/openldap_server/install_krb5"
      "masson/core/openldap_client"
      "masson/commons/phpldapadmin"
      "masson/core/krb5_server"
      "masson/core/sssd"
      "masson/commons/docker"
      "masson/commons/mysql_server"
      "ryba/zookeeper/server"
      "ryba/hadoop/hdfs_jn"
      "ryba/hadoop/httpfs"
      "ryba/hadoop/yarn_ts"
      "ryba/hadoop/mapred_jhs"
      "ryba/hive/hcatalog"
      "ryba/hive/server2"
      "ryba/hive/webhcat"
      "ryba/hbase/rest"
      "ryba/oozie/server"
      "ryba/elasticsearch"
      "ryba/rexster"
      "ryba/kafka/broker"
      "ryba/opentsdb"
      "ryba/nagios"
    ]
    host: "master3.ryba"
    shortname: "master3"
    metrics_sinks:
      file:
        class: "org.apache.hadoop.metrics2.sink.FileSink"
        filename: "metrics.out"
      ganglia:
        class: "org.apache.hadoop.metrics2.sink.ganglia.GangliaSink31"
        period: "10"
        supportparse: "true"
        slope: "jvm.metrics.gcCount=zero,jvm.metrics.memHeapUsedM=both"
        dmax: "jvm.metrics.threadsBlocked=70,jvm.metrics.memHeapUsedM=40"
      graphite:
        class: "org.apache.hadoop.metrics2.sink.GraphiteSink"
        period: "10"
    hostname: "master3.ryba"
    groups: {}
    fstab:
      enabled: false
      exhaustive: false
      volumes: {}
    phpldapadmin:
      config_path: "/etc/phpldapadmin/config.php"
      config_httpd_path: "/etc/httpd/conf.d/phpldapadmin.conf"
    docker:
      nsenter: true
  "front1.ryba":
    connection:
      private_key: '''
        -----BEGIN RSA PRIVATE KEY-----
        MIIEogIBAAKCAQEArBDFt50aN9jfIJ629pRGIMA1fCMb9RyTHt9A+jx3FOsIOtJs
        eaBIpv98drbFVURr+cUs/CrgGVk5k2NIeiz0bG4ONV5nTwx38z5CzqLb7UryZS3i
        a/TS14fWOxvWTRR27R71ePX90G/ZIReKFeTrucw9y9Pl+xAzsmeblRwLBxv/SWBX
        Uai2mHAZaejlG9dGkn9f2n+oPmbgk6krLMCjLhlNBnkdroBNSXGA9ewLPFF4y54Q
        kBqmG3eLzCqAKAzwyJ5PpybtNGAWfN81gY/P5LBzC66WdtEzpwsYAv1wCioqggtg
        xVZN2s0ajxQrCxahRkXstBI2IDcm2qUTxaDbUwIDAQABAoIBAFruOi7AvXxKBhCt
        D6/bx/vC2AEUZM/yG+Wywhn8HkpVsvGzBlR4Wiy208XA7SQUlqNWimFxHyEGQCEd
        1M2MOFedCbE2hI4H3tQTUSb2dhc/Bj5mM0QuC8aPKK3wFh6B9B93vu3/wfSHR03v
        rK/JXLHBt96hyuYVN9zOWDBCs6k7SdQ2BcsQLiPg6feTsZelJDuO+DO65kKLMiz3
        mNPThErklRaKovNk47LSYakk6gsJXrpG6JWQ6nwsRenwplDwZ8Zs9mlRi7f3nChM
        3I1WlISN8y2kcQBQ94YZKk8wzH/lzmxsabcLa5ETNubxQ6ThDu1oYUIIUsQyNPm+
        DkW0VwECgYEA5MttelspKexWS39Y3sQYvZ/v8VZBQl4tRbpUWWc+PNEtcEwOBza/
        H4jBWYd2eWKTApJT1st58E4b34Mv88nQVElLb3sE7uJMkihPyNpABGbCvr63hDYw
        PyL53nKaPelY/aDnL0F8LmREfdKw/uy6+UChgkPfdo2VVk1oyvsZaRMCgYEAwIZ+
        lCmeXQ4mU6uxO+ChhDn7zw9rR5qlCyfJiLPe2lV20vaHV5ZfKIWGegsVJSpFr2ST
        5ghh+FVIneoNRtTHEKwNWCK7I6qeF+WAaci+KsLQigJQHsw58n9cdA7wHHc475n/
        pf7efoPcvk6qYOS2mpDgC87m+o3C4Dyspqp9TMECgYA4/ed+dBjT5Zg1ZDp5+zUC
        f0Wgw1CsPJNgbCK4xnv9YEnGUFuqNlvzefhX2eOMJx7hpBuYRMVSM9LDoYUfYCUx
        6bQNyAIZk2tpePsu2BbcQdC+/PjvySPJhmfhnoCHbYoKW7tazSAm2jkpcoM+bS/C
        CPRyY3/Voz0Q62VwMo5I2wKBgB4mMbZUGieqapgZwASHdeO2DNftKzioYAYyMd5F
        hLWeQqBg2Or/cmFvH5MHH0WVrBn+Xybb0zPHbzrDh1a7RX035FMUBUhdlKpbV1O5
        iwY5Qd0K5a8c/koaZckK+dELXpAvBpjhI8ieL7hhq07HIk1sOJnAye0cvBLPjZ3/
        /uVBAoGAVAs6tFpS0pFlxmg4tfGEm7/aP6FhyBHNhv2QGluw8vv/XVMzUItxGIef
        HcSMWBm08IJMRJLgmoo1cuQv6hBui7JpDeZk/20qoF2oZW9lJ9fdRObJqi61wufP
        BNiriqexq/eTy2uF9RCCjLItWxUscVMlVt4V65HLkCF5WxCQw+o=
        -----END RSA PRIVATE KEY-----
      '''
      public_key: "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCsEMW3nRo32N8gnrb2lEYgwDV8Ixv1HJMe30D6PHcU6wg60mx5oEim/3x2tsVVRGv5xSz8KuAZWTmTY0h6LPRsbg41XmdPDHfzPkLOotvtSvJlLeJr9NLXh9Y7G9ZNFHbtHvV49f3Qb9khF4oV5Ou5zD3L0+X7EDOyZ5uVHAsHG/9JYFdRqLaYcBlp6OUb10aSf1/af6g+ZuCTqSsswKMuGU0GeR2ugE1JcYD17As8UXjLnhCQGqYbd4vMKoAoDPDInk+nJu00YBZ83zWBj8/ksHMLrpZ20TOnCxgC/XAKKiqCC2DFVk3azRqPFCsLFqFGRey0EjYgNybapRPFoNtT Ryba Hadoop"
      bootstrap:
        username: "vagrant"
        password: "vagrant"
        host: "10.10.10.14"
        port: 22
        cmd: "su -"
        retry: 3
      username: "root"
      host: "10.10.10.14"
      port: 22
      private_key_location: "~/.ssh/id_rsa"
      retry: 3
      end: true
      wait: 1000
    mecano:
      cache_dir: "/home/pierrotws/workspace/ryba-cluster/conf/../resources/cache"
      log_serializer: true
    log:
      archive: true
      disabled: false
      basedir: "./log"
      fqdn_reversed: "ryba.front1"
      filename: "front1.log"
      elasticsearch:
        enable: false
        url: "http://localhost:9200"
        index: "masson"
    security:
      selinux: false
      limits: {}
    network:
      hosts_auto: true
      hosts:
        "127.0.0.1": "localhost localhost.localdomain localhost4 localhost4.localdomain4"
        "10.10.10.10": "repos.ryba ryba"
      resolv: '''
        search ryba
        nameserver 10.10.10.13
        nameserver 10.0.2.3
      '''
      hostname_disabled: false
    iptables:
      action: "stop"
      startup: false
      log: true
      rules: []
      log_prefix: "IPTables-Dropped: "
      log_level: 4
      log_rules: [
        {
          chain: "INPUT"
          command: "-A"
          jump: "LOGGING"
        }
        {
          chain: "LOGGING"
          command: "-A"
          "--limit": "2/min"
          jump: "LOG"
          "log-prefix": "IPTables-Dropped: "
          "log-level": 4
        }
        {
          chain: "LOGGING"
          command: "-A"
          jump: "DROP"
        }
      ]
    bind_server:
      zones: [
        "/home/pierrotws/workspace/ryba-cluster/conf/zones/ryba"
        "/home/pierrotws/workspace/ryba-cluster/conf/zones/10.10.10.in-addr.arpa"
      ]
      user:
        uid: 802
        gid: 802
      group:
        gid: 802
    ssh:
      banner:
        destination: "/etc/banner"
        content: "Welcome to Hadoop!"
      sshd_config:
        PermitRootLogin: "without-password"
    users:
      root:
        authorized_keys: [
          "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCWvEjSt2sAvRmkpkt9+u1EXuFDWJSuI1C8G/+NMcpMRDSUTary3Njqt/DC5mx7X36mVJdaq2KqgAVa28zzeuN6Yv7iuxCTw/4K7OKXYu+q0UG8BlIknWgLa8s7Nx2J69Prkb4oFgzw5IqK9EM6VMarUJUCXVNhb3zmamrF59OIxAIyQhV5i5SzoAxLIcD9EtxS/ZRf9t9fOBEhn42SVcpEWO09bUHZ11J2tw/Pwsxk+va83cH9qipVsEwIMDUCosfzV1G2zF5HhU/mhIHWRdAULpaRfd3IgNqTtI6BBi6FOFbJdrkHXPXKRybZwCxChncq1TZI2SXx6BCRpoJ/s887 m.sauvage.pierre@gmail.com"
        ]
        name: "root"
        home: "/root"
    yum:
      packages:
        tree: true
        git: true
        htop: true
        vim: true
        "yum-plugin-priorities": true
        man: true
        ksh: true
      config:
        proxy: null
        main:
          keepcache: "0"
          proxy: null
          proxy_username: null
          proxy_password: null
      copy: "/home/pierrotws/workspace/ryba-cluster/conf/user/offline/*.repo"
      clean: false
      merge: true
      update: true
      proxy: true
      epel: true
      epel_url: "http://download.fedoraproject.org/pub/epel/6/i386/epel-release-6-8.noarch.rpm"
    mysql:
      server:
        current_password: ""
        password: "test123"
        my_cnf:
          mysqld:
            innodb_file_per_table: "1"
    openldap_server:
      suffix: "dc=ryba"
      root_dn: "cn=Manager,dc=ryba"
      root_password: "test"
      config_dn: "cn=admin,cn=config"
      config_password: "test"
      users_dn: "ou=users,dc=ryba"
      groups_dn: "ou=groups,dc=ryba"
      ldapdelete: []
      ldapadd: []
      tls: true
      tls_ca_cert_file: "/home/pierrotws/workspace/ryba-cluster/conf/certs/cacert.pem"
      tls_cert_file: "/home/pierrotws/workspace/ryba-cluster/conf/certs/master3_cert.pem"
      tls_key_file: "/home/pierrotws/workspace/ryba-cluster/conf/certs/master3_key.pem"
      proxy_user:
        uidNumber: 801
        gidNumber: 801
      proxy_group:
        gidNumber: 801
    openldap_client:
      certificates: [
        "/home/pierrotws/workspace/ryba-cluster/conf/certs/master3_cert.pem"
      ]
      config:
        BASE: "dc=ryba"
        URI: "ldaps://master3.ryba"
        TLS_CACERTDIR: "/etc/openldap/cacerts"
        TLS_REQCERT: "allow"
        TIMELIMIT: "15"
        TIMEOUT: "20"
      suffix: "dc=ryba"
      root_dn: "cn=Manager,dc=ryba"
      root_password: "test"
    openldap_server_krb5:
      manager_dn: "cn=Manager,dc=ryba"
      manager_password: "test"
      krbadmin_user:
        mail: "david@adaltas.com"
        userPassword: "test"
        uidNumber: 800
        gidNumber: 800
      krbadmin_group:
        gidNumber: 800
    krb5:
      etc_krb5_conf:
        logging:
          default: "SYSLOG:INFO:LOCAL1"
          kdc: "SYSLOG:NOTICE:LOCAL1"
          admin_server: "SYSLOG:WARNING:LOCAL1"
        libdefaults:
          dns_lookup_realm: false
          dns_lookup_kdc: false
          ticket_lifetime: "24h"
          renew_lifetime: "7d"
          forwardable: true
          allow_weak_crypto: "false"
          clockskew: "300"
          rdns: "false"
          default_realm: "HADOOP.RYBA"
        realms:
          "USERS.RYBA":
            kadmin_principal: "wdavidw/admin@USERS.RYBA"
            kadmin_password: "test"
            principals: [
              {
                principal: "krbtgt/HADOOP.RYBA@USERS.RYBA"
                password: "test"
              }
            ]
            kdc: [
              "master3.ryba"
            ]
            admin_server: "master3.ryba"
            default_domain: "users.ryba"
          "HADOOP.RYBA":
            kadmin_principal: "wdavidw/admin@HADOOP.RYBA"
            kadmin_password: "test"
            principals: [
              {
                principal: "krbtgt/HADOOP.RYBA@USERS.RYBA"
                password: "test"
              }
            ]
            kdc: [
              "master1.ryba"
            ]
            admin_server: "master1.ryba"
            default_domain: "hadoop.ryba"
        domain_realm:
          ryba: "HADOOP.RYBA"
        appdefaults:
          pam:
            debug: false
            ticket_lifetime: 36000
            renew_lifetime: 36000
            forwardable: true
            krb4_convert: false
        dbmodules: {}
      kdc_conf:
        realms: {}
      sshd: {}
      kinit: "/usr/bin/kinit"
    sssd:
      force_check: false
      certificates: [
        "/home/pierrotws/workspace/ryba-cluster/conf/certs/cacert.pem"
      ]
      config:
        sssd:
          config_file_version: "2"
          reconnection_retries: "3"
          sbus_timeout: "30"
          services: "nss, pam"
          debug_level: "1"
          domains: "hadoop,users"
        nss:
          filter_groups: "root"
          filter_users: "root"
          reconnection_retries: "3"
          entry_cache_timeout: "300"
          entry_cache_nowait_percentage: "75"
          debug_level: "1"
        pam:
          reconnection_retries: "3"
          offline_credentials_expiration: "2"
          offline_failed_login_attempts: "3"
          offline_failed_login_delay: "5"
          debug_level: "1"
        "domain/hadoop":
          debug_level: "1"
          cache_credentials: "True"
          ldap_search_base: "ou=users,dc=ryba"
          ldap_group_search_base: "ou=groups,dc=ryba"
          id_provider: "ldap"
          auth_provider: "ldap"
          chpass_provider: "ldap"
          ldap_uri: "ldaps://master3.ryba:636"
          ldap_tls_cacertdir: "/etc/openldap/cacerts"
          ldap_default_bind_dn: "cn=Manager,dc=ryba"
          ldap_default_authtok: "test"
          ldap_id_use_start_tls: "True"
        "domain/users":
          debug_level: "1"
          cache_credentials: "True"
          ldap_search_base: "ou=users,dc=ryba"
          ldap_group_search_base: "ou=groups,dc=ryba"
          id_provider: "ldap"
          auth_provider: "ldap"
          chpass_provider: "ldap"
          ldap_uri: "ldaps://master3.ryba:636"
          ldap_tls_cacertdir: "/etc/openldap/cacerts"
          ldap_default_bind_dn: "cn=Manager,dc=ryba"
          ldap_default_authtok: "test"
          ldap_id_use_start_tls: "False"
      merge: false
      test_user: null
    java:
      java_home: "/usr/lib/jvm/java"
      jre_home: "/usr/lib/jvm/java/jre"
      proxy: null
      openjdk: true
    ryba:
      clean_logs: true
      force_check: false
      check_hdfs_fsck: false
      security: "kerberos"
      realm: "HADOOP.RYBA"
      nameservice: "torval"
      krb5_user:
        password: "test123"
        password_sync: true
        principal: "ryba@HADOOP.RYBA"
      ssl:
        cacert: "/home/pierrotws/workspace/ryba-cluster/conf/certs/cacert.pem"
        cert: "/home/pierrotws/workspace/ryba-cluster/conf/certs/front1_cert.pem"
        key: "/home/pierrotws/workspace/ryba-cluster/conf/certs/front1_key.pem"
      ambari:
        repo: "/home/pierrotws/workspace/ryba-cluster/conf/resources/repos/ambari-2.0.0.repo"
      ssh_fencing:
        private_key: "/home/pierrotws/workspace/ryba-cluster/conf/hdfs_keys/id_rsa"
        public_key: "/home/pierrotws/workspace/ryba-cluster/conf/hdfs_keys/id_rsa.pub"
      hadoop_opts: "-Djava.net.preferIPv4Stack=true -Dsun.security.krb5.debug=false"
      core_site:
        "hadoop.ssl.exclude.cipher.suites": "SSL_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA,SSL_RSA_EXPORT_WITH_DES40_CBC_SHA,SSL_RSA_EXPORT_WITH_RC4_40_MD5,TLS_DHE_RSA_WITH_AES_128_CBC_SHA,TLS_DHE_RSA_WITH_AES_256_CBC_SHA"
        "io.compression.codecs": "org.apache.hadoop.io.compress.GzipCodec,org.apache.hadoop.io.compress.DefaultCodec,org.apache.hadoop.io.compress.SnappyCodec"
        "fs.defaultFS": "hdfs://torval:8020"
        "hadoop.security.authentication": "kerberos"
        "hadoop.security.authorization": "true"
        "hadoop.rpc.protection": "authentication"
        "hadoop.security.group.mapping": "org.apache.hadoop.security.JniBasedUnixGroupsMappingWithFallback"
        "ha.zookeeper.quorum": [
          "master1.ryba:2181"
          "master2.ryba:2181"
          "master3.ryba:2181"
        ]
        "net.topology.script.file.name": "/etc/hadoop/conf/rack_topology.sh"
        "hadoop.http.filter.initializers": "org.apache.hadoop.security.AuthenticationFilterInitializer"
        "hadoop.http.authentication.type": "kerberos"
        "hadoop.http.authentication.token.validity": "36000"
        "hadoop.http.authentication.signature.secret.file": "/etc/hadoop/hadoop-http-auth-signature-secret"
        "hadoop.http.authentication.simple.anonymous.allowed": "false"
        "hadoop.http.authentication.kerberos.principal": "HTTP/_HOST@HADOOP.RYBA"
        "hadoop.http.authentication.kerberos.keytab": "/etc/security/keytabs/spnego.service.keytab"
        "hadoop.http.authentication.cookie.domain": "ryba"
        "hadoop.security.auth_to_local": '''
          
          RULE:[2:$1@$0]([rn]m@HADOOP\\.RYBA)s/.*/yarn/
          RULE:[2:$1@$0](jhs@HADOOP\\.RYBA)s/.*/mapred/
          RULE:[2:$1@$0]([nd]n@HADOOP\\.RYBA)s/.*/hdfs/
          RULE:[2:$1@$0](hm@HADOOP\\.RYBA)s/.*/hbase/
          RULE:[2:$1@$0](rs@HADOOP\\.RYBA)s/.*/hbase/
          RULE:[2:$1@$0](opentsdb@HADOOP\\.RYBA)s/.*/hbase/
          DEFAULT
          RULE:[1:$1](yarn|mapred|hdfs|hive|hbase|oozie)s/.*/nobody/
          RULE:[2:$1](yarn|mapred|hdfs|hive|hbase|oozie)s/.*/nobody/
          RULE:[1:$1]
          RULE:[2:$1]
          
        '''
        "hadoop.proxyuser.HTTP.hosts": "*"
        "hadoop.proxyuser.HTTP.groups": "*"
        "hadoop.ssl.require.client.cert": "false"
        "hadoop.ssl.hostname.verifier": "DEFAULT"
        "hadoop.ssl.keystores.factory.class": "org.apache.hadoop.security.ssl.FileBasedKeyStoresFactory"
        "hadoop.ssl.server.conf": "ssl-server.xml"
        "hadoop.ssl.client.conf": "ssl-client.xml"
      hadoop_metrics:
        "*.sink.file.class": "org.apache.hadoop.metrics2.sink.FileSink"
        sinks:
          file: true
          ganglia: false
          graphite: false
        config:
          "*.period": "60"
          "*.sink.file.class": "org.apache.hadoop.metrics2.sink.FileSink"
          "*.sink.file.filename": "metrics.out"
          "namenode.sink.file.filename": "namenode-metrics.out"
          "datanode.sink.file.filename": "datanode-metrics.out"
          "resourcemanager.sink.file.filename": "resourcemanager-metrics.out"
          "nodemanager.sink.file.filename": "nodemanager-metrics.out"
          "mrappmaster.sink.file.filename": "mrappmaster-metrics.out"
          "jobhistoryserver.sink.file.filename": "jobhistoryserver-metrics.out"
      hadoop_heap: "512"
      hadoop_namenode_init_heap: "-Xms512m"
      hdfs:
        user:
          limits:
            nproc: 16384
            nofile: 16384
          uid: 2401
          gid: "hdfs"
          name: "hdfs"
          system: true
          groups: "hadoop"
          comment: "Hadoop HDFS User"
          home: "/var/lib/hadoop-hdfs"
        krb5_user:
          password: "hdfs123"
          password_sync: true
          principal: "hdfs@HADOOP.RYBA"
        sysctl:
          "vm.swappiness": 0
          "vm.overcommit_memory": 1
          "vm.overcommit_ratio": 100
          "net.core.somaxconn": 1024
        site:
          "dfs.namenode.safemode.extension": 1000
          "dfs.replication": 2
          "dfs.http.policy": "HTTPS_ONLY"
          "dfs.namenode.kerberos.principal.pattern": "*"
          "dfs.namenode.kerberos.principal": "nn/_HOST@HADOOP.RYBA"
          "dfs.namenode.kerberos.internal.spnego.principal": "HTTP/_HOST@HADOOP.RYBA"
          "dfs.namenode.kerberos.https.principal": "HTTP/_HOST@HADOOP.RYBA"
          "dfs.web.authentication.kerberos.principal": "HTTP/_HOST@HADOOP.RYBA"
          "dfs.ha.automatic-failover.enabled": "true"
          "dfs.nameservices": "torval"
          "dfs.internal.nameservices": "torval"
          "dfs.ha.namenodes.torval": "master1,master2"
          "dfs.namenode.http-address": null
          "dfs.namenode.https-address": null
          "dfs.namenode.rpc-address.torval.master1": "master1.ryba:8020"
          "dfs.namenode.http-address.torval.master1": "master1.ryba:50070"
          "dfs.namenode.https-address.torval.master1": "master1.ryba:50470"
          "dfs.namenode.rpc-address.torval.master2": "master2.ryba:8020"
          "dfs.namenode.http-address.torval.master2": "master2.ryba:50070"
          "dfs.namenode.https-address.torval.master2": "master2.ryba:50470"
          "dfs.client.failover.proxy.provider.torval": "org.apache.hadoop.hdfs.server.namenode.ha.ConfiguredFailoverProxyProvider"
          "dfs.datanode.kerberos.principal": "dn/_HOST@HADOOP.RYBA"
          "dfs.client.read.shortcircuit": "true"
          "dfs.domain.socket.path": "/var/lib/hadoop-hdfs/dn_socket"
        group:
          gid: 2401
          name: "hdfs"
          system: true
        log_dir: "/var/log/hadoop-hdfs"
        pid_dir: "/var/run/hadoop-hdfs"
        secure_dn_pid_dir: "/var/run/hadoop-hdfs"
        secure_dn_user: "hdfs"
      zkfc:
        digest:
          name: "zkfc"
          password: "zkfc123"
      yarn:
        user:
          limits:
            nproc: 16384
            nofile: 16384
          uid: 2403
          gid: "yarn"
          name: "yarn"
          system: true
          groups: "hadoop"
          comment: "Hadoop YARN User"
          home: "/var/lib/hadoop-yarn"
        opts: "-Dsun.net.spi.nameservice.provider.1=sun,dns"
        site:
          "yarn.http.policy": "HTTPS_ONLY"
          "yarn.application.classpath": "$HADOOP_CONF_DIR,/usr/hdp/current/hadoop-client/*,/usr/hdp/current/hadoop-client/lib/*,/usr/hdp/current/hadoop-hdfs-client/*,/usr/hdp/current/hadoop-hdfs-client/lib/*,/usr/hdp/current/hadoop-yarn-client/*,/usr/hdp/current/hadoop-yarn-client/lib/*"
          "yarn.generic-application-history.save-non-am-container-meta-info": "true"
          "yarn.timeline-service.enabled": "true"
          "yarn.timeline-service.address": "master3.ryba:10200"
          "yarn.timeline-service.webapp.address": "master3.ryba:8188"
          "yarn.timeline-service.webapp.https.address": "master3.ryba:8190"
          "yarn.timeline-service.principal": "ats/_HOST@HADOOP.RYBA"
          "yarn.timeline-service.http-authentication.type": "kerberos"
          "yarn.timeline-service.http-authentication.kerberos.principal": "HTTP/_HOST@HADOOP.RYBA"
          "yarn.nodemanager.remote-app-log-dir": "/app-logs"
          "yarn.resourcemanager.principal": "rm/_HOST@HADOOP.RYBA"
          "yarn.resourcemanager.cluster-id": "yarn_cluster_01"
          "yarn.resourcemanager.ha.enabled": "true"
          "yarn.resourcemanager.ha.rm-ids": "master1,master2"
          "yarn.resourcemanager.webapp.delegation-token-auth-filter.enabled": "true"
          "yarn.resourcemanager.address.master1": "master1.ryba:8050"
          "yarn.resourcemanager.scheduler.address.master1": "master1.ryba:8030"
          "yarn.resourcemanager.admin.address.master1": "master1.ryba:8141"
          "yarn.resourcemanager.webapp.address.master1": "master1.ryba:8088"
          "yarn.resourcemanager.webapp.https.address.master1": "master1.ryba:8090"
          "yarn.resourcemanager.address.master2": "master2.ryba:8050"
          "yarn.resourcemanager.scheduler.address.master2": "master2.ryba:8030"
          "yarn.resourcemanager.admin.address.master2": "master2.ryba:8141"
          "yarn.resourcemanager.webapp.address.master2": "master2.ryba:8088"
          "yarn.resourcemanager.webapp.https.address.master2": "master2.ryba:8090"
          "yarn.scheduler.minimum-allocation-mb": null
          "yarn.scheduler.maximum-allocation-mb": null
        group:
          gid: 2403
          name: "yarn"
          system: true
        log_dir: "/var/log/hadoop-yarn"
        pid_dir: "/var/run/hadoop-yarn"
        conf_dir: "/etc/hadoop/conf"
        heapsize: "1024"
        home: "/usr/hdp/current/hadoop-yarn-client"
      capacity_scheduler:
        "yarn.scheduler.capacity.maximum-am-resource-percent": ".5"
      mapred:
        user:
          limits:
            nproc: 16384
            nofile: 16384
          uid: 2404
          gid: "mapred"
          name: "mapred"
          system: true
          groups: "hadoop"
          comment: "Hadoop MapReduce User"
          home: "/var/lib/hadoop-mapreduce"
        site:
          "mapreduce.job.counters.max": "10000"
          "mapreduce.job.counters.limit": "10000"
          "yarn.app.mapreduce.am.resource.mb": "256"
          "yarn.app.mapreduce.am.command-opts": "-Xmx204m"
          "mapreduce.map.memory.mb": "512"
          "mapreduce.reduce.memory.mb": "1024"
          "mapreduce.map.java.opts": "-Xmx409m"
          "mapreduce.reduce.java.opts": "-Xmx819m"
          "mapreduce.task.io.sort.mb": "204"
          "mapreduce.map.cpu.vcores": "1"
          "mapreduce.reduce.cpu.vcores": "1"
          "mapreduce.reduce.shuffle.parallelcopies": "50"
          "mapreduce.admin.map.child.java.opts": "-server -Djava.net.preferIPv4Stack=true -Dhdp.version=${hdp.version}"
          "mapreduce.admin.reduce.child.java.opts": null
          "mapreduce.task.io.sort.factor": 100
          "mapreduce.admin.user.env": "LD_LIBRARY_PATH=/usr/hdp/${hdp.version}/hadoop/lib/native:/usr/hdp/${hdp.version}/hadoop/lib/native/Linux-amd64-64"
          "mapreduce.application.framework.path": "/hdp/apps/${hdp.version}/mapreduce/mapreduce.tar.gz#mr-framework"
          "mapreduce.application.classpath": "$PWD/mr-framework/hadoop/share/hadoop/mapreduce/*:$PWD/mr-framework/hadoop/share/hadoop/mapreduce/lib/*:$PWD/mr-framework/hadoop/share/hadoop/common/*:$PWD/mr-framework/hadoop/share/hadoop/common/lib/*:$PWD/mr-framework/hadoop/share/hadoop/yarn/*:$PWD/mr-framework/hadoop/share/hadoop/yarn/lib/*:$PWD/mr-framework/hadoop/share/hadoop/hdfs/*:$PWD/mr-framework/hadoop/share/hadoop/hdfs/lib/*:/usr/hdp/current/share/lzo/0.6.0/lib/hadoop-lzo-0.6.0.jar:/etc/hadoop/conf/secure"
          "yarn.app.mapreduce.am.staging-dir": "/user"
          "mapreduce.jobhistory.address": "master3.ryba:10020"
          "mapreduce.jobhistory.webapp.address": "master3.ryba:19888"
          "mapreduce.jobhistory.webapp.https.address": "master3.ryba:19889"
          "mapreduce.jobhistory.done-dir": null
          "mapreduce.jobhistory.intermediate-done-dir": null
          "mapreduce.jobhistory.principal": "jhs/master3.ryba@HADOOP.RYBA"
          "yarn.app.mapreduce.am.job.client.port-range": "59100-59200"
          "mapreduce.framework.name": "yarn"
          "mapreduce.cluster.local.dir": null
          "mapreduce.jobtracker.system.dir": null
        group:
          gid: 2404
          name: "mapred"
          system: true
        log_dir: "/var/log/hadoop-mapreduce"
        pid_dir: "/var/run/hadoop-mapreduce"
      hive:
        user:
          limits:
            nproc: 16384
            nofile: 16384
          uid: 2407
          gid: "hive"
          name: "hive"
          system: true
          groups: "hadoop"
          comment: "Hive User"
          home: "/var/lib/hive"
        site:
          "javax.jdo.option.ConnectionDriverName": "com.mysql.jdbc.Driver"
          "javax.jdo.option.ConnectionUserName": null
          "javax.jdo.option.ConnectionPassword": null
          "hive.tez.container.size": "512"
          "hive.tez.java.opts": "-Xmx409m"
          " hive.metastore.uris ": null
          " hive.cluster.delegation.token.store.class ": null
          "hive.metastore.local": null
          "fs.hdfs.impl.disable.cache": "false"
          "fs.file.impl.disable.cache": "false"
          "hive.server2.thrift.sasl.qop": "auth"
          "hive.metastore.sasl.enabled": "true"
          "hive.metastore.kerberos.keytab.file": "/etc/hive/conf/hive.service.keytab"
          "hive.metastore.kerberos.principal": "hive/_HOST@HADOOP.RYBA"
          "hive.metastore.cache.pinobjtypes": "Table,Database,Type,FieldSchema,Order"
          "hive.security.authorization.manager": "org.apache.hadoop.hive.ql.security.authorization.StorageBasedAuthorizationProvider"
          "hive.security.metastore.authorization.manager": "org.apache.hadoop.hive.ql.security.authorization.StorageBasedAuthorizationProvider"
          "hive.security.authenticator.manager": "org.apache.hadoop.hive.ql.security.ProxyUserAuthenticator"
          "hive.security.metastore.authenticator.manager": "org.apache.hadoop.hive.ql.security.HadoopDefaultMetastoreAuthenticator"
          "hive.metastore.pre.event.listeners": "org.apache.hadoop.hive.ql.security.authorization.AuthorizationPreEventListener"
          "hive.optimize.mapjoin.mapreduce": null
          "hive.heapsize": null
          "hive.auto.convert.sortmerge.join.noconditionaltask": null
          "hive.exec.max.created.files": "100000"
          "hive.exec.compress.intermediate": "true"
          "hive.auto.convert.join": "true"
          "hive.cli.print.header": "false"
          "hive.execution.engine": "mr"
          "hive.exec.reducers.bytes.per.reducer": "268435456"
          "hive.metastore.uris": "thrift://master2.ryba:9083,thrift://master3.ryba:9083"
          "hive.security.authorization.enabled": "true"
          "hive.server2.authentication": "KERBEROS"
          "hive.support.concurrency": "true"
          "hive.zookeeper.quorum": "master1.ryba:2181,master2.ryba:2181,master3.ryba:2181"
          "hive.enforce.bucketing": "true"
          "hive.exec.dynamic.partition.mode": "nonstrict"
          "hive.txn.manager": "org.apache.hadoop.hive.ql.lockmgr.DbTxnManager"
          "hive.txn.timeout": "300"
          "hive.txn.max.open.batch": "1000"
          "hive.cluster.delegation.token.store.class": "org.apache.hadoop.hive.thrift.DBTokenStore"
        group:
          gid: 2407
          name: "hive"
          system: true
        conf_dir: "/etc/hive/conf"
        aux_jars: [
          "/usr/hdp/current/hive-webhcat/share/hcatalog/hive-hcatalog-core.jar"
          "/usr/hdp/current/phoenix-server.jar"
        ]
        client:
          opts: ""
          heapsize: 1024
          truststore_location: "/etc/hive/conf/truststore"
          truststore_password: "ryba123"
      hue:
        ini:
          desktop:
            smtp:
              host: ""
            database:
              engine: "mysql"
              password: "hue123"
        ssl:
          certificate: "/home/pierrotws/workspace/ryba-cluster/conf/certs/master3_cert.pem"
          private_key: "/home/pierrotws/workspace/ryba-cluster/conf/certs/master3_key.pem"
          client_ca: "/home/pierrotws/workspace/ryba-cluster/conf/certs/cacert.pem"
        group:
          gid: 2410
        user:
          uid: 2410
          gid: 2410
      sqoop:
        libs: []
        user:
          uid: 2412
          gid: 2400
          name: "sqoop"
          system: true
          comment: "Sqoop User"
          home: "/var/lib/sqoop"
        conf_dir: "/etc/sqoop/conf"
        site: {}
      hbase:
        regionserver_opts: "-Xmx512m"
        admin:
          password: "hbase123"
          name: "hbase"
          principal: "hbase@HADOOP.RYBA"
        metrics:
          "*.sink.file.class": "org.apache.hadoop.metrics2.sink.FileSink"
        group:
          gid: 2409
          name: "hbase"
          system: true
        user:
          uid: 2409
          gid: "hbase"
          name: "hbase"
          system: true
          comment: "HBase User"
          home: "/var/run/hbase"
          groups: "hadoop"
          limits:
            nofile: 64000
            nproc: true
        test:
          default_table: "ryba"
        conf_dir: "/etc/hbase/conf"
        log_dir: "/var/log/hbase"
        pid_dir: "/var/run/hbase"
        site:
          "zookeeper.znode.parent": "/hbase"
          "hbase.cluster.distributed": "true"
          "hbase.rootdir": "hdfs://torval:8020/apps/hbase/data"
          "hbase.zookeeper.quorum": "master1.ryba,master2.ryba,master3.ryba"
          "hbase.zookeeper.property.clientPort": "2181"
          "dfs.domain.socket.path": "/var/lib/hadoop-hdfs/dn_socket"
          "hbase.security.authentication": "kerberos"
          "hbase.security.authorization": "true"
          "hbase.rpc.engine": "org.apache.hadoop.hbase.ipc.SecureRpcEngine"
          "hbase.superuser": "hbase"
          "hbase.bulkload.staging.dir": "/apps/hbase/staging"
          "hbase.ipc.client.specificThreadForWriting": "true"
          "hbase.client.primaryCallTimeout.get": "10000"
          "hbase.client.primaryCallTimeout. multiget": "10000"
          "hbase.client.primaryCallTimeout.scan": "1000000"
          "hbase.meta.replicas.use": "true"
          "hbase.master.kerberos.principal": "hbase/_HOST@HADOOP.RYBA"
          "hbase.regionserver.kerberos.principal": "hbase/_HOST@HADOOP.RYBA"
        env:
          JAVA_HOME: "/usr/lib/jvm/java"
          HBASE_LOG_DIR: "/var/log/hbase"
          HBASE_OPTS: "-ea -XX:+UseConcMarkSweepGC -XX:+CMSIncrementalMode -Djava.security.auth.login.config=/etc/hbase/conf/hbase-client.jaas"
          HBASE_MASTER_OPTS: "-Xmx2048m"
          HBASE_REGIONSERVER_OPTS: "-Xmn200m -Xms4096m -Xmx4096m"
      kafka:
        broker:
          heapsize: 128
        group:
          gid: 2424
          name: "kafka"
          system: true
        user:
          uid: 2424
          gid: 2424
          name: "kafka"
          system: true
          comment: "Kafka User"
          home: "/var/lib/kafka"
        consumer:
          conf_dir: "/etc/kafka/conf"
          config:
            "zookeeper.connect": [
              "master1.ryba:2181"
              "master2.ryba:2181"
              "master3.ryba:2181"
            ]
            "group.id": "ryba-consumer-group"
            "security.protocol": "SASL_SSL"
            "ssl.truststore.location": "/etc/kafka/conf/truststore"
            "ssl.truststore.password": "ryba123"
          log4j:
            "log4j.rootLogger": "WARN, stdout"
            "log4j.appender.stdout": "org.apache.log4j.ConsoleAppender"
            "log4j.appender.stdout.layout": "org.apache.log4j.PatternLayout"
            "log4j.appender.stdout.layout.ConversionPattern": "[%d] %p %m (%c)%n"
          env:
            KAFKA_KERBEROS_PARAMS: "-Djava.security.auth.login.config=/etc/kafka/conf/kafka-client.jaas"
        producer:
          conf_dir: "/etc/kafka/conf"
          config:
            "compression.codec": "snappy"
            "security.protocol": "SASL_SSL"
            "metadata.broker.list": "master1.ryba:9096,master2.ryba:9096,master3.ryba:9096"
            "ssl.truststore.location": "/etc/kafka/conf/truststore"
            "ssl.truststore.password": "ryba123"
          log4j:
            "log4j.rootLogger": "WARN, stdout"
            "log4j.appender.stdout": "org.apache.log4j.ConsoleAppender"
            "log4j.appender.stdout.layout": "org.apache.log4j.PatternLayout"
            "log4j.appender.stdout.layout.ConversionPattern": "[%d] %p %m (%c)%n"
          env:
            KAFKA_KERBEROS_PARAMS: "-Djava.security.auth.login.config=/etc/kafka/conf/kafka-client.jaas"
      opentsdb:
        version: "2.2.0RC3"
        group:
          gid: 2428
        user:
          uid: 2428
          gid: 2428
      nagios:
        users:
          nagiosadmin:
            password: "nagios123"
            alias: "Nagios Admin"
            email: ""
          guest:
            password: "guest123"
            alias: "Nagios Guest"
            email: ""
        groups:
          admins:
            alias: "Nagios Administrators"
            members: [
              "nagiosadmin"
              "guest"
            ]
        group:
          gid: 2418
        groupcmd:
          gid: 2419
        user:
          uid: 2418
          gid: 2418
      hadoop_group:
        gid: 2400
        name: "hadoop"
        system: true
      group:
        gid: 2414
        name: "ryba"
        system: true
      user:
        uid: 2414
        gid: 2414
        name: "ryba"
        password: "password"
        system: true
        comment: "ryba User"
        home: "/home/ryba"
      zookeeper:
        group:
          gid: 2402
          name: "zookeeper"
          system: true
        user:
          uid: 2402
          gid: 2400
          name: "zookeeper"
          system: true
          groups: "hadoop"
          comment: "Zookeeper User"
          home: "/var/lib/zookeeper"
        conf_dir: "/etc/zookeeper/conf"
        log_dir: "/var/log/zookeeper"
        port: 2181
        env:
          JAVA_HOME: "/usr/lib/jvm/java"
          CLIENT_JVMFLAGS: "-Djava.security.auth.login.config=/etc/zookeeper/conf/zookeeper-client.jaas"
      flume:
        group:
          gid: 2405
          name: "flume"
          system: true
        user:
          uid: 2405
          gid: 2405
          name: "flume"
          system: true
          comment: "Flume User"
          home: "/var/lib/flume"
        conf_dir: "/etc/flume/conf"
      ganglia:
        rrdcached_group:
          gid: 2406
          name: "rrdcached"
          system: true
        rrdcached_user:
          uid: 2406
          gid: "rrdcached"
          name: "rrdcached"
          system: true
          shell: false
          comment: "RRDtool User"
          home: "/var/rrdtool/rrdcached"
        collector_port: 8649
        slaves_port: 8660
        hbase_region_port: 8660
        nn_port: 8661
        jt_port: 8662
        hm_port: 8663
        hbase_master_port: 8663
        rm_port: 8664
        jhs_port: 8666
        spark_port: 8667
      oozie:
        group:
          gid: 2411
        user:
          uid: 2411
          gid: 2411
        conf_dir: "/etc/oozie/conf"
        site:
          "oozie.base.url": "https://master3.ryba:11443/oozie"
          "oozie.service.HadoopAccessorService.kerberos.principal": "oozie/master3.ryba@HADOOP.RYBA"
          "oozie.service.JPAService.jdbc.username": null
          "oozie.service.JPAService.jdbc.password": null
      pig:
        user:
          uid: 2413
          gid: 2400
          name: "pig"
          system: true
          comment: "Pig User"
          home: "/home/pig"
        conf_dir: "/etc/pig/conf"
        config: {}
      knox:
        group:
          gid: 2420
          name: "knox"
          system: true
        user:
          uid: 2420
          gid: "knox"
          name: "knox"
          system: true
          comment: "Knox Gateway User"
          home: "/var/lib/knox"
        conf_dir: "/etc/knox/conf"
        krb5_user:
          principal: "knox/front1.ryba@HADOOP.RYBA"
          keytab: "/etc/security/keytabs/knox.service.keytab"
        env:
          app_mem_opts: "-Xmx8192m"
        site:
          "gateway.port": "8443"
          "gateway.path": "gateway"
          "java.security.krb5.conf": "/etc/krb5.conf"
          "java.security.auth.login.config": "/etc/knox/conf/knox.jaas"
          "gateway.hadoop.kerberos.secured": "true"
          "sun.security.krb5.debug": "true"
        topologies:
          torval:
            providers:
              authentication:
                name: "ShiroProvider"
                config:
                  sessionTimeout: 30
                  "main.ldapRealm": "org.apache.hadoop.gateway.shirorealm.KnoxLdapRealm"
                  "main.ldapContextFactory": "org.apache.hadoop.gateway.shirorealm.KnoxLdapContextFactory"
                  "main.ldapRealm.contextFactory": "$ldapContextFactory"
                  "main.ldapRealm.userDnTemplate": "uid={0},ou=users,dc=ryba"
                  "main.ldapRealm.contextFactory.url": "ldaps://master3.ryba:389"
                  "main.ldapRealm.contextFactory.authenticationMechanism": "simple"
                  "urls./**": "authcBasic"
              "identity-assertion":
                name: "Pseudo"
              authorization:
                name: "AclsAuthz"
              ha:
                name: "HaProvider"
                config:
                  WEBHDFS: "maxFailoverAttempts=3;failoverSleep=1000;maxRetryAttempts=300;retrySleep=1000;enabled=true"
            services:
              knox: ""
              namenode: "hdfs://torval:8020"
              webhdfs: [
                "https://master1.ryba:14000/webhdfs/v1"
                "https://master2.ryba:14000/webhdfs/v1"
                "https://master3.ryba:14000/webhdfs/v1"
              ]
              hive: "http://master2.ryba:10001/cliservice"
              webhcat: "http://master3.ryba:50111/templeton"
              oozie: "https://master3.ryba:11443/oozie"
              webhbase: "https://master3.ryba:60080"
        ssl:
          storepass: "knox_master_secret_123"
          cacert: "/home/pierrotws/workspace/ryba-cluster/conf/certs/cacert.pem"
          cert: "/home/pierrotws/workspace/ryba-cluster/conf/certs/front1_cert.pem"
          key: "/home/pierrotws/workspace/ryba-cluster/conf/certs/front1_key.pem"
      falcon:
        group:
          gid: 2421
          name: "falcon"
          system: true
        user:
          uid: 2421
          gid: "falcon"
          name: "falcon"
          system: true
          comment: "Falcon User"
          home: "/var/lib/falcon"
          groups: [
            "hadoop"
          ]
        conf_dir: "/etc/falcon/conf"
        log_dir: "/var/log/falcon"
        pid_dir: "/var/run/falcon"
        server_opts: ""
        server_heap: ""
        runtime: {}
        startup:
          "prism.falcon.local.endpoint": "http://front1.ryba:16000/"
          "*.falcon.authentication.type": "kerberos"
          "*.falcon.service.authentication.kerberos.principal": "falcon/front1.ryba@HADOOP.RYBA"
          "*.falcon.service.authentication.kerberos.keytab": "/etc/security/keytabs/falcon.service.keytab"
          "*.dfs.namenode.kerberos.principal": "nn/_HOST@HADOOP.RYBA"
          "*.falcon.http.authentication.type=kerberos": "kerberos"
          "*.falcon.http.authentication.token.validity": "36000"
          "*.falcon.http.authentication.signature.secret": "falcon"
          "*.falcon.http.authentication.cookie.domain": ""
          "*.falcon.http.authentication.kerberos.principal": "HTTP/front1.ryba@HADOOP.RYBA"
          "*.falcon.http.authentication.kerberos.keytab": "/etc/security/keytabs/spnego.service.keytab"
          "*.falcon.http.authentication.kerberos.name.rules": "DEFAULT"
          "*.falcon.http.authentication.blacklisted.users": ""
      elasticsearch:
        group:
          gid: 2422
        user:
          uid: 2422
          gid: 2422
      rexster:
        group:
          gid: 2423
        user:
          uid: 2423
          gid: 2423
      presto:
        group:
          gid: 2425
        user:
          uid: 2425
          gid: 2425
      spark:
        group:
          gid: 2426
          name: "spark"
          system: true
        user:
          uid: 2426
          gid: 2426
          name: "spark"
          system: true
          comment: "Spark User"
          home: "/var/run/spark"
          groups: "hadoop"
        conf:
          "spark.master": "local[*]"
          "spark.authenticate": "true"
          "spark.eventLog.enabled": "true"
          "spark.yarn.services": "org.apache.spark.deploy.yarn.history.YarnHistoryService"
          "spark.history.provider": "org.apache.spark.deploy.yarn.history.YarnHistoryProvider"
          "spark.ssl.enabled": "false"
          "spark.ssl.enabledAlgorithms": "MD5"
          "spark.ssl.keyPassword": "ryba123"
          "spark.ssl.keyStore": "/etc/spark/conf/keystore"
          "spark.ssl.keyStorePassword": "ryba123"
          "spark.ssl.protocol": "SSLv3"
          "spark.ssl.trustStore": "/etc/spark/conf/trustore"
          "spark.ssl.trustStorePassword": "ryba123"
          "spark.eventLog.overwrite": "true"
          "spark.yarn.jar": "hdfs:///apps/spark/spark-assembly.jar"
          "spark.yarn.applicationMaster.waitTries": null
          "spark.yarn.am.waitTime": "10"
          "spark.yarn.containerLauncherMaxThreads": "25"
          "spark.yarn.driver.memoryOverhead": "384"
          "spark.yarn.executor.memoryOverhead": "384"
          "spark.yarn.max.executor.failures": "3"
          "spark.yarn.preserve.staging.files": "false"
          "spark.yarn.queue": "default"
          "spark.yarn.scheduler.heartbeat.interval-ms": "5000"
          "spark.yarn.submit.file.replication": "3"
          "spark.yarn.historyServer.address": null
          "spark.metrics.conf": null
          "spark.yarn.dist.files": "file:///etc/spark/conf/metrics.properties"
          "spark.eventLog.dir": "hdfs://torval:8020/user/spark/applicationHistory"
          "spark.history.fs.logDirectory": "hdfs://torval:8020/user/spark/applicationHistory"
        client_dir: "/usr/hdp/current/spark-client"
        conf_dir: "/etc/spark/conf"
        metrics:
          "master.source.jvm.class": "org.apache.spark.metrics.source.JvmSource"
          "worker.source.jvm.class": "org.apache.spark.metrics.source.JvmSource"
          "driver.source.jvm.class": "org.apache.spark.metrics.source.JvmSource"
          "executor.source.jvm.class": "org.apache.spark.metrics.source.JvmSource"
      httpfs:
        group:
          gid: 2427
        user:
          uid: 2427
          gid: 2427
      nagvis:
        group:
          gid: 2429
        user:
          uid: 2429
          gid: 2429
      hdp_repo: false
      titan:
        source: "http://10.10.10.1/titan-0.5.4-hadoop2.zip"
      tez:
        site:
          "tez.am.resource.memory.mb": 256
          "tez.task.resource.memory.mb": "512"
          "tez.runtime.io.sort.mb": "204"
          "tez.lib.uris": "/hdp/apps/${hdp.version}/tez/tez.tar.gz"
          "hive.tez.java.opts": "-Xmx204m"
        env:
          TEZ_CONF_DIR: "/etc/tez/conf"
          TEZ_JARS: "/usr/hdp/current/tez-client/*:/usr/hdp/current/tez-client/lib/*"
          HADOOP_CLASSPATH: "$TEZ_CONF_DIR:$TEZ_JARS:$HADOOP_CLASSPATH"
      proxy: null
      db_admin:
        engine: "mysql"
        host: "master3.ryba"
        path: "mysql"
        port: "3306"
        username: "root"
        password: "test123"
      graphite:
        carbon_port: 2023
        carbon_cache_port: 2003
        carbon_aggregator_port: 2023
        metrics_prefix: "hadoop"
        carbon_rewrite_rules: [
          "[pre]"
          "^(?P<cluster>w+).hbase.[a-zA-Z0-9_.,:;-=]*Context=(?P<context>w+).Hostname=(?P<host>w+).(?P<metric>.w+)*$ = g<cluster>.g<host>.hbase.g<context>g<metric>"
          "^(?P<cluster>w+).(?P<bean>w+).(?P<foobar>w+).Hostname=(?P<host>w+).(?P<metric>.w+)*$ = g<cluster>.g<host>.g<foobar>g<metric>"
          "^(?P<cluster>w+).(?P<bean>w+).[a-zA-Z0-9_.=]*port=(?P<port>w+).Context=(?P<context>w+).[a-zA-Z0-9_.=]*Hostname=(?P<host>w+).(?P<metric>.w+)*$ = g<cluster>.g<host>.g<context>.g<port>g<metric>"
          "^(?P<cluster>w+).(?P<bean>w+).[a-zA-Z0-9_.=]*Queue=root(?P<queue>.w+\b)*.Context=(?P<context>w+).[a-zA-Z0-9_.=]*Hostname=(?P<host>w+).(?P<metric>.w+)*$ = g<cluster>.g<host>.g<context>.queue.g<queue>g<metric>"
          "^(?P<cluster>w+).(?P<bean>w+).[a-zA-Z0-9_.=]*Context=(?P<context>w+).ProcessName=(?P<process>w+).[a-zA-Z0-9_.=]*Hostname=(?P<host>w+).(?P<metric>.w+)*$ = g<cluster>.g<host>.g<context>.g<process>g<metric>"
          "^(?P<cluster>w+).(?P<bean>w+).[a-zA-Z0-9_.=]*Context=(?P<context>w+).[a-zA-Z0-9_.=]*Hostname=(?P<host>w+).(?P<metric>.w+)*$ = g<cluster>.g<host>.g<context>g<metric>"
          "rpcdetailed = rpc"
        ]
        carbon_conf: [
          "[aggregator]"
          "LINE_RECEIVER_INTERFACE = 0.0.0.0"
          "LINE_RECEIVER_PORT = 2023"
          "PICKLE_RECEIVER_INTERFACE = 0.0.0.0"
          "PICKLE_RECEIVER_PORT = 2024"
          "LOG_LISTENER_CONNECTIONS = True"
          "FORWARD_ALL = True"
          "DESTINATIONS = 127.0.0.1:2004"
          "REPLICATION_FACTOR = 1"
          "MAX_QUEUE_SIZE = 10000"
          "USE_FLOW_CONTROL = True"
          "MAX_DATAPOINTS_PER_MESSAGE = 500"
          "MAX_AGGREGATION_INTERVALS = 5"
          "# WRITE_BACK_FREQUENCY = 0"
        ]
      hadoop_conf_dir: "/etc/hadoop/conf"
      hadoop_lib_home: "/usr/hdp/current/hadoop-client/lib"
      active_nn: false
      standby_nn_host: "master2.ryba"
      static_host: "_HOST"
      active_nn_host: "master1.ryba"
      core_jars: {}
      hadoop_classpath: ""
      hadoop_client_opts: "-Xmx2048m"
      hadoop_policy: {}
      ssl_client:
        "ssl.client.truststore.location": "/etc/hadoop/conf/truststore"
        "ssl.client.truststore.password": "ryba123"
        "ssl.client.truststore.type": "jks"
      ssl_server:
        "ssl.server.keystore.location": "/etc/hadoop/conf/keystore"
        "ssl.server.keystore.password": "ryba123"
        "ssl.server.keystore.type": "jks"
        "ssl.server.keystore.keypassword": "ryba123"
        "ssl.server.truststore.location": "/etc/hadoop/conf/truststore"
        "ssl.server.truststore.password": "ryba123"
        "ssl.server.truststore.type": "jks"
      phoenix:
        conf_dir: "/etc/phoenix/conf"
    httpd:
      user:
        uid: 2416
        gid: 2416
      group:
        gid: 2416
    xasecure:
      group:
        gid: 2417
      user:
        uid: 2417
        gid: 2417
    proxy:
      system: false
      system_file: "/etc/profile.d/phyla_proxy.sh"
      host: null
      port: null
      username: null
      password: null
      secure: null
      http_proxy: null
      https_proxy: null
      http_proxy_no_auth: null
      https_proxy_no_auth: null
    curl:
      check: false
      config:
        noproxy: "localhost,127.0.0.1,.ryba"
        proxy: null
      merge: true
      users: true
      proxy: true
      check_match: {}
    profile:
      "proxy.sh": ""
    ntp:
      servers: [
        "master3.ryba"
      ]
      fudge: 14
      lag: 2000
    hdp:
      hue_smtp_host: ""
    ambari: {}
    ip: "10.10.10.14"
    modules: [
      "masson/core/reload"
      "masson/core/fstab"
      "masson/core/network"
      "masson/core/network_check"
      "masson/core/users"
      "masson/core/ssh"
      "masson/core/ntp"
      "masson/core/proxy"
      "masson/core/yum"
      "masson/core/security"
      "masson/core/iptables"
      "masson/core/krb5_client"
      "masson/core/sssd"
      "ryba/zookeeper/client"
      "ryba/hadoop/hdfs_client"
      "ryba/hadoop/yarn_client"
      "ryba/hadoop/mapred_client"
      "ryba/tez"
      "ryba/spark/client"
      "ryba/hbase/client"
      "ryba/phoenix/client"
      "ryba/pig"
      "ryba/hive/client"
      "ryba/oozie/client"
      "ryba/sqoop"
      "ryba/flume"
      "ryba/mahout"
      "ryba/falcon"
      "ryba/kafka/consumer"
      "ryba/kafka/producer"
      "ryba/knox"
    ]
    host: "front1.ryba"
    shortname: "front1"
    hostname: "front1.ryba"
    groups: {}
    fstab:
      enabled: false
      exhaustive: false
      volumes: {}
    metrics_sinks:
      file:
        class: "org.apache.hadoop.metrics2.sink.FileSink"
        filename: "metrics.out"
      ganglia:
        class: "org.apache.hadoop.metrics2.sink.ganglia.GangliaSink31"
        period: "10"
        supportparse: "true"
        slope: "jvm.metrics.gcCount=zero,jvm.metrics.memHeapUsedM=both"
        dmax: "jvm.metrics.threadsBlocked=70,jvm.metrics.memHeapUsedM=40"
      graphite:
        class: "org.apache.hadoop.metrics2.sink.GraphiteSink"
        period: "10"
  "worker1.ryba":
    connection:
      private_key: '''
        -----BEGIN RSA PRIVATE KEY-----
        MIIEogIBAAKCAQEArBDFt50aN9jfIJ629pRGIMA1fCMb9RyTHt9A+jx3FOsIOtJs
        eaBIpv98drbFVURr+cUs/CrgGVk5k2NIeiz0bG4ONV5nTwx38z5CzqLb7UryZS3i
        a/TS14fWOxvWTRR27R71ePX90G/ZIReKFeTrucw9y9Pl+xAzsmeblRwLBxv/SWBX
        Uai2mHAZaejlG9dGkn9f2n+oPmbgk6krLMCjLhlNBnkdroBNSXGA9ewLPFF4y54Q
        kBqmG3eLzCqAKAzwyJ5PpybtNGAWfN81gY/P5LBzC66WdtEzpwsYAv1wCioqggtg
        xVZN2s0ajxQrCxahRkXstBI2IDcm2qUTxaDbUwIDAQABAoIBAFruOi7AvXxKBhCt
        D6/bx/vC2AEUZM/yG+Wywhn8HkpVsvGzBlR4Wiy208XA7SQUlqNWimFxHyEGQCEd
        1M2MOFedCbE2hI4H3tQTUSb2dhc/Bj5mM0QuC8aPKK3wFh6B9B93vu3/wfSHR03v
        rK/JXLHBt96hyuYVN9zOWDBCs6k7SdQ2BcsQLiPg6feTsZelJDuO+DO65kKLMiz3
        mNPThErklRaKovNk47LSYakk6gsJXrpG6JWQ6nwsRenwplDwZ8Zs9mlRi7f3nChM
        3I1WlISN8y2kcQBQ94YZKk8wzH/lzmxsabcLa5ETNubxQ6ThDu1oYUIIUsQyNPm+
        DkW0VwECgYEA5MttelspKexWS39Y3sQYvZ/v8VZBQl4tRbpUWWc+PNEtcEwOBza/
        H4jBWYd2eWKTApJT1st58E4b34Mv88nQVElLb3sE7uJMkihPyNpABGbCvr63hDYw
        PyL53nKaPelY/aDnL0F8LmREfdKw/uy6+UChgkPfdo2VVk1oyvsZaRMCgYEAwIZ+
        lCmeXQ4mU6uxO+ChhDn7zw9rR5qlCyfJiLPe2lV20vaHV5ZfKIWGegsVJSpFr2ST
        5ghh+FVIneoNRtTHEKwNWCK7I6qeF+WAaci+KsLQigJQHsw58n9cdA7wHHc475n/
        pf7efoPcvk6qYOS2mpDgC87m+o3C4Dyspqp9TMECgYA4/ed+dBjT5Zg1ZDp5+zUC
        f0Wgw1CsPJNgbCK4xnv9YEnGUFuqNlvzefhX2eOMJx7hpBuYRMVSM9LDoYUfYCUx
        6bQNyAIZk2tpePsu2BbcQdC+/PjvySPJhmfhnoCHbYoKW7tazSAm2jkpcoM+bS/C
        CPRyY3/Voz0Q62VwMo5I2wKBgB4mMbZUGieqapgZwASHdeO2DNftKzioYAYyMd5F
        hLWeQqBg2Or/cmFvH5MHH0WVrBn+Xybb0zPHbzrDh1a7RX035FMUBUhdlKpbV1O5
        iwY5Qd0K5a8c/koaZckK+dELXpAvBpjhI8ieL7hhq07HIk1sOJnAye0cvBLPjZ3/
        /uVBAoGAVAs6tFpS0pFlxmg4tfGEm7/aP6FhyBHNhv2QGluw8vv/XVMzUItxGIef
        HcSMWBm08IJMRJLgmoo1cuQv6hBui7JpDeZk/20qoF2oZW9lJ9fdRObJqi61wufP
        BNiriqexq/eTy2uF9RCCjLItWxUscVMlVt4V65HLkCF5WxCQw+o=
        -----END RSA PRIVATE KEY-----
      '''
      public_key: "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCsEMW3nRo32N8gnrb2lEYgwDV8Ixv1HJMe30D6PHcU6wg60mx5oEim/3x2tsVVRGv5xSz8KuAZWTmTY0h6LPRsbg41XmdPDHfzPkLOotvtSvJlLeJr9NLXh9Y7G9ZNFHbtHvV49f3Qb9khF4oV5Ou5zD3L0+X7EDOyZ5uVHAsHG/9JYFdRqLaYcBlp6OUb10aSf1/af6g+ZuCTqSsswKMuGU0GeR2ugE1JcYD17As8UXjLnhCQGqYbd4vMKoAoDPDInk+nJu00YBZ83zWBj8/ksHMLrpZ20TOnCxgC/XAKKiqCC2DFVk3azRqPFCsLFqFGRey0EjYgNybapRPFoNtT Ryba Hadoop"
      bootstrap:
        username: "vagrant"
        password: "vagrant"
        host: "10.10.10.16"
        port: 22
        cmd: "su -"
        retry: 3
      username: "root"
      host: "10.10.10.16"
      port: 22
      private_key_location: "~/.ssh/id_rsa"
      retry: 3
      end: true
      wait: 1000
    mecano:
      cache_dir: "/home/pierrotws/workspace/ryba-cluster/conf/../resources/cache"
      log_serializer: true
    log:
      archive: true
      disabled: false
      basedir: "./log"
      fqdn_reversed: "ryba.worker1"
      filename: "worker1.log"
      elasticsearch:
        enable: false
        url: "http://localhost:9200"
        index: "masson"
    security:
      selinux: false
      limits: {}
    network:
      hosts_auto: true
      hosts:
        "127.0.0.1": "localhost localhost.localdomain localhost4 localhost4.localdomain4"
        "10.10.10.10": "repos.ryba ryba"
      resolv: '''
        search ryba
        nameserver 10.10.10.13
        nameserver 10.0.2.3
      '''
      hostname_disabled: false
    iptables:
      action: "stop"
      startup: false
      log: true
      rules: []
      log_prefix: "IPTables-Dropped: "
      log_level: 4
      log_rules: [
        {
          chain: "INPUT"
          command: "-A"
          jump: "LOGGING"
        }
        {
          chain: "LOGGING"
          command: "-A"
          "--limit": "2/min"
          jump: "LOG"
          "log-prefix": "IPTables-Dropped: "
          "log-level": 4
        }
        {
          chain: "LOGGING"
          command: "-A"
          jump: "DROP"
        }
      ]
    bind_server:
      zones: [
        "/home/pierrotws/workspace/ryba-cluster/conf/zones/ryba"
        "/home/pierrotws/workspace/ryba-cluster/conf/zones/10.10.10.in-addr.arpa"
      ]
      user:
        uid: 802
        gid: 802
      group:
        gid: 802
    ssh:
      banner:
        destination: "/etc/banner"
        content: "Welcome to Hadoop!"
      sshd_config:
        PermitRootLogin: "without-password"
    users:
      root:
        authorized_keys: [
          "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCWvEjSt2sAvRmkpkt9+u1EXuFDWJSuI1C8G/+NMcpMRDSUTary3Njqt/DC5mx7X36mVJdaq2KqgAVa28zzeuN6Yv7iuxCTw/4K7OKXYu+q0UG8BlIknWgLa8s7Nx2J69Prkb4oFgzw5IqK9EM6VMarUJUCXVNhb3zmamrF59OIxAIyQhV5i5SzoAxLIcD9EtxS/ZRf9t9fOBEhn42SVcpEWO09bUHZ11J2tw/Pwsxk+va83cH9qipVsEwIMDUCosfzV1G2zF5HhU/mhIHWRdAULpaRfd3IgNqTtI6BBi6FOFbJdrkHXPXKRybZwCxChncq1TZI2SXx6BCRpoJ/s887 m.sauvage.pierre@gmail.com"
        ]
        name: "root"
        home: "/root"
    yum:
      packages:
        tree: true
        git: true
        htop: true
        vim: true
        "yum-plugin-priorities": true
        man: true
        ksh: true
      config:
        proxy: null
        main:
          keepcache: "0"
          proxy: null
          proxy_username: null
          proxy_password: null
      copy: "/home/pierrotws/workspace/ryba-cluster/conf/user/offline/*.repo"
      clean: false
      merge: true
      update: true
      proxy: true
      epel: true
      epel_url: "http://download.fedoraproject.org/pub/epel/6/i386/epel-release-6-8.noarch.rpm"
    mysql:
      server:
        current_password: ""
        password: "test123"
        my_cnf:
          mysqld:
            innodb_file_per_table: "1"
    openldap_server:
      suffix: "dc=ryba"
      root_dn: "cn=Manager,dc=ryba"
      root_password: "test"
      config_dn: "cn=admin,cn=config"
      config_password: "test"
      users_dn: "ou=users,dc=ryba"
      groups_dn: "ou=groups,dc=ryba"
      ldapdelete: []
      ldapadd: []
      tls: true
      tls_ca_cert_file: "/home/pierrotws/workspace/ryba-cluster/conf/certs/cacert.pem"
      tls_cert_file: "/home/pierrotws/workspace/ryba-cluster/conf/certs/master3_cert.pem"
      tls_key_file: "/home/pierrotws/workspace/ryba-cluster/conf/certs/master3_key.pem"
      proxy_user:
        uidNumber: 801
        gidNumber: 801
      proxy_group:
        gidNumber: 801
    openldap_client:
      certificates: [
        "/home/pierrotws/workspace/ryba-cluster/conf/certs/master3_cert.pem"
      ]
      config:
        BASE: "dc=ryba"
        URI: "ldaps://master3.ryba"
        TLS_CACERTDIR: "/etc/openldap/cacerts"
        TLS_REQCERT: "allow"
        TIMELIMIT: "15"
        TIMEOUT: "20"
      suffix: "dc=ryba"
      root_dn: "cn=Manager,dc=ryba"
      root_password: "test"
    openldap_server_krb5:
      manager_dn: "cn=Manager,dc=ryba"
      manager_password: "test"
      krbadmin_user:
        mail: "david@adaltas.com"
        userPassword: "test"
        uidNumber: 800
        gidNumber: 800
      krbadmin_group:
        gidNumber: 800
    krb5:
      etc_krb5_conf:
        logging:
          default: "SYSLOG:INFO:LOCAL1"
          kdc: "SYSLOG:NOTICE:LOCAL1"
          admin_server: "SYSLOG:WARNING:LOCAL1"
        libdefaults:
          dns_lookup_realm: false
          dns_lookup_kdc: false
          ticket_lifetime: "24h"
          renew_lifetime: "7d"
          forwardable: true
          allow_weak_crypto: "false"
          clockskew: "300"
          rdns: "false"
          default_realm: "HADOOP.RYBA"
        realms:
          "USERS.RYBA":
            kadmin_principal: "wdavidw/admin@USERS.RYBA"
            kadmin_password: "test"
            principals: [
              {
                principal: "krbtgt/HADOOP.RYBA@USERS.RYBA"
                password: "test"
              }
            ]
            kdc: [
              "master3.ryba"
            ]
            admin_server: "master3.ryba"
            default_domain: "users.ryba"
          "HADOOP.RYBA":
            kadmin_principal: "wdavidw/admin@HADOOP.RYBA"
            kadmin_password: "test"
            principals: [
              {
                principal: "krbtgt/HADOOP.RYBA@USERS.RYBA"
                password: "test"
              }
            ]
            kdc: [
              "master1.ryba"
            ]
            admin_server: "master1.ryba"
            default_domain: "hadoop.ryba"
        domain_realm:
          ryba: "HADOOP.RYBA"
        appdefaults:
          pam:
            debug: false
            ticket_lifetime: 36000
            renew_lifetime: 36000
            forwardable: true
            krb4_convert: false
        dbmodules: {}
      kdc_conf:
        realms: {}
      sshd: {}
      kinit: "/usr/bin/kinit"
    sssd:
      force_check: false
      certificates: [
        "/home/pierrotws/workspace/ryba-cluster/conf/certs/cacert.pem"
      ]
      config:
        sssd:
          config_file_version: "2"
          reconnection_retries: "3"
          sbus_timeout: "30"
          services: "nss, pam"
          debug_level: "1"
          domains: "hadoop,users"
        nss:
          filter_groups: "root"
          filter_users: "root"
          reconnection_retries: "3"
          entry_cache_timeout: "300"
          entry_cache_nowait_percentage: "75"
          debug_level: "1"
        pam:
          reconnection_retries: "3"
          offline_credentials_expiration: "2"
          offline_failed_login_attempts: "3"
          offline_failed_login_delay: "5"
          debug_level: "1"
        "domain/hadoop":
          debug_level: "1"
          cache_credentials: "True"
          ldap_search_base: "ou=users,dc=ryba"
          ldap_group_search_base: "ou=groups,dc=ryba"
          id_provider: "ldap"
          auth_provider: "ldap"
          chpass_provider: "ldap"
          ldap_uri: "ldaps://master3.ryba:636"
          ldap_tls_cacertdir: "/etc/openldap/cacerts"
          ldap_default_bind_dn: "cn=Manager,dc=ryba"
          ldap_default_authtok: "test"
          ldap_id_use_start_tls: "True"
        "domain/users":
          debug_level: "1"
          cache_credentials: "True"
          ldap_search_base: "ou=users,dc=ryba"
          ldap_group_search_base: "ou=groups,dc=ryba"
          id_provider: "ldap"
          auth_provider: "ldap"
          chpass_provider: "ldap"
          ldap_uri: "ldaps://master3.ryba:636"
          ldap_tls_cacertdir: "/etc/openldap/cacerts"
          ldap_default_bind_dn: "cn=Manager,dc=ryba"
          ldap_default_authtok: "test"
          ldap_id_use_start_tls: "False"
      merge: false
      test_user: null
    java:
      java_home: "/usr/lib/jvm/java"
      jre_home: "/usr/lib/jvm/java/jre"
      proxy: null
      openjdk: true
    ryba:
      clean_logs: true
      force_check: false
      check_hdfs_fsck: false
      security: "kerberos"
      realm: "HADOOP.RYBA"
      nameservice: "torval"
      krb5_user:
        password: "test123"
        password_sync: true
        principal: "ryba@HADOOP.RYBA"
      ssl:
        cacert: "/home/pierrotws/workspace/ryba-cluster/conf/certs/cacert.pem"
        cert: "/home/pierrotws/workspace/ryba-cluster/conf/certs/worker1_cert.pem"
        key: "/home/pierrotws/workspace/ryba-cluster/conf/certs/worker1_key.pem"
      ambari:
        repo: "/home/pierrotws/workspace/ryba-cluster/conf/resources/repos/ambari-2.0.0.repo"
      ssh_fencing:
        private_key: "/home/pierrotws/workspace/ryba-cluster/conf/hdfs_keys/id_rsa"
        public_key: "/home/pierrotws/workspace/ryba-cluster/conf/hdfs_keys/id_rsa.pub"
      hadoop_opts: "-Djava.net.preferIPv4Stack=true -Dsun.security.krb5.debug=false"
      core_site:
        "hadoop.ssl.exclude.cipher.suites": "SSL_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA,SSL_RSA_EXPORT_WITH_DES40_CBC_SHA,SSL_RSA_EXPORT_WITH_RC4_40_MD5,TLS_DHE_RSA_WITH_AES_128_CBC_SHA,TLS_DHE_RSA_WITH_AES_256_CBC_SHA"
        "hadoop.proxyuser.httpfs.hosts": "master1.ryba,master2.ryba,master3.ryba"
        "hadoop.proxyuser.httpfs.groups": "*"
        "io.compression.codecs": "org.apache.hadoop.io.compress.GzipCodec,org.apache.hadoop.io.compress.DefaultCodec,org.apache.hadoop.io.compress.SnappyCodec"
        "fs.defaultFS": "hdfs://torval:8020"
        "hadoop.security.authentication": "kerberos"
        "hadoop.security.authorization": "true"
        "hadoop.rpc.protection": "authentication"
        "hadoop.security.group.mapping": "org.apache.hadoop.security.JniBasedUnixGroupsMappingWithFallback"
        "ha.zookeeper.quorum": [
          "master1.ryba:2181"
          "master2.ryba:2181"
          "master3.ryba:2181"
        ]
        "net.topology.script.file.name": "/etc/hadoop/conf/rack_topology.sh"
        "hadoop.http.filter.initializers": "org.apache.hadoop.security.AuthenticationFilterInitializer"
        "hadoop.http.authentication.type": "kerberos"
        "hadoop.http.authentication.token.validity": "36000"
        "hadoop.http.authentication.signature.secret.file": "/etc/hadoop/hadoop-http-auth-signature-secret"
        "hadoop.http.authentication.simple.anonymous.allowed": "false"
        "hadoop.http.authentication.kerberos.principal": "HTTP/_HOST@HADOOP.RYBA"
        "hadoop.http.authentication.kerberos.keytab": "/etc/security/keytabs/spnego.service.keytab"
        "hadoop.http.authentication.cookie.domain": "ryba"
        "hadoop.security.auth_to_local": '''
          
          RULE:[2:$1@$0]([rn]m@HADOOP\\.RYBA)s/.*/yarn/
          RULE:[2:$1@$0](jhs@HADOOP\\.RYBA)s/.*/mapred/
          RULE:[2:$1@$0]([nd]n@HADOOP\\.RYBA)s/.*/hdfs/
          RULE:[2:$1@$0](hm@HADOOP\\.RYBA)s/.*/hbase/
          RULE:[2:$1@$0](rs@HADOOP\\.RYBA)s/.*/hbase/
          RULE:[2:$1@$0](opentsdb@HADOOP\\.RYBA)s/.*/hbase/
          DEFAULT
          RULE:[1:$1](yarn|mapred|hdfs|hive|hbase|oozie)s/.*/nobody/
          RULE:[2:$1](yarn|mapred|hdfs|hive|hbase|oozie)s/.*/nobody/
          RULE:[1:$1]
          RULE:[2:$1]
          
        '''
        "hadoop.proxyuser.HTTP.hosts": "*"
        "hadoop.proxyuser.HTTP.groups": "*"
        "hadoop.proxyuser.hbase.hosts": "*"
        "hadoop.proxyuser.hbase.groups": "*"
        "hadoop.proxyuser.hive.groups": "*"
        "hadoop.proxyuser.hive.hosts": "*"
        "hadoop.proxyuser.oozie.hosts": "master3.ryba"
        "hadoop.proxyuser.oozie.groups": "*"
        "hadoop.proxyuser.falcon.groups": "*"
        "hadoop.proxyuser.falcon.hosts": "front1.ryba"
        "hadoop.proxyuser.knox.hosts": "front1.ryba"
        "hadoop.proxyuser.knox.groups": "*"
        "hadoop.ssl.require.client.cert": "false"
        "hadoop.ssl.hostname.verifier": "DEFAULT"
        "hadoop.ssl.keystores.factory.class": "org.apache.hadoop.security.ssl.FileBasedKeyStoresFactory"
        "hadoop.ssl.server.conf": "ssl-server.xml"
        "hadoop.ssl.client.conf": "ssl-client.xml"
      hadoop_metrics:
        "*.sink.file.class": "org.apache.hadoop.metrics2.sink.FileSink"
        sinks:
          file: true
          ganglia: false
          graphite: false
        config:
          "*.period": "60"
          "*.sink.file.class": "org.apache.hadoop.metrics2.sink.FileSink"
          "*.sink.file.filename": "metrics.out"
          "namenode.sink.file.filename": "namenode-metrics.out"
          "datanode.sink.file.filename": "datanode-metrics.out"
          "resourcemanager.sink.file.filename": "resourcemanager-metrics.out"
          "nodemanager.sink.file.filename": "nodemanager-metrics.out"
          "mrappmaster.sink.file.filename": "mrappmaster-metrics.out"
          "jobhistoryserver.sink.file.filename": "jobhistoryserver-metrics.out"
      hadoop_heap: "512"
      hadoop_namenode_init_heap: "-Xms512m"
      hdfs:
        user:
          limits:
            nproc: 16384
            nofile: 16384
          uid: 2401
          gid: "hdfs"
          name: "hdfs"
          system: true
          groups: "hadoop"
          comment: "Hadoop HDFS User"
          home: "/var/lib/hadoop-hdfs"
        krb5_user:
          password: "hdfs123"
          password_sync: true
          principal: "hdfs@HADOOP.RYBA"
        sysctl:
          "vm.swappiness": 0
          "vm.overcommit_memory": 1
          "vm.overcommit_ratio": 100
          "net.core.somaxconn": 1024
        site:
          "dfs.namenode.safemode.extension": 1000
          "dfs.replication": 2
          "dfs.datanode.data.dir": "/data/1/hdfs/data,/data/2/hdfs/data"
          "dfs.namenode.kerberos.principal": "nn/_HOST@HADOOP.RYBA"
          "dfs.namenode.kerberos.internal.spnego.principal": "HTTP/_HOST@HADOOP.RYBA"
          "dfs.namenode.kerberos.https.principal": "HTTP/_HOST@HADOOP.RYBA"
          "dfs.web.authentication.kerberos.principal": "HTTP/_HOST@HADOOP.RYBA"
          "dfs.ha.automatic-failover.enabled": "true"
          "dfs.nameservices": "torval"
          "dfs.internal.nameservices": "torval"
          "dfs.ha.namenodes.torval": "master1,master2"
          "dfs.namenode.http-address": null
          "dfs.namenode.https-address": null
          "dfs.namenode.rpc-address.torval.master1": "master1.ryba:8020"
          "dfs.namenode.http-address.torval.master1": "master1.ryba:50070"
          "dfs.namenode.https-address.torval.master1": "master1.ryba:50470"
          "dfs.namenode.rpc-address.torval.master2": "master2.ryba:8020"
          "dfs.namenode.http-address.torval.master2": "master2.ryba:50070"
          "dfs.namenode.https-address.torval.master2": "master2.ryba:50470"
          "dfs.client.failover.proxy.provider.torval": "org.apache.hadoop.hdfs.server.namenode.ha.ConfiguredFailoverProxyProvider"
          "dfs.http.policy": "HTTPS_ONLY"
          "dfs.datanode.data.dir.perm": "700"
          "dfs.datanode.address": "0.0.0.0:1004"
          "dfs.datanode.ipc.address": "0.0.0.0:50020"
          "dfs.datanode.http.address": "0.0.0.0:1006"
          "dfs.datanode.https.address": "0.0.0.0:50475"
          "dfs.datanode.kerberos.principal": "dn/_HOST@HADOOP.RYBA"
          "dfs.datanode.keytab.file": "/etc/security/keytabs/dn.service.keytab"
          "dfs.datanode.failed.volumes.tolerated": "0"
          "dfs.datanode.fsdataset.volume.choosing.policy": "org.apache.hadoop.hdfs.server.datanode.fsdataset.AvailableSpaceVolumeChoosingPolicy"
          "dfs.datanode.available-space-volume-choosing-policy.balanced-space-threshold": "10737418240"
          "dfs.datanode.available-space-volume-choosing-policy.balanced-space-preference-fraction": "1.0"
          "dfs.datanode.du.reserved": "1073741824"
          "dfs.client.read.shortcircuit": "true"
          "dfs.domain.socket.path": "/var/lib/hadoop-hdfs/dn_socket"
          "dfs.namenode.kerberos.principal.pattern": "*"
        group:
          gid: 2401
          name: "hdfs"
          system: true
        nn:
          site:
            "dfs.http.policy": "HTTPS_ONLY"
            "fs.permissions.umask-mode": "027"
            "dfs.block.access.token.enable": "true"
        log_dir: "/var/log/hadoop-hdfs"
        pid_dir: "/var/run/hadoop-hdfs"
        secure_dn_pid_dir: "/var/run/hadoop-hdfs"
        secure_dn_user: "hdfs"
        dn:
          conf_dir: "/etc/hadoop-hdfs-datanode/conf"
        datanode_opts: ""
      zkfc:
        digest:
          name: "zkfc"
          password: "zkfc123"
      yarn:
        user:
          limits:
            nproc: 16384
            nofile: 16384
          uid: 2403
          gid: "yarn"
          name: "yarn"
          system: true
          groups: "hadoop"
          comment: "Hadoop YARN User"
          home: "/var/lib/hadoop-yarn"
        opts: "-Dsun.net.spi.nameservice.provider.1=sun,dns"
        site:
          "yarn.nodemanager.resource.percentage-physical-cpu-limit": "100"
          "yarn.nodemanager.resource.memory-mb": 1536
          "yarn.nodemanager.vmem-pmem-ratio": "2.1"
          "yarn.nodemanager.resource.cpu-vcores": 3
          "yarn.nodemanager.local-dirs": "/data/1/yarn/local,/data/2/yarn/local"
          "yarn.nodemanager.log-dirs": "/data/1/yarn/log,/data/2/yarn/log"
          "yarn.http.policy": "HTTPS_ONLY"
          "yarn.nodemanager.address": "worker1.ryba:45454"
          "yarn.nodemanager.localizer.address": "worker1.ryba:8040"
          "yarn.nodemanager.webapp.address": "worker1.ryba:8042"
          "yarn.nodemanager.webapp.https.address": "worker1.ryba:8044"
          "yarn.nodemanager.remote-app-log-dir": "/app-logs"
          "yarn.nodemanager.keytab": "/etc/security/keytabs/nm.service.keytab"
          "yarn.nodemanager.principal": "nm/_HOST@HADOOP.RYBA"
          "yarn.nodemanager.container-executor.class": "org.apache.hadoop.yarn.server.nodemanager.LinuxContainerExecutor"
          "yarn.nodemanager.linux-container-executor.group": "yarn"
          "yarn.nodemanager.linux-container-executor.cgroups.strict-resource-usage": "false"
          "yarn.nodemanager.log.retain-second": null
          "yarn.nodemanager.log.retain-seconds": "604800"
          "yarn.log-aggregation-enable": "true"
          "yarn.log-aggregation.retain-seconds": "2592000"
          "yarn.log-aggregation.retain-check-interval-seconds": "-1"
          "yarn.resourcemanager.principal": "rm/_HOST@HADOOP.RYBA"
          "yarn.resourcemanager.cluster-id": "yarn_cluster_01"
          "yarn.resourcemanager.ha.enabled": "true"
          "yarn.resourcemanager.ha.rm-ids": "master1,master2"
          "yarn.resourcemanager.webapp.delegation-token-auth-filter.enabled": "true"
          "yarn.resourcemanager.address.master1": "master1.ryba:8050"
          "yarn.resourcemanager.scheduler.address.master1": "master1.ryba:8030"
          "yarn.resourcemanager.admin.address.master1": "master1.ryba:8141"
          "yarn.resourcemanager.webapp.address.master1": "master1.ryba:8088"
          "yarn.resourcemanager.webapp.https.address.master1": "master1.ryba:8090"
          "yarn.resourcemanager.resource-tracker.address.master1": "master1.ryba:8025"
          "yarn.resourcemanager.address.master2": "master2.ryba:8050"
          "yarn.resourcemanager.scheduler.address.master2": "master2.ryba:8030"
          "yarn.resourcemanager.admin.address.master2": "master2.ryba:8141"
          "yarn.resourcemanager.webapp.address.master2": "master2.ryba:8088"
          "yarn.resourcemanager.webapp.https.address.master2": "master2.ryba:8090"
          "yarn.resourcemanager.resource-tracker.address.master2": "master2.ryba:8025"
          "yarn.timeline-service.enabled": "true"
          "yarn.timeline-service.address": "master3.ryba:10200"
          "yarn.timeline-service.webapp.address": "master3.ryba:8188"
          "yarn.timeline-service.webapp.https.address": "master3.ryba:8190"
          "yarn.timeline-service.principal": "ats/_HOST@HADOOP.RYBA"
          "yarn.timeline-service.http-authentication.type": "kerberos"
          "yarn.timeline-service.http-authentication.kerberos.principal": "HTTP/_HOST@HADOOP.RYBA"
          "yarn.nodemanager.recovery.enabled": "true"
          "yarn.nodemanager.recovery.dir": "/var/yarn/recovery-state"
          "yarn.nodemanager.linux-container-executor.resources-handler.class": "org.apache.hadoop.yarn.server.nodemanager.util.CgroupsLCEResourcesHandler"
          "yarn.nodemanager.linux-container-executor.cgroups.hierarchy": "/yarn"
          "yarn.nodemanager.linux-container-executor.cgroups.mount": "true"
          "yarn.nodemanager.linux-container-executor.cgroups.mount-path": "/cgroup"
          "yarn.application.classpath": "$HADOOP_CONF_DIR,/usr/hdp/current/hadoop-client/*,/usr/hdp/current/hadoop-client/lib/*,/usr/hdp/current/hadoop-hdfs-client/*,/usr/hdp/current/hadoop-hdfs-client/lib/*,/usr/hdp/current/hadoop-yarn-client/*,/usr/hdp/current/hadoop-yarn-client/lib/*"
          "yarn.generic-application-history.save-non-am-container-meta-info": "true"
          "yarn.scheduler.minimum-allocation-mb": null
          "yarn.scheduler.maximum-allocation-mb": null
        group:
          gid: 2403
          name: "yarn"
          system: true
        log_dir: "/var/log/hadoop-yarn"
        pid_dir: "/var/run/hadoop-yarn"
        home: "/usr/hdp/current/hadoop-yarn-nodemanager"
        nm:
          conf_dir: "/etc/hadoop-yarn-nodemanager/conf"
          opts: ""
          heapsize: "1024"
        conf_dir: "/etc/hadoop/conf"
        heapsize: "1024"
      capacity_scheduler:
        "yarn.scheduler.capacity.maximum-am-resource-percent": ".5"
      mapred:
        user:
          limits:
            nproc: 16384
            nofile: 16384
          uid: 2404
          gid: "mapred"
          name: "mapred"
          system: true
          groups: "hadoop"
          comment: "Hadoop MapReduce User"
          home: "/var/lib/hadoop-mapreduce"
        site:
          "mapreduce.job.counters.max": "10000"
          "mapreduce.job.counters.limit": "10000"
          "yarn.app.mapreduce.am.resource.mb": "256"
          "yarn.app.mapreduce.am.command-opts": "-Xmx204m"
          "mapreduce.map.memory.mb": "512"
          "mapreduce.reduce.memory.mb": "1024"
          "mapreduce.map.java.opts": "-Xmx409m"
          "mapreduce.reduce.java.opts": "-Xmx819m"
          "mapreduce.task.io.sort.mb": "204"
          "mapreduce.map.cpu.vcores": "1"
          "mapreduce.reduce.cpu.vcores": "1"
          "mapreduce.reduce.shuffle.parallelcopies": "50"
          "mapreduce.admin.map.child.java.opts": "-server -Djava.net.preferIPv4Stack=true -Dhdp.version=${hdp.version}"
          "mapreduce.admin.reduce.child.java.opts": null
          "mapreduce.task.io.sort.factor": 100
          "mapreduce.admin.user.env": "LD_LIBRARY_PATH=/usr/hdp/${hdp.version}/hadoop/lib/native:/usr/hdp/${hdp.version}/hadoop/lib/native/Linux-amd64-64"
          "mapreduce.application.framework.path": "/hdp/apps/${hdp.version}/mapreduce/mapreduce.tar.gz#mr-framework"
          "mapreduce.application.classpath": "$PWD/mr-framework/hadoop/share/hadoop/mapreduce/*:$PWD/mr-framework/hadoop/share/hadoop/mapreduce/lib/*:$PWD/mr-framework/hadoop/share/hadoop/common/*:$PWD/mr-framework/hadoop/share/hadoop/common/lib/*:$PWD/mr-framework/hadoop/share/hadoop/yarn/*:$PWD/mr-framework/hadoop/share/hadoop/yarn/lib/*:$PWD/mr-framework/hadoop/share/hadoop/hdfs/*:$PWD/mr-framework/hadoop/share/hadoop/hdfs/lib/*:/usr/hdp/current/share/lzo/0.6.0/lib/hadoop-lzo-0.6.0.jar:/etc/hadoop/conf/secure"
          "yarn.app.mapreduce.am.staging-dir": "/user"
          "mapreduce.jobhistory.address": "master3.ryba:10020"
          "mapreduce.jobhistory.webapp.address": "master3.ryba:19888"
          "mapreduce.jobhistory.webapp.https.address": "master3.ryba:19889"
          "mapreduce.jobhistory.done-dir": null
          "mapreduce.jobhistory.intermediate-done-dir": null
          "mapreduce.jobhistory.principal": "jhs/master3.ryba@HADOOP.RYBA"
          "yarn.app.mapreduce.am.job.client.port-range": "59100-59200"
          "mapreduce.framework.name": "yarn"
          "mapreduce.cluster.local.dir": null
          "mapreduce.jobtracker.system.dir": null
        group:
          gid: 2404
          name: "mapred"
          system: true
        log_dir: "/var/log/hadoop-mapreduce"
        pid_dir: "/var/run/hadoop-mapreduce"
      hive:
        user:
          limits:
            nproc: 16384
            nofile: 16384
          uid: 2407
          gid: 2407
        site:
          "javax.jdo.option.ConnectionDriverName": "com.mysql.jdbc.Driver"
          "javax.jdo.option.ConnectionUserName": "hive"
          "javax.jdo.option.ConnectionPassword": "hive123"
        group:
          gid: 2407
      hue:
        ini:
          desktop:
            smtp:
              host: ""
            database:
              engine: "mysql"
              password: "hue123"
        ssl:
          certificate: "/home/pierrotws/workspace/ryba-cluster/conf/certs/master3_cert.pem"
          private_key: "/home/pierrotws/workspace/ryba-cluster/conf/certs/master3_key.pem"
          client_ca: "/home/pierrotws/workspace/ryba-cluster/conf/certs/cacert.pem"
        group:
          gid: 2410
        user:
          uid: 2410
          gid: 2410
      sqoop:
        libs: []
        user:
          uid: 2412
          gid: 2400
      hbase:
        regionserver_opts: "-Xmx128m"
        admin:
          password: "hbase123"
          name: "hbase"
          principal: "hbase@HADOOP.RYBA"
        metrics:
          "*.sink.file.class": "org.apache.hadoop.metrics2.sink.FileSink"
          sinks:
            file: true
            ganglia: false
            graphite: false
          config:
            "*.period": "60"
            "*.sink.file.class": "org.apache.hadoop.metrics2.sink.FileSink"
            "*.sink.file.filename": "metrics.out"
            "hbase.sink.file.filename": "hbase-metrics.out"
        group:
          gid: 2409
          name: "hbase"
          system: true
        user:
          uid: 2409
          gid: "hbase"
          name: "hbase"
          system: true
          comment: "HBase User"
          home: "/var/run/hbase"
          groups: "hadoop"
          limits:
            nofile: 64000
            nproc: true
        site:
          "hadoop.proxyuser.hbase_rest.groups": "*"
          "hadoop.proxyuser.hbase_rest.hosts": "*"
          "zookeeper.znode.parent": "/hbase"
          "hbase.cluster.distributed": "true"
          "hbase.rootdir": "hdfs://torval:8020/apps/hbase/data"
          "hbase.zookeeper.quorum": "master1.ryba,master2.ryba,master3.ryba"
          "hbase.zookeeper.property.clientPort": "2181"
          "dfs.domain.socket.path": "/var/lib/hadoop-hdfs/dn_socket"
          "hbase.security.authentication": "kerberos"
          "hbase.security.authorization": "true"
          "hbase.rpc.engine": "org.apache.hadoop.hbase.ipc.SecureRpcEngine"
          "hbase.superuser": "hbase"
          "hbase.bulkload.staging.dir": "/apps/hbase/staging"
          "hbase.regionserver.storefile.refresh.all": "true"
          "hbase.regionserver.storefile.refresh.period": "30000"
          "hbase.region.replica.replication.enabled": "true"
          "hbase.master.hfilecleaner.ttl": "3600000"
          "hbase.master.loadbalancer.class": "org.apache.hadoop.hbase.master.balancer.StochasticLoadBalancer"
          "hbase.meta.replica.count": "3"
          "hbase.region.replica.wait.for.primary.flush": "true"
          "hbase.region.replica.storefile.refresh.memstore.multiplier": "4"
          "hbase.regionserver.port": "60020"
          "hbase.regionserver.info.port": "60030"
          "hbase.ssl.enabled": "true"
          "hbase.regionserver.handler.count": 60
          "hbase.master.kerberos.principal": "hbase/_HOST@HADOOP.RYBA"
          "hbase.regionserver.keytab.file": "/etc/security/keytabs/rs.service.keytab"
          "hbase.regionserver.kerberos.principal": "hbase/_HOST@HADOOP.RYBA"
          "hbase.regionserver.global.memstore.upperLimit": null
          "hbase.regionserver.global.memstore.size": "0.4"
          "hbase.coprocessor.region.classes": [
            "org.apache.hadoop.hbase.security.token.TokenProvider"
            "org.apache.hadoop.hbase.security.access.SecureBulkLoadEndpoint"
            "org.apache.hadoop.hbase.security.access.AccessController"
          ]
          "hbase.defaults.for.version.skip": "true"
          "phoenix.functions.allowUserDefinedFunctions": "true"
          "hbase.regionserver.wal.codec": "org.apache.hadoop.hbase.regionserver.wal.IndexedWALEditCodec"
          "hbase.rpc.controllerfactory.class": "org.apache.hadoop.hbase.ipc.controller.ServerRpcControllerFactory"
          "hbase.regionserver.rpc.scheduler.factory.class": "org.apache.hadoop.hbase.ipc.PhoenixRpcSchedulerFactory"
        test:
          default_table: "ryba"
        conf_dir: "/etc/hbase/conf"
        log_dir: "/var/log/hbase"
        pid_dir: "/var/run/hbase"
        env:
          JAVA_HOME: "/usr/lib/jvm/java"
          HBASE_LOG_DIR: "/var/log/hbase"
          HBASE_OPTS: "-ea -XX:+UseConcMarkSweepGC -XX:+CMSIncrementalMode"
          HBASE_MASTER_OPTS: "-Xmx2048m"
          HBASE_REGIONSERVER_OPTS: "-Xmn200m -Xms4096m -Xmx4096m -Djava.security.auth.login.config=/etc/hbase/conf/hbase-regionserver.jaas"
      kafka:
        broker:
          heapsize: 128
        group:
          gid: 2424
        user:
          uid: 2424
          gid: 2424
      opentsdb:
        version: "2.2.0RC3"
        group:
          gid: 2428
        user:
          uid: 2428
          gid: 2428
      nagios:
        users:
          nagiosadmin:
            password: "nagios123"
            alias: "Nagios Admin"
            email: ""
          guest:
            password: "guest123"
            alias: "Nagios Guest"
            email: ""
        groups:
          admins:
            alias: "Nagios Administrators"
            members: [
              "nagiosadmin"
              "guest"
            ]
        group:
          gid: 2418
        groupcmd:
          gid: 2419
        user:
          uid: 2418
          gid: 2418
      hadoop_group:
        gid: 2400
        name: "hadoop"
        system: true
      group:
        gid: 2414
        name: "ryba"
        system: true
      user:
        uid: 2414
        gid: 2414
        name: "ryba"
        password: "password"
        system: true
        comment: "ryba User"
        home: "/home/ryba"
      zookeeper:
        group:
          gid: 2402
          name: "zookeeper"
          system: true
        user:
          uid: 2402
          gid: 2400
          name: "zookeeper"
          system: true
          groups: "hadoop"
          comment: "Zookeeper User"
          home: "/var/lib/zookeeper"
        conf_dir: "/etc/zookeeper/conf"
        log_dir: "/var/log/zookeeper"
        port: 2181
        env:
          JAVA_HOME: "/usr/lib/jvm/java"
          CLIENT_JVMFLAGS: "-Djava.security.auth.login.config=/etc/zookeeper/conf/zookeeper-client.jaas"
      flume:
        group:
          gid: 2405
          name: "flume"
          system: true
        user:
          uid: 2405
          gid: 2405
          name: "flume"
          system: true
          comment: "Flume User"
          home: "/var/lib/flume"
        conf_dir: "/etc/flume/conf"
      ganglia:
        rrdcached_group:
          gid: 2406
          name: "rrdcached"
          system: true
        rrdcached_user:
          uid: 2406
          gid: "rrdcached"
          name: "rrdcached"
          system: true
          shell: false
          comment: "RRDtool User"
          home: "/var/rrdtool/rrdcached"
        collector_port: 8649
        slaves_port: 8660
        hbase_region_port: 8660
        nn_port: 8661
        jt_port: 8662
        hm_port: 8663
        hbase_master_port: 8663
        rm_port: 8664
        jhs_port: 8666
        spark_port: 8667
      oozie:
        group:
          gid: 2411
        user:
          uid: 2411
          gid: 2411
      pig:
        user:
          uid: 2413
          gid: 2400
      knox:
        group:
          gid: 2420
        user:
          uid: 2420
          gid: 2420
      falcon:
        group:
          gid: 2421
        user:
          uid: 2421
          gid: 2421
      elasticsearch:
        group:
          gid: 2422
        user:
          uid: 2422
          gid: 2422
      rexster:
        group:
          gid: 2423
        user:
          uid: 2423
          gid: 2423
      presto:
        group:
          gid: 2425
        user:
          uid: 2425
          gid: 2425
      spark:
        group:
          gid: 2426
        user:
          uid: 2426
          gid: 2426
      httpfs:
        group:
          gid: 2427
        user:
          uid: 2427
          gid: 2427
      nagvis:
        group:
          gid: 2429
        user:
          uid: 2429
          gid: 2429
      hdp_repo: false
      titan:
        source: "http://10.10.10.1/titan-0.5.4-hadoop2.zip"
      rack: 1
      graphite:
        carbon_port: 2023
        carbon_cache_port: 2003
        carbon_aggregator_port: 2023
        metrics_prefix: "hadoop"
        carbon_rewrite_rules: [
          "[pre]"
          "^(?P<cluster>w+).hbase.[a-zA-Z0-9_.,:;-=]*Context=(?P<context>w+).Hostname=(?P<host>w+).(?P<metric>.w+)*$ = g<cluster>.g<host>.hbase.g<context>g<metric>"
          "^(?P<cluster>w+).(?P<bean>w+).(?P<foobar>w+).Hostname=(?P<host>w+).(?P<metric>.w+)*$ = g<cluster>.g<host>.g<foobar>g<metric>"
          "^(?P<cluster>w+).(?P<bean>w+).[a-zA-Z0-9_.=]*port=(?P<port>w+).Context=(?P<context>w+).[a-zA-Z0-9_.=]*Hostname=(?P<host>w+).(?P<metric>.w+)*$ = g<cluster>.g<host>.g<context>.g<port>g<metric>"
          "^(?P<cluster>w+).(?P<bean>w+).[a-zA-Z0-9_.=]*Queue=root(?P<queue>.w+\b)*.Context=(?P<context>w+).[a-zA-Z0-9_.=]*Hostname=(?P<host>w+).(?P<metric>.w+)*$ = g<cluster>.g<host>.g<context>.queue.g<queue>g<metric>"
          "^(?P<cluster>w+).(?P<bean>w+).[a-zA-Z0-9_.=]*Context=(?P<context>w+).ProcessName=(?P<process>w+).[a-zA-Z0-9_.=]*Hostname=(?P<host>w+).(?P<metric>.w+)*$ = g<cluster>.g<host>.g<context>.g<process>g<metric>"
          "^(?P<cluster>w+).(?P<bean>w+).[a-zA-Z0-9_.=]*Context=(?P<context>w+).[a-zA-Z0-9_.=]*Hostname=(?P<host>w+).(?P<metric>.w+)*$ = g<cluster>.g<host>.g<context>g<metric>"
          "rpcdetailed = rpc"
        ]
        carbon_conf: [
          "[aggregator]"
          "LINE_RECEIVER_INTERFACE = 0.0.0.0"
          "LINE_RECEIVER_PORT = 2023"
          "PICKLE_RECEIVER_INTERFACE = 0.0.0.0"
          "PICKLE_RECEIVER_PORT = 2024"
          "LOG_LISTENER_CONNECTIONS = True"
          "FORWARD_ALL = True"
          "DESTINATIONS = 127.0.0.1:2004"
          "REPLICATION_FACTOR = 1"
          "MAX_QUEUE_SIZE = 10000"
          "USE_FLOW_CONTROL = True"
          "MAX_DATAPOINTS_PER_MESSAGE = 500"
          "MAX_AGGREGATION_INTERVALS = 5"
          "# WRITE_BACK_FREQUENCY = 0"
        ]
      proxy: null
      db_admin:
        engine: "mysql"
        host: "master3.ryba"
        path: "mysql"
        port: "3306"
        username: "root"
        password: "test123"
      hadoop_conf_dir: "/etc/hadoop/conf"
      hadoop_lib_home: "/usr/hdp/current/hadoop-client/lib"
      active_nn: false
      standby_nn_host: "master2.ryba"
      static_host: "_HOST"
      active_nn_host: "master1.ryba"
      core_jars: {}
      hadoop_classpath: ""
      hadoop_client_opts: "-Xmx2048m"
      hadoop_policy: {}
      container_executor:
        "yarn.nodemanager.local-dirs": "/data/1/yarn/local,/data/2/yarn/local"
        "yarn.nodemanager.linux-container-executor.group": "yarn"
        "yarn.nodemanager.log-dirs": "/data/1/yarn/log,/data/2/yarn/log"
        "banned.users": "hfds,yarn,mapred,bin"
        "min.user.id": "0"
      ssl_client:
        "ssl.client.truststore.location": "/etc/hadoop/conf/truststore"
        "ssl.client.truststore.password": "ryba123"
        "ssl.client.truststore.type": "jks"
      ssl_server:
        "ssl.server.keystore.location": "/etc/hadoop/conf/keystore"
        "ssl.server.keystore.password": "ryba123"
        "ssl.server.keystore.type": "jks"
        "ssl.server.keystore.keypassword": "ryba123"
        "ssl.server.truststore.location": "/etc/hadoop/conf/truststore"
        "ssl.server.truststore.password": "ryba123"
        "ssl.server.truststore.type": "jks"
    httpd:
      user:
        uid: 2416
        gid: 2416
      group:
        gid: 2416
    xasecure:
      group:
        gid: 2417
      user:
        uid: 2417
        gid: 2417
    proxy:
      system: false
      system_file: "/etc/profile.d/phyla_proxy.sh"
      host: null
      port: null
      username: null
      password: null
      secure: null
      http_proxy: null
      https_proxy: null
      http_proxy_no_auth: null
      https_proxy_no_auth: null
    curl:
      check: false
      config:
        noproxy: "localhost,127.0.0.1,.ryba"
        proxy: null
      merge: true
      users: true
      proxy: true
      check_match: {}
    profile:
      "proxy.sh": ""
    ntp:
      servers: [
        "master3.ryba"
      ]
      fudge: 14
      lag: 2000
    hdp:
      hue_smtp_host: ""
    ambari: {}
    ip: "10.10.10.16"
    modules: [
      "masson/core/reload"
      "masson/core/fstab"
      "masson/core/network"
      "masson/core/network_check"
      "masson/core/users"
      "masson/core/ssh"
      "masson/core/ntp"
      "masson/core/proxy"
      "masson/core/yum"
      "masson/core/security"
      "masson/core/iptables"
      "masson/core/krb5_client"
      "masson/core/sssd"
      "ryba/hadoop/hdfs_dn"
      "ryba/hadoop/yarn_nm"
      "ryba/hadoop/mapred_client"
      "ryba/flume"
      "ryba/phoenix/regionserver"
      "ryba/hbase/regionserver"
    ]
    host: "worker1.ryba"
    shortname: "worker1"
    metrics_sinks:
      file:
        class: "org.apache.hadoop.metrics2.sink.FileSink"
        filename: "metrics.out"
      ganglia:
        class: "org.apache.hadoop.metrics2.sink.ganglia.GangliaSink31"
        period: "10"
        supportparse: "true"
        slope: "jvm.metrics.gcCount=zero,jvm.metrics.memHeapUsedM=both"
        dmax: "jvm.metrics.threadsBlocked=70,jvm.metrics.memHeapUsedM=40"
      graphite:
        class: "org.apache.hadoop.metrics2.sink.GraphiteSink"
        period: "10"
    hostname: "worker1.ryba"
    groups: {}
    fstab:
      enabled: false
      exhaustive: false
      volumes: {}
  "worker2.ryba":
    connection:
      private_key: '''
        -----BEGIN RSA PRIVATE KEY-----
        MIIEogIBAAKCAQEArBDFt50aN9jfIJ629pRGIMA1fCMb9RyTHt9A+jx3FOsIOtJs
        eaBIpv98drbFVURr+cUs/CrgGVk5k2NIeiz0bG4ONV5nTwx38z5CzqLb7UryZS3i
        a/TS14fWOxvWTRR27R71ePX90G/ZIReKFeTrucw9y9Pl+xAzsmeblRwLBxv/SWBX
        Uai2mHAZaejlG9dGkn9f2n+oPmbgk6krLMCjLhlNBnkdroBNSXGA9ewLPFF4y54Q
        kBqmG3eLzCqAKAzwyJ5PpybtNGAWfN81gY/P5LBzC66WdtEzpwsYAv1wCioqggtg
        xVZN2s0ajxQrCxahRkXstBI2IDcm2qUTxaDbUwIDAQABAoIBAFruOi7AvXxKBhCt
        D6/bx/vC2AEUZM/yG+Wywhn8HkpVsvGzBlR4Wiy208XA7SQUlqNWimFxHyEGQCEd
        1M2MOFedCbE2hI4H3tQTUSb2dhc/Bj5mM0QuC8aPKK3wFh6B9B93vu3/wfSHR03v
        rK/JXLHBt96hyuYVN9zOWDBCs6k7SdQ2BcsQLiPg6feTsZelJDuO+DO65kKLMiz3
        mNPThErklRaKovNk47LSYakk6gsJXrpG6JWQ6nwsRenwplDwZ8Zs9mlRi7f3nChM
        3I1WlISN8y2kcQBQ94YZKk8wzH/lzmxsabcLa5ETNubxQ6ThDu1oYUIIUsQyNPm+
        DkW0VwECgYEA5MttelspKexWS39Y3sQYvZ/v8VZBQl4tRbpUWWc+PNEtcEwOBza/
        H4jBWYd2eWKTApJT1st58E4b34Mv88nQVElLb3sE7uJMkihPyNpABGbCvr63hDYw
        PyL53nKaPelY/aDnL0F8LmREfdKw/uy6+UChgkPfdo2VVk1oyvsZaRMCgYEAwIZ+
        lCmeXQ4mU6uxO+ChhDn7zw9rR5qlCyfJiLPe2lV20vaHV5ZfKIWGegsVJSpFr2ST
        5ghh+FVIneoNRtTHEKwNWCK7I6qeF+WAaci+KsLQigJQHsw58n9cdA7wHHc475n/
        pf7efoPcvk6qYOS2mpDgC87m+o3C4Dyspqp9TMECgYA4/ed+dBjT5Zg1ZDp5+zUC
        f0Wgw1CsPJNgbCK4xnv9YEnGUFuqNlvzefhX2eOMJx7hpBuYRMVSM9LDoYUfYCUx
        6bQNyAIZk2tpePsu2BbcQdC+/PjvySPJhmfhnoCHbYoKW7tazSAm2jkpcoM+bS/C
        CPRyY3/Voz0Q62VwMo5I2wKBgB4mMbZUGieqapgZwASHdeO2DNftKzioYAYyMd5F
        hLWeQqBg2Or/cmFvH5MHH0WVrBn+Xybb0zPHbzrDh1a7RX035FMUBUhdlKpbV1O5
        iwY5Qd0K5a8c/koaZckK+dELXpAvBpjhI8ieL7hhq07HIk1sOJnAye0cvBLPjZ3/
        /uVBAoGAVAs6tFpS0pFlxmg4tfGEm7/aP6FhyBHNhv2QGluw8vv/XVMzUItxGIef
        HcSMWBm08IJMRJLgmoo1cuQv6hBui7JpDeZk/20qoF2oZW9lJ9fdRObJqi61wufP
        BNiriqexq/eTy2uF9RCCjLItWxUscVMlVt4V65HLkCF5WxCQw+o=
        -----END RSA PRIVATE KEY-----
      '''
      public_key: "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCsEMW3nRo32N8gnrb2lEYgwDV8Ixv1HJMe30D6PHcU6wg60mx5oEim/3x2tsVVRGv5xSz8KuAZWTmTY0h6LPRsbg41XmdPDHfzPkLOotvtSvJlLeJr9NLXh9Y7G9ZNFHbtHvV49f3Qb9khF4oV5Ou5zD3L0+X7EDOyZ5uVHAsHG/9JYFdRqLaYcBlp6OUb10aSf1/af6g+ZuCTqSsswKMuGU0GeR2ugE1JcYD17As8UXjLnhCQGqYbd4vMKoAoDPDInk+nJu00YBZ83zWBj8/ksHMLrpZ20TOnCxgC/XAKKiqCC2DFVk3azRqPFCsLFqFGRey0EjYgNybapRPFoNtT Ryba Hadoop"
      bootstrap:
        username: "vagrant"
        password: "vagrant"
        host: "10.10.10.17"
        port: 22
        cmd: "su -"
        retry: 3
      username: "root"
      host: "10.10.10.17"
      port: 22
      private_key_location: "~/.ssh/id_rsa"
      retry: 3
      end: true
      wait: 1000
    mecano:
      cache_dir: "/home/pierrotws/workspace/ryba-cluster/conf/../resources/cache"
      log_serializer: true
    log:
      archive: true
      disabled: false
      basedir: "./log"
      fqdn_reversed: "ryba.worker2"
      filename: "worker2.log"
      elasticsearch:
        enable: false
        url: "http://localhost:9200"
        index: "masson"
    security:
      selinux: false
      limits: {}
    network:
      hosts_auto: true
      hosts:
        "127.0.0.1": "localhost localhost.localdomain localhost4 localhost4.localdomain4"
        "10.10.10.10": "repos.ryba ryba"
      resolv: '''
        search ryba
        nameserver 10.10.10.13
        nameserver 10.0.2.3
      '''
      hostname_disabled: false
    iptables:
      action: "stop"
      startup: false
      log: true
      rules: []
      log_prefix: "IPTables-Dropped: "
      log_level: 4
      log_rules: [
        {
          chain: "INPUT"
          command: "-A"
          jump: "LOGGING"
        }
        {
          chain: "LOGGING"
          command: "-A"
          "--limit": "2/min"
          jump: "LOG"
          "log-prefix": "IPTables-Dropped: "
          "log-level": 4
        }
        {
          chain: "LOGGING"
          command: "-A"
          jump: "DROP"
        }
      ]
    bind_server:
      zones: [
        "/home/pierrotws/workspace/ryba-cluster/conf/zones/ryba"
        "/home/pierrotws/workspace/ryba-cluster/conf/zones/10.10.10.in-addr.arpa"
      ]
      user:
        uid: 802
        gid: 802
      group:
        gid: 802
    ssh:
      banner:
        destination: "/etc/banner"
        content: "Welcome to Hadoop!"
      sshd_config:
        PermitRootLogin: "without-password"
    users:
      root:
        authorized_keys: [
          "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCWvEjSt2sAvRmkpkt9+u1EXuFDWJSuI1C8G/+NMcpMRDSUTary3Njqt/DC5mx7X36mVJdaq2KqgAVa28zzeuN6Yv7iuxCTw/4K7OKXYu+q0UG8BlIknWgLa8s7Nx2J69Prkb4oFgzw5IqK9EM6VMarUJUCXVNhb3zmamrF59OIxAIyQhV5i5SzoAxLIcD9EtxS/ZRf9t9fOBEhn42SVcpEWO09bUHZ11J2tw/Pwsxk+va83cH9qipVsEwIMDUCosfzV1G2zF5HhU/mhIHWRdAULpaRfd3IgNqTtI6BBi6FOFbJdrkHXPXKRybZwCxChncq1TZI2SXx6BCRpoJ/s887 m.sauvage.pierre@gmail.com"
        ]
        name: "root"
        home: "/root"
    yum:
      packages:
        tree: true
        git: true
        htop: true
        vim: true
        "yum-plugin-priorities": true
        man: true
        ksh: true
      config:
        proxy: null
        main:
          keepcache: "0"
          proxy: null
          proxy_username: null
          proxy_password: null
      copy: "/home/pierrotws/workspace/ryba-cluster/conf/user/offline/*.repo"
      clean: false
      merge: true
      update: true
      proxy: true
      epel: true
      epel_url: "http://download.fedoraproject.org/pub/epel/6/i386/epel-release-6-8.noarch.rpm"
    mysql:
      server:
        current_password: ""
        password: "test123"
        my_cnf:
          mysqld:
            innodb_file_per_table: "1"
    openldap_server:
      suffix: "dc=ryba"
      root_dn: "cn=Manager,dc=ryba"
      root_password: "test"
      config_dn: "cn=admin,cn=config"
      config_password: "test"
      users_dn: "ou=users,dc=ryba"
      groups_dn: "ou=groups,dc=ryba"
      ldapdelete: []
      ldapadd: []
      tls: true
      tls_ca_cert_file: "/home/pierrotws/workspace/ryba-cluster/conf/certs/cacert.pem"
      tls_cert_file: "/home/pierrotws/workspace/ryba-cluster/conf/certs/master3_cert.pem"
      tls_key_file: "/home/pierrotws/workspace/ryba-cluster/conf/certs/master3_key.pem"
      proxy_user:
        uidNumber: 801
        gidNumber: 801
      proxy_group:
        gidNumber: 801
    openldap_client:
      certificates: [
        "/home/pierrotws/workspace/ryba-cluster/conf/certs/master3_cert.pem"
      ]
      config:
        BASE: "dc=ryba"
        URI: "ldaps://master3.ryba"
        TLS_CACERTDIR: "/etc/openldap/cacerts"
        TLS_REQCERT: "allow"
        TIMELIMIT: "15"
        TIMEOUT: "20"
      suffix: "dc=ryba"
      root_dn: "cn=Manager,dc=ryba"
      root_password: "test"
    openldap_server_krb5:
      manager_dn: "cn=Manager,dc=ryba"
      manager_password: "test"
      krbadmin_user:
        mail: "david@adaltas.com"
        userPassword: "test"
        uidNumber: 800
        gidNumber: 800
      krbadmin_group:
        gidNumber: 800
    krb5:
      etc_krb5_conf:
        logging:
          default: "SYSLOG:INFO:LOCAL1"
          kdc: "SYSLOG:NOTICE:LOCAL1"
          admin_server: "SYSLOG:WARNING:LOCAL1"
        libdefaults:
          dns_lookup_realm: false
          dns_lookup_kdc: false
          ticket_lifetime: "24h"
          renew_lifetime: "7d"
          forwardable: true
          allow_weak_crypto: "false"
          clockskew: "300"
          rdns: "false"
          default_realm: "HADOOP.RYBA"
        realms:
          "USERS.RYBA":
            kadmin_principal: "wdavidw/admin@USERS.RYBA"
            kadmin_password: "test"
            principals: [
              {
                principal: "krbtgt/HADOOP.RYBA@USERS.RYBA"
                password: "test"
              }
            ]
            kdc: [
              "master3.ryba"
            ]
            admin_server: "master3.ryba"
            default_domain: "users.ryba"
          "HADOOP.RYBA":
            kadmin_principal: "wdavidw/admin@HADOOP.RYBA"
            kadmin_password: "test"
            principals: [
              {
                principal: "krbtgt/HADOOP.RYBA@USERS.RYBA"
                password: "test"
              }
            ]
            kdc: [
              "master1.ryba"
            ]
            admin_server: "master1.ryba"
            default_domain: "hadoop.ryba"
        domain_realm:
          ryba: "HADOOP.RYBA"
        appdefaults:
          pam:
            debug: false
            ticket_lifetime: 36000
            renew_lifetime: 36000
            forwardable: true
            krb4_convert: false
        dbmodules: {}
      kdc_conf:
        realms: {}
      sshd: {}
      kinit: "/usr/bin/kinit"
    sssd:
      force_check: false
      certificates: [
        "/home/pierrotws/workspace/ryba-cluster/conf/certs/cacert.pem"
      ]
      config:
        sssd:
          config_file_version: "2"
          reconnection_retries: "3"
          sbus_timeout: "30"
          services: "nss, pam"
          debug_level: "1"
          domains: "hadoop,users"
        nss:
          filter_groups: "root"
          filter_users: "root"
          reconnection_retries: "3"
          entry_cache_timeout: "300"
          entry_cache_nowait_percentage: "75"
          debug_level: "1"
        pam:
          reconnection_retries: "3"
          offline_credentials_expiration: "2"
          offline_failed_login_attempts: "3"
          offline_failed_login_delay: "5"
          debug_level: "1"
        "domain/hadoop":
          debug_level: "1"
          cache_credentials: "True"
          ldap_search_base: "ou=users,dc=ryba"
          ldap_group_search_base: "ou=groups,dc=ryba"
          id_provider: "ldap"
          auth_provider: "ldap"
          chpass_provider: "ldap"
          ldap_uri: "ldaps://master3.ryba:636"
          ldap_tls_cacertdir: "/etc/openldap/cacerts"
          ldap_default_bind_dn: "cn=Manager,dc=ryba"
          ldap_default_authtok: "test"
          ldap_id_use_start_tls: "True"
        "domain/users":
          debug_level: "1"
          cache_credentials: "True"
          ldap_search_base: "ou=users,dc=ryba"
          ldap_group_search_base: "ou=groups,dc=ryba"
          id_provider: "ldap"
          auth_provider: "ldap"
          chpass_provider: "ldap"
          ldap_uri: "ldaps://master3.ryba:636"
          ldap_tls_cacertdir: "/etc/openldap/cacerts"
          ldap_default_bind_dn: "cn=Manager,dc=ryba"
          ldap_default_authtok: "test"
          ldap_id_use_start_tls: "False"
      merge: false
      test_user: null
    java:
      java_home: "/usr/lib/jvm/java"
      jre_home: "/usr/lib/jvm/java/jre"
      proxy: null
      openjdk: true
    ryba:
      clean_logs: true
      force_check: false
      check_hdfs_fsck: false
      security: "kerberos"
      realm: "HADOOP.RYBA"
      nameservice: "torval"
      krb5_user:
        password: "test123"
        password_sync: true
        principal: "ryba@HADOOP.RYBA"
      ssl:
        cacert: "/home/pierrotws/workspace/ryba-cluster/conf/certs/cacert.pem"
        cert: "/home/pierrotws/workspace/ryba-cluster/conf/certs/worker2_cert.pem"
        key: "/home/pierrotws/workspace/ryba-cluster/conf/certs/worker2_key.pem"
      ambari:
        repo: "/home/pierrotws/workspace/ryba-cluster/conf/resources/repos/ambari-2.0.0.repo"
      ssh_fencing:
        private_key: "/home/pierrotws/workspace/ryba-cluster/conf/hdfs_keys/id_rsa"
        public_key: "/home/pierrotws/workspace/ryba-cluster/conf/hdfs_keys/id_rsa.pub"
      hadoop_opts: "-Djava.net.preferIPv4Stack=true -Dsun.security.krb5.debug=false"
      core_site:
        "hadoop.ssl.exclude.cipher.suites": "SSL_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA,SSL_RSA_EXPORT_WITH_DES40_CBC_SHA,SSL_RSA_EXPORT_WITH_RC4_40_MD5,TLS_DHE_RSA_WITH_AES_128_CBC_SHA,TLS_DHE_RSA_WITH_AES_256_CBC_SHA"
        "hadoop.proxyuser.httpfs.hosts": "master1.ryba,master2.ryba,master3.ryba"
        "hadoop.proxyuser.httpfs.groups": "*"
        "io.compression.codecs": "org.apache.hadoop.io.compress.GzipCodec,org.apache.hadoop.io.compress.DefaultCodec,org.apache.hadoop.io.compress.SnappyCodec"
        "fs.defaultFS": "hdfs://torval:8020"
        "hadoop.security.authentication": "kerberos"
        "hadoop.security.authorization": "true"
        "hadoop.rpc.protection": "authentication"
        "hadoop.security.group.mapping": "org.apache.hadoop.security.JniBasedUnixGroupsMappingWithFallback"
        "ha.zookeeper.quorum": [
          "master1.ryba:2181"
          "master2.ryba:2181"
          "master3.ryba:2181"
        ]
        "net.topology.script.file.name": "/etc/hadoop/conf/rack_topology.sh"
        "hadoop.http.filter.initializers": "org.apache.hadoop.security.AuthenticationFilterInitializer"
        "hadoop.http.authentication.type": "kerberos"
        "hadoop.http.authentication.token.validity": "36000"
        "hadoop.http.authentication.signature.secret.file": "/etc/hadoop/hadoop-http-auth-signature-secret"
        "hadoop.http.authentication.simple.anonymous.allowed": "false"
        "hadoop.http.authentication.kerberos.principal": "HTTP/_HOST@HADOOP.RYBA"
        "hadoop.http.authentication.kerberos.keytab": "/etc/security/keytabs/spnego.service.keytab"
        "hadoop.http.authentication.cookie.domain": "ryba"
        "hadoop.security.auth_to_local": '''
          
          RULE:[2:$1@$0]([rn]m@HADOOP\\.RYBA)s/.*/yarn/
          RULE:[2:$1@$0](jhs@HADOOP\\.RYBA)s/.*/mapred/
          RULE:[2:$1@$0]([nd]n@HADOOP\\.RYBA)s/.*/hdfs/
          RULE:[2:$1@$0](hm@HADOOP\\.RYBA)s/.*/hbase/
          RULE:[2:$1@$0](rs@HADOOP\\.RYBA)s/.*/hbase/
          RULE:[2:$1@$0](opentsdb@HADOOP\\.RYBA)s/.*/hbase/
          DEFAULT
          RULE:[1:$1](yarn|mapred|hdfs|hive|hbase|oozie)s/.*/nobody/
          RULE:[2:$1](yarn|mapred|hdfs|hive|hbase|oozie)s/.*/nobody/
          RULE:[1:$1]
          RULE:[2:$1]
          
        '''
        "hadoop.proxyuser.HTTP.hosts": "*"
        "hadoop.proxyuser.HTTP.groups": "*"
        "hadoop.proxyuser.hbase.hosts": "*"
        "hadoop.proxyuser.hbase.groups": "*"
        "hadoop.proxyuser.hive.groups": "*"
        "hadoop.proxyuser.hive.hosts": "*"
        "hadoop.proxyuser.oozie.hosts": "master3.ryba"
        "hadoop.proxyuser.oozie.groups": "*"
        "hadoop.proxyuser.falcon.groups": "*"
        "hadoop.proxyuser.falcon.hosts": "front1.ryba"
        "hadoop.proxyuser.knox.hosts": "front1.ryba"
        "hadoop.proxyuser.knox.groups": "*"
        "hadoop.ssl.require.client.cert": "false"
        "hadoop.ssl.hostname.verifier": "DEFAULT"
        "hadoop.ssl.keystores.factory.class": "org.apache.hadoop.security.ssl.FileBasedKeyStoresFactory"
        "hadoop.ssl.server.conf": "ssl-server.xml"
        "hadoop.ssl.client.conf": "ssl-client.xml"
      hadoop_metrics:
        "*.sink.file.class": "org.apache.hadoop.metrics2.sink.FileSink"
        sinks:
          file: true
          ganglia: false
          graphite: false
        config:
          "*.period": "60"
          "*.sink.file.class": "org.apache.hadoop.metrics2.sink.FileSink"
          "*.sink.file.filename": "metrics.out"
          "namenode.sink.file.filename": "namenode-metrics.out"
          "datanode.sink.file.filename": "datanode-metrics.out"
          "resourcemanager.sink.file.filename": "resourcemanager-metrics.out"
          "nodemanager.sink.file.filename": "nodemanager-metrics.out"
          "mrappmaster.sink.file.filename": "mrappmaster-metrics.out"
          "jobhistoryserver.sink.file.filename": "jobhistoryserver-metrics.out"
      hadoop_heap: "512"
      hadoop_namenode_init_heap: "-Xms512m"
      hdfs:
        user:
          limits:
            nproc: 16384
            nofile: 16384
          uid: 2401
          gid: "hdfs"
          name: "hdfs"
          system: true
          groups: "hadoop"
          comment: "Hadoop HDFS User"
          home: "/var/lib/hadoop-hdfs"
        krb5_user:
          password: "hdfs123"
          password_sync: true
          principal: "hdfs@HADOOP.RYBA"
        sysctl:
          "vm.swappiness": 0
          "vm.overcommit_memory": 1
          "vm.overcommit_ratio": 100
          "net.core.somaxconn": 1024
        site:
          "dfs.namenode.safemode.extension": 1000
          "dfs.replication": 2
          "dfs.datanode.data.dir": "/data/1/hdfs/data,/data/2/hdfs/data"
          "dfs.namenode.kerberos.principal": "nn/_HOST@HADOOP.RYBA"
          "dfs.namenode.kerberos.internal.spnego.principal": "HTTP/_HOST@HADOOP.RYBA"
          "dfs.namenode.kerberos.https.principal": "HTTP/_HOST@HADOOP.RYBA"
          "dfs.web.authentication.kerberos.principal": "HTTP/_HOST@HADOOP.RYBA"
          "dfs.ha.automatic-failover.enabled": "true"
          "dfs.nameservices": "torval"
          "dfs.internal.nameservices": "torval"
          "dfs.ha.namenodes.torval": "master1,master2"
          "dfs.namenode.http-address": null
          "dfs.namenode.https-address": null
          "dfs.namenode.rpc-address.torval.master1": "master1.ryba:8020"
          "dfs.namenode.http-address.torval.master1": "master1.ryba:50070"
          "dfs.namenode.https-address.torval.master1": "master1.ryba:50470"
          "dfs.namenode.rpc-address.torval.master2": "master2.ryba:8020"
          "dfs.namenode.http-address.torval.master2": "master2.ryba:50070"
          "dfs.namenode.https-address.torval.master2": "master2.ryba:50470"
          "dfs.client.failover.proxy.provider.torval": "org.apache.hadoop.hdfs.server.namenode.ha.ConfiguredFailoverProxyProvider"
          "dfs.http.policy": "HTTPS_ONLY"
          "dfs.datanode.data.dir.perm": "700"
          "dfs.datanode.address": "0.0.0.0:1004"
          "dfs.datanode.ipc.address": "0.0.0.0:50020"
          "dfs.datanode.http.address": "0.0.0.0:1006"
          "dfs.datanode.https.address": "0.0.0.0:50475"
          "dfs.datanode.kerberos.principal": "dn/_HOST@HADOOP.RYBA"
          "dfs.datanode.keytab.file": "/etc/security/keytabs/dn.service.keytab"
          "dfs.datanode.failed.volumes.tolerated": "0"
          "dfs.datanode.fsdataset.volume.choosing.policy": "org.apache.hadoop.hdfs.server.datanode.fsdataset.AvailableSpaceVolumeChoosingPolicy"
          "dfs.datanode.available-space-volume-choosing-policy.balanced-space-threshold": "10737418240"
          "dfs.datanode.available-space-volume-choosing-policy.balanced-space-preference-fraction": "1.0"
          "dfs.datanode.du.reserved": "1073741824"
          "dfs.client.read.shortcircuit": "true"
          "dfs.domain.socket.path": "/var/lib/hadoop-hdfs/dn_socket"
          "dfs.namenode.kerberos.principal.pattern": "*"
        group:
          gid: 2401
          name: "hdfs"
          system: true
        nn:
          site:
            "dfs.http.policy": "HTTPS_ONLY"
            "fs.permissions.umask-mode": "027"
            "dfs.block.access.token.enable": "true"
        log_dir: "/var/log/hadoop-hdfs"
        pid_dir: "/var/run/hadoop-hdfs"
        secure_dn_pid_dir: "/var/run/hadoop-hdfs"
        secure_dn_user: "hdfs"
        dn:
          conf_dir: "/etc/hadoop-hdfs-datanode/conf"
        datanode_opts: ""
      zkfc:
        digest:
          name: "zkfc"
          password: "zkfc123"
      yarn:
        user:
          limits:
            nproc: 16384
            nofile: 16384
          uid: 2403
          gid: "yarn"
          name: "yarn"
          system: true
          groups: "hadoop"
          comment: "Hadoop YARN User"
          home: "/var/lib/hadoop-yarn"
        opts: "-Dsun.net.spi.nameservice.provider.1=sun,dns"
        site:
          "yarn.nodemanager.resource.percentage-physical-cpu-limit": "100"
          "yarn.nodemanager.resource.memory-mb": 1536
          "yarn.nodemanager.vmem-pmem-ratio": "2.1"
          "yarn.nodemanager.resource.cpu-vcores": 3
          "yarn.nodemanager.local-dirs": "/data/1/yarn/local,/data/2/yarn/local"
          "yarn.nodemanager.log-dirs": "/data/1/yarn/log,/data/2/yarn/log"
          "yarn.http.policy": "HTTPS_ONLY"
          "yarn.nodemanager.address": "worker2.ryba:45454"
          "yarn.nodemanager.localizer.address": "worker2.ryba:8040"
          "yarn.nodemanager.webapp.address": "worker2.ryba:8042"
          "yarn.nodemanager.webapp.https.address": "worker2.ryba:8044"
          "yarn.nodemanager.remote-app-log-dir": "/app-logs"
          "yarn.nodemanager.keytab": "/etc/security/keytabs/nm.service.keytab"
          "yarn.nodemanager.principal": "nm/_HOST@HADOOP.RYBA"
          "yarn.nodemanager.container-executor.class": "org.apache.hadoop.yarn.server.nodemanager.LinuxContainerExecutor"
          "yarn.nodemanager.linux-container-executor.group": "yarn"
          "yarn.nodemanager.linux-container-executor.cgroups.strict-resource-usage": "false"
          "yarn.nodemanager.log.retain-second": null
          "yarn.nodemanager.log.retain-seconds": "604800"
          "yarn.log-aggregation-enable": "true"
          "yarn.log-aggregation.retain-seconds": "2592000"
          "yarn.log-aggregation.retain-check-interval-seconds": "-1"
          "yarn.resourcemanager.principal": "rm/_HOST@HADOOP.RYBA"
          "yarn.resourcemanager.cluster-id": "yarn_cluster_01"
          "yarn.resourcemanager.ha.enabled": "true"
          "yarn.resourcemanager.ha.rm-ids": "master1,master2"
          "yarn.resourcemanager.webapp.delegation-token-auth-filter.enabled": "true"
          "yarn.resourcemanager.address.master1": "master1.ryba:8050"
          "yarn.resourcemanager.scheduler.address.master1": "master1.ryba:8030"
          "yarn.resourcemanager.admin.address.master1": "master1.ryba:8141"
          "yarn.resourcemanager.webapp.address.master1": "master1.ryba:8088"
          "yarn.resourcemanager.webapp.https.address.master1": "master1.ryba:8090"
          "yarn.resourcemanager.resource-tracker.address.master1": "master1.ryba:8025"
          "yarn.resourcemanager.address.master2": "master2.ryba:8050"
          "yarn.resourcemanager.scheduler.address.master2": "master2.ryba:8030"
          "yarn.resourcemanager.admin.address.master2": "master2.ryba:8141"
          "yarn.resourcemanager.webapp.address.master2": "master2.ryba:8088"
          "yarn.resourcemanager.webapp.https.address.master2": "master2.ryba:8090"
          "yarn.resourcemanager.resource-tracker.address.master2": "master2.ryba:8025"
          "yarn.timeline-service.enabled": "true"
          "yarn.timeline-service.address": "master3.ryba:10200"
          "yarn.timeline-service.webapp.address": "master3.ryba:8188"
          "yarn.timeline-service.webapp.https.address": "master3.ryba:8190"
          "yarn.timeline-service.principal": "ats/_HOST@HADOOP.RYBA"
          "yarn.timeline-service.http-authentication.type": "kerberos"
          "yarn.timeline-service.http-authentication.kerberos.principal": "HTTP/_HOST@HADOOP.RYBA"
          "yarn.nodemanager.recovery.enabled": "true"
          "yarn.nodemanager.recovery.dir": "/var/yarn/recovery-state"
          "yarn.nodemanager.linux-container-executor.resources-handler.class": "org.apache.hadoop.yarn.server.nodemanager.util.CgroupsLCEResourcesHandler"
          "yarn.nodemanager.linux-container-executor.cgroups.hierarchy": "/yarn"
          "yarn.nodemanager.linux-container-executor.cgroups.mount": "true"
          "yarn.nodemanager.linux-container-executor.cgroups.mount-path": "/cgroup"
          "yarn.application.classpath": "$HADOOP_CONF_DIR,/usr/hdp/current/hadoop-client/*,/usr/hdp/current/hadoop-client/lib/*,/usr/hdp/current/hadoop-hdfs-client/*,/usr/hdp/current/hadoop-hdfs-client/lib/*,/usr/hdp/current/hadoop-yarn-client/*,/usr/hdp/current/hadoop-yarn-client/lib/*"
          "yarn.generic-application-history.save-non-am-container-meta-info": "true"
          "yarn.scheduler.minimum-allocation-mb": null
          "yarn.scheduler.maximum-allocation-mb": null
        group:
          gid: 2403
          name: "yarn"
          system: true
        log_dir: "/var/log/hadoop-yarn"
        pid_dir: "/var/run/hadoop-yarn"
        home: "/usr/hdp/current/hadoop-yarn-nodemanager"
        nm:
          conf_dir: "/etc/hadoop-yarn-nodemanager/conf"
          opts: ""
          heapsize: "1024"
        conf_dir: "/etc/hadoop/conf"
        heapsize: "1024"
      capacity_scheduler:
        "yarn.scheduler.capacity.maximum-am-resource-percent": ".5"
      mapred:
        user:
          limits:
            nproc: 16384
            nofile: 16384
          uid: 2404
          gid: "mapred"
          name: "mapred"
          system: true
          groups: "hadoop"
          comment: "Hadoop MapReduce User"
          home: "/var/lib/hadoop-mapreduce"
        site:
          "mapreduce.job.counters.max": "10000"
          "mapreduce.job.counters.limit": "10000"
          "yarn.app.mapreduce.am.resource.mb": "256"
          "yarn.app.mapreduce.am.command-opts": "-Xmx204m"
          "mapreduce.map.memory.mb": "512"
          "mapreduce.reduce.memory.mb": "1024"
          "mapreduce.map.java.opts": "-Xmx409m"
          "mapreduce.reduce.java.opts": "-Xmx819m"
          "mapreduce.task.io.sort.mb": "204"
          "mapreduce.map.cpu.vcores": "1"
          "mapreduce.reduce.cpu.vcores": "1"
          "mapreduce.reduce.shuffle.parallelcopies": "50"
          "mapreduce.admin.map.child.java.opts": "-server -Djava.net.preferIPv4Stack=true -Dhdp.version=${hdp.version}"
          "mapreduce.admin.reduce.child.java.opts": null
          "mapreduce.task.io.sort.factor": 100
          "mapreduce.admin.user.env": "LD_LIBRARY_PATH=/usr/hdp/${hdp.version}/hadoop/lib/native:/usr/hdp/${hdp.version}/hadoop/lib/native/Linux-amd64-64"
          "mapreduce.application.framework.path": "/hdp/apps/${hdp.version}/mapreduce/mapreduce.tar.gz#mr-framework"
          "mapreduce.application.classpath": "$PWD/mr-framework/hadoop/share/hadoop/mapreduce/*:$PWD/mr-framework/hadoop/share/hadoop/mapreduce/lib/*:$PWD/mr-framework/hadoop/share/hadoop/common/*:$PWD/mr-framework/hadoop/share/hadoop/common/lib/*:$PWD/mr-framework/hadoop/share/hadoop/yarn/*:$PWD/mr-framework/hadoop/share/hadoop/yarn/lib/*:$PWD/mr-framework/hadoop/share/hadoop/hdfs/*:$PWD/mr-framework/hadoop/share/hadoop/hdfs/lib/*:/usr/hdp/current/share/lzo/0.6.0/lib/hadoop-lzo-0.6.0.jar:/etc/hadoop/conf/secure"
          "yarn.app.mapreduce.am.staging-dir": "/user"
          "mapreduce.jobhistory.address": "master3.ryba:10020"
          "mapreduce.jobhistory.webapp.address": "master3.ryba:19888"
          "mapreduce.jobhistory.webapp.https.address": "master3.ryba:19889"
          "mapreduce.jobhistory.done-dir": null
          "mapreduce.jobhistory.intermediate-done-dir": null
          "mapreduce.jobhistory.principal": "jhs/master3.ryba@HADOOP.RYBA"
          "yarn.app.mapreduce.am.job.client.port-range": "59100-59200"
          "mapreduce.framework.name": "yarn"
          "mapreduce.cluster.local.dir": null
          "mapreduce.jobtracker.system.dir": null
        group:
          gid: 2404
          name: "mapred"
          system: true
        log_dir: "/var/log/hadoop-mapreduce"
        pid_dir: "/var/run/hadoop-mapreduce"
      hive:
        user:
          limits:
            nproc: 16384
            nofile: 16384
          uid: 2407
          gid: 2407
        site:
          "javax.jdo.option.ConnectionDriverName": "com.mysql.jdbc.Driver"
          "javax.jdo.option.ConnectionUserName": "hive"
          "javax.jdo.option.ConnectionPassword": "hive123"
        group:
          gid: 2407
      hue:
        ini:
          desktop:
            smtp:
              host: ""
            database:
              engine: "mysql"
              password: "hue123"
        ssl:
          certificate: "/home/pierrotws/workspace/ryba-cluster/conf/certs/master3_cert.pem"
          private_key: "/home/pierrotws/workspace/ryba-cluster/conf/certs/master3_key.pem"
          client_ca: "/home/pierrotws/workspace/ryba-cluster/conf/certs/cacert.pem"
        group:
          gid: 2410
        user:
          uid: 2410
          gid: 2410
      sqoop:
        libs: []
        user:
          uid: 2412
          gid: 2400
      hbase:
        regionserver_opts: "-Xmx128m"
        admin:
          password: "hbase123"
          name: "hbase"
          principal: "hbase@HADOOP.RYBA"
        metrics:
          "*.sink.file.class": "org.apache.hadoop.metrics2.sink.FileSink"
          sinks:
            file: true
            ganglia: false
            graphite: false
          config:
            "*.period": "60"
            "*.sink.file.class": "org.apache.hadoop.metrics2.sink.FileSink"
            "*.sink.file.filename": "metrics.out"
            "hbase.sink.file.filename": "hbase-metrics.out"
        group:
          gid: 2409
          name: "hbase"
          system: true
        user:
          uid: 2409
          gid: "hbase"
          name: "hbase"
          system: true
          comment: "HBase User"
          home: "/var/run/hbase"
          groups: "hadoop"
          limits:
            nofile: 64000
            nproc: true
        site:
          "hadoop.proxyuser.hbase_rest.groups": "*"
          "hadoop.proxyuser.hbase_rest.hosts": "*"
          "zookeeper.znode.parent": "/hbase"
          "hbase.cluster.distributed": "true"
          "hbase.rootdir": "hdfs://torval:8020/apps/hbase/data"
          "hbase.zookeeper.quorum": "master1.ryba,master2.ryba,master3.ryba"
          "hbase.zookeeper.property.clientPort": "2181"
          "dfs.domain.socket.path": "/var/lib/hadoop-hdfs/dn_socket"
          "hbase.security.authentication": "kerberos"
          "hbase.security.authorization": "true"
          "hbase.rpc.engine": "org.apache.hadoop.hbase.ipc.SecureRpcEngine"
          "hbase.superuser": "hbase"
          "hbase.bulkload.staging.dir": "/apps/hbase/staging"
          "hbase.regionserver.storefile.refresh.all": "true"
          "hbase.regionserver.storefile.refresh.period": "30000"
          "hbase.region.replica.replication.enabled": "true"
          "hbase.master.hfilecleaner.ttl": "3600000"
          "hbase.master.loadbalancer.class": "org.apache.hadoop.hbase.master.balancer.StochasticLoadBalancer"
          "hbase.meta.replica.count": "3"
          "hbase.region.replica.wait.for.primary.flush": "true"
          "hbase.region.replica.storefile.refresh.memstore.multiplier": "4"
          "hbase.regionserver.port": "60020"
          "hbase.regionserver.info.port": "60030"
          "hbase.ssl.enabled": "true"
          "hbase.regionserver.handler.count": 60
          "hbase.master.kerberos.principal": "hbase/_HOST@HADOOP.RYBA"
          "hbase.regionserver.keytab.file": "/etc/security/keytabs/rs.service.keytab"
          "hbase.regionserver.kerberos.principal": "hbase/_HOST@HADOOP.RYBA"
          "hbase.regionserver.global.memstore.upperLimit": null
          "hbase.regionserver.global.memstore.size": "0.4"
          "hbase.coprocessor.region.classes": [
            "org.apache.hadoop.hbase.security.token.TokenProvider"
            "org.apache.hadoop.hbase.security.access.SecureBulkLoadEndpoint"
            "org.apache.hadoop.hbase.security.access.AccessController"
          ]
          "hbase.defaults.for.version.skip": "true"
          "phoenix.functions.allowUserDefinedFunctions": "true"
          "hbase.regionserver.wal.codec": "org.apache.hadoop.hbase.regionserver.wal.IndexedWALEditCodec"
          "hbase.rpc.controllerfactory.class": "org.apache.hadoop.hbase.ipc.controller.ServerRpcControllerFactory"
          "hbase.regionserver.rpc.scheduler.factory.class": "org.apache.hadoop.hbase.ipc.PhoenixRpcSchedulerFactory"
        test:
          default_table: "ryba"
        conf_dir: "/etc/hbase/conf"
        log_dir: "/var/log/hbase"
        pid_dir: "/var/run/hbase"
        env:
          JAVA_HOME: "/usr/lib/jvm/java"
          HBASE_LOG_DIR: "/var/log/hbase"
          HBASE_OPTS: "-ea -XX:+UseConcMarkSweepGC -XX:+CMSIncrementalMode"
          HBASE_MASTER_OPTS: "-Xmx2048m"
          HBASE_REGIONSERVER_OPTS: "-Xmn200m -Xms4096m -Xmx4096m -Djava.security.auth.login.config=/etc/hbase/conf/hbase-regionserver.jaas"
      kafka:
        broker:
          heapsize: 128
        group:
          gid: 2424
        user:
          uid: 2424
          gid: 2424
      opentsdb:
        version: "2.2.0RC3"
        group:
          gid: 2428
        user:
          uid: 2428
          gid: 2428
      nagios:
        users:
          nagiosadmin:
            password: "nagios123"
            alias: "Nagios Admin"
            email: ""
          guest:
            password: "guest123"
            alias: "Nagios Guest"
            email: ""
        groups:
          admins:
            alias: "Nagios Administrators"
            members: [
              "nagiosadmin"
              "guest"
            ]
        group:
          gid: 2418
        groupcmd:
          gid: 2419
        user:
          uid: 2418
          gid: 2418
      hadoop_group:
        gid: 2400
        name: "hadoop"
        system: true
      group:
        gid: 2414
        name: "ryba"
        system: true
      user:
        uid: 2414
        gid: 2414
        name: "ryba"
        password: "password"
        system: true
        comment: "ryba User"
        home: "/home/ryba"
      zookeeper:
        group:
          gid: 2402
          name: "zookeeper"
          system: true
        user:
          uid: 2402
          gid: 2400
          name: "zookeeper"
          system: true
          groups: "hadoop"
          comment: "Zookeeper User"
          home: "/var/lib/zookeeper"
        conf_dir: "/etc/zookeeper/conf"
        log_dir: "/var/log/zookeeper"
        port: 2181
        env:
          JAVA_HOME: "/usr/lib/jvm/java"
          CLIENT_JVMFLAGS: "-Djava.security.auth.login.config=/etc/zookeeper/conf/zookeeper-client.jaas"
      flume:
        group:
          gid: 2405
          name: "flume"
          system: true
        user:
          uid: 2405
          gid: 2405
          name: "flume"
          system: true
          comment: "Flume User"
          home: "/var/lib/flume"
        conf_dir: "/etc/flume/conf"
      ganglia:
        rrdcached_group:
          gid: 2406
          name: "rrdcached"
          system: true
        rrdcached_user:
          uid: 2406
          gid: "rrdcached"
          name: "rrdcached"
          system: true
          shell: false
          comment: "RRDtool User"
          home: "/var/rrdtool/rrdcached"
        collector_port: 8649
        slaves_port: 8660
        hbase_region_port: 8660
        nn_port: 8661
        jt_port: 8662
        hm_port: 8663
        hbase_master_port: 8663
        rm_port: 8664
        jhs_port: 8666
        spark_port: 8667
      oozie:
        group:
          gid: 2411
        user:
          uid: 2411
          gid: 2411
      pig:
        user:
          uid: 2413
          gid: 2400
      knox:
        group:
          gid: 2420
        user:
          uid: 2420
          gid: 2420
      falcon:
        group:
          gid: 2421
        user:
          uid: 2421
          gid: 2421
      elasticsearch:
        group:
          gid: 2422
        user:
          uid: 2422
          gid: 2422
      rexster:
        group:
          gid: 2423
        user:
          uid: 2423
          gid: 2423
      presto:
        group:
          gid: 2425
        user:
          uid: 2425
          gid: 2425
      spark:
        group:
          gid: 2426
        user:
          uid: 2426
          gid: 2426
      httpfs:
        group:
          gid: 2427
        user:
          uid: 2427
          gid: 2427
      nagvis:
        group:
          gid: 2429
        user:
          uid: 2429
          gid: 2429
      hdp_repo: false
      titan:
        source: "http://10.10.10.1/titan-0.5.4-hadoop2.zip"
      rack: 2
      graphite:
        carbon_port: 2023
        carbon_cache_port: 2003
        carbon_aggregator_port: 2023
        metrics_prefix: "hadoop"
        carbon_rewrite_rules: [
          "[pre]"
          "^(?P<cluster>w+).hbase.[a-zA-Z0-9_.,:;-=]*Context=(?P<context>w+).Hostname=(?P<host>w+).(?P<metric>.w+)*$ = g<cluster>.g<host>.hbase.g<context>g<metric>"
          "^(?P<cluster>w+).(?P<bean>w+).(?P<foobar>w+).Hostname=(?P<host>w+).(?P<metric>.w+)*$ = g<cluster>.g<host>.g<foobar>g<metric>"
          "^(?P<cluster>w+).(?P<bean>w+).[a-zA-Z0-9_.=]*port=(?P<port>w+).Context=(?P<context>w+).[a-zA-Z0-9_.=]*Hostname=(?P<host>w+).(?P<metric>.w+)*$ = g<cluster>.g<host>.g<context>.g<port>g<metric>"
          "^(?P<cluster>w+).(?P<bean>w+).[a-zA-Z0-9_.=]*Queue=root(?P<queue>.w+\b)*.Context=(?P<context>w+).[a-zA-Z0-9_.=]*Hostname=(?P<host>w+).(?P<metric>.w+)*$ = g<cluster>.g<host>.g<context>.queue.g<queue>g<metric>"
          "^(?P<cluster>w+).(?P<bean>w+).[a-zA-Z0-9_.=]*Context=(?P<context>w+).ProcessName=(?P<process>w+).[a-zA-Z0-9_.=]*Hostname=(?P<host>w+).(?P<metric>.w+)*$ = g<cluster>.g<host>.g<context>.g<process>g<metric>"
          "^(?P<cluster>w+).(?P<bean>w+).[a-zA-Z0-9_.=]*Context=(?P<context>w+).[a-zA-Z0-9_.=]*Hostname=(?P<host>w+).(?P<metric>.w+)*$ = g<cluster>.g<host>.g<context>g<metric>"
          "rpcdetailed = rpc"
        ]
        carbon_conf: [
          "[aggregator]"
          "LINE_RECEIVER_INTERFACE = 0.0.0.0"
          "LINE_RECEIVER_PORT = 2023"
          "PICKLE_RECEIVER_INTERFACE = 0.0.0.0"
          "PICKLE_RECEIVER_PORT = 2024"
          "LOG_LISTENER_CONNECTIONS = True"
          "FORWARD_ALL = True"
          "DESTINATIONS = 127.0.0.1:2004"
          "REPLICATION_FACTOR = 1"
          "MAX_QUEUE_SIZE = 10000"
          "USE_FLOW_CONTROL = True"
          "MAX_DATAPOINTS_PER_MESSAGE = 500"
          "MAX_AGGREGATION_INTERVALS = 5"
          "# WRITE_BACK_FREQUENCY = 0"
        ]
      proxy: null
      db_admin:
        engine: "mysql"
        host: "master3.ryba"
        path: "mysql"
        port: "3306"
        username: "root"
        password: "test123"
      hadoop_conf_dir: "/etc/hadoop/conf"
      hadoop_lib_home: "/usr/hdp/current/hadoop-client/lib"
      active_nn: false
      standby_nn_host: "master2.ryba"
      static_host: "_HOST"
      active_nn_host: "master1.ryba"
      core_jars: {}
      hadoop_classpath: ""
      hadoop_client_opts: "-Xmx2048m"
      hadoop_policy: {}
      container_executor:
        "yarn.nodemanager.local-dirs": "/data/1/yarn/local,/data/2/yarn/local"
        "yarn.nodemanager.linux-container-executor.group": "yarn"
        "yarn.nodemanager.log-dirs": "/data/1/yarn/log,/data/2/yarn/log"
        "banned.users": "hfds,yarn,mapred,bin"
        "min.user.id": "0"
      ssl_client:
        "ssl.client.truststore.location": "/etc/hadoop/conf/truststore"
        "ssl.client.truststore.password": "ryba123"
        "ssl.client.truststore.type": "jks"
      ssl_server:
        "ssl.server.keystore.location": "/etc/hadoop/conf/keystore"
        "ssl.server.keystore.password": "ryba123"
        "ssl.server.keystore.type": "jks"
        "ssl.server.keystore.keypassword": "ryba123"
        "ssl.server.truststore.location": "/etc/hadoop/conf/truststore"
        "ssl.server.truststore.password": "ryba123"
        "ssl.server.truststore.type": "jks"
    httpd:
      user:
        uid: 2416
        gid: 2416
      group:
        gid: 2416
    xasecure:
      group:
        gid: 2417
      user:
        uid: 2417
        gid: 2417
    proxy:
      system: false
      system_file: "/etc/profile.d/phyla_proxy.sh"
      host: null
      port: null
      username: null
      password: null
      secure: null
      http_proxy: null
      https_proxy: null
      http_proxy_no_auth: null
      https_proxy_no_auth: null
    curl:
      check: false
      config:
        noproxy: "localhost,127.0.0.1,.ryba"
        proxy: null
      merge: true
      users: true
      proxy: true
      check_match: {}
    profile:
      "proxy.sh": ""
    ntp:
      servers: [
        "master3.ryba"
      ]
      fudge: 14
      lag: 2000
    hdp:
      hue_smtp_host: ""
    ambari: {}
    ip: "10.10.10.17"
    modules: [
      "masson/core/reload"
      "masson/core/fstab"
      "masson/core/network"
      "masson/core/network_check"
      "masson/core/users"
      "masson/core/ssh"
      "masson/core/ntp"
      "masson/core/proxy"
      "masson/core/yum"
      "masson/core/security"
      "masson/core/iptables"
      "masson/core/krb5_client"
      "masson/core/sssd"
      "ryba/hadoop/hdfs_dn"
      "ryba/hadoop/yarn_nm"
      "ryba/hadoop/mapred_client"
      "ryba/flume"
      "ryba/phoenix/regionserver"
      "ryba/hbase/regionserver"
    ]
    host: "worker2.ryba"
    shortname: "worker2"
    metrics_sinks:
      file:
        class: "org.apache.hadoop.metrics2.sink.FileSink"
        filename: "metrics.out"
      ganglia:
        class: "org.apache.hadoop.metrics2.sink.ganglia.GangliaSink31"
        period: "10"
        supportparse: "true"
        slope: "jvm.metrics.gcCount=zero,jvm.metrics.memHeapUsedM=both"
        dmax: "jvm.metrics.threadsBlocked=70,jvm.metrics.memHeapUsedM=40"
      graphite:
        class: "org.apache.hadoop.metrics2.sink.GraphiteSink"
        period: "10"
    hostname: "worker2.ryba"
    groups: {}
    fstab:
      enabled: false
      exhaustive: false
      volumes: {}