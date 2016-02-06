
module.exports =
  mecano:
    cache_dir: "#{__dirname}/../resources/cache"
    log_serializer: true
  log: archive: true
  security:
    selinux: false
    limits: {}
  network:
    hosts_auto: true
    hosts:
      '127.0.0.1': 'localhost localhost.localdomain localhost4 localhost4.localdomain4'
      '10.10.10.10': 'repos.ryba ryba'
    resolv: """
      search ryba
      nameserver 10.10.10.13
      nameserver 10.0.2.3
      """
  iptables:
    action: 'stop'
    startup: false
    log: true
    rules: [
      # { chain: 'INPUT', jump: 'ACCEPT', source: "10.10.10.0/24", comment: 'Local Network' }
    ]
  bind_server:
    zones: [
      "#{__dirname}/zones/ryba"
      "#{__dirname}/zones/10.10.10.in-addr.arpa"
    ]
  ssh:
    banner:
      destination: '/etc/banner'
      content: "Welcome to Ryba Monitoring!"
    sshd_config:
      PermitRootLogin: 'without-password'
  users:
    'root':
      authorized_keys:  []
  yum:
    packages: "tree": true, "git": true, "htop": true, "vim": true
  krb5:
    etc_krb5_conf:
      libdefaults:
        default_realm: 'HADOOP.RYBA'
      realms:
        'HADOOP.RYBA':
          kdc: 'master1.ryba'
          default_domain: 'hadoop.ryba'
        'USERS.RYBA':
          kdc: 'master3.ryba'
          default_domain: 'users.ryba'
      domain_realm:
        # '.ryba': 'HADOOP.RYBA'
        'ryba': 'HADOOP.RYBA'
    kdc_conf:
      realms: {}
  sssd:
    # test_user: 'ryba'
    force_check: false
    certificates: [
      "#{__dirname}/certs/cacert.pem"
    ]
    config:
      'domain/hadoop':
        'debug_level': '1'
        'cache_credentials' : 'True'
        'ldap_search_base' : 'ou=users,dc=ryba'
        'ldap_group_search_base' : 'ou=groups,dc=ryba'
        'id_provider' : 'ldap'
        'auth_provider' : 'ldap'
        'chpass_provider' : 'ldap'
        'ldap_uri' : 'ldaps://master3.ryba:636'
        'ldap_tls_cacertdir' : '/etc/openldap/cacerts'
        # 'ldap_default_bind_dn' : 'cn=nssproxy,dc=ryba'
        'ldap_default_bind_dn' : 'cn=Manager,dc=ryba'
        'ldap_default_authtok' : 'test'
        'ldap_id_use_start_tls' : 'True'
      'domain/users':
        'debug_level': '1'
        'cache_credentials' : 'True'
        'ldap_search_base' : 'ou=users,dc=ryba'
        'ldap_group_search_base' : 'ou=groups,dc=ryba'
        'id_provider' : 'ldap'
        'auth_provider' : 'ldap'
        'chpass_provider' : 'ldap'
        'ldap_uri' : 'ldaps://master3.ryba:636'
        'ldap_tls_cacertdir' : '/etc/openldap/cacerts'
        # 'ldap_default_bind_dn' : 'cn=nssproxy,dc=ryba'
        'ldap_default_bind_dn' : 'cn=Manager,dc=ryba'
        'ldap_default_authtok' : 'test'
        'ldap_id_use_start_tls' : 'False'
      'sssd':
        'domains' : 'hadoop,users'
  java: {}
  ryba:
    clean_logs: true
    security: 'kerberos'
    realm: 'HADOOP.RYBA'
    ssl:
      'cacert': "#{__dirname}/certs/cacert.pem"
    #   'cert': "#{__dirname}/certs/hadoop_cert.pem"
    #   'key': "#{__dirname}/certs/hadoop_key.pem"
    