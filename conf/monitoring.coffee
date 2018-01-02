# 
module.exports =
  clusters:
    'vagrant-monitoring': services:
      'masson/core/system':
        affinity: type: 'tags', values: 'monit-environment': 'dev-monitoring'
        options:
          selinux: false
          limits: {}
          users:
            ryba: {}
      'masson/core/yum':
        affinity: type: 'tags', values: 'monit-environment': 'dev-monitoring'
        options:
          update: true
          packages:
            'tree': true, 'git': true, 'htop': false, 'vim': true,
            'bash-completion': true, 'unzip': true,
            'net-tools': true # Install netstat
            # 'bind-utils': true # Install dig
      'masson/core/ssl':
        affinity: type: 'tags', values: 'monit-environment': 'dev-monitoring'
        options:
          cacert:
            source: "#{__dirname}/certs/ca.cert.pem"
            local: true
          truststore:
            password: 'Truststore123-'
          keystore:
            password: 'Keystore123-'
            keypass: 'Keystore123-'
      'masson/core/iptables':
        affinity: type: 'tags', values: 'monit-environment': 'dev-monitoring'
        options:
          action: 'stop'
          startup: false
          redirect_log: true
          rules: [
            # { chain: 'INPUT', jump: 'ACCEPT', source: "10.10.10.0/24", comment: 'Local Network' }
          ]
      'masson/core/krb5_client':
        affinity: type: 'tags', values: 'monit-environment': 'dev-monitoring'
        options:
          admin:
            'HADOOP.RYBA':
              kadmin_principal: 'admin/admin@HADOOP.RYBA'
              kadmin_password: 'test'
              database_module: 'hadoop_ryba_db'
              kdc_master_key: 'test'
              admin_server: ['master01.metal.ryba']
              kpasswd_server: 'master01.metal.ryba'
              principals: [
                principal: 'krbtgt/HADOOP.RYBA@USERS.RYBA'
                password: 'test'
              ]
          etc_krb5_conf:
            libdefaults: 'default_realm': 'HADOOP.RYBA'
            realms:
              'HADOOP.RYBA':
                kadmin_principal: 'admin/admin@HADOOP.RYBA'
                kadmin_password: 'test'
                database_module: 'hadoop_ryba_db'
                kdc_master_key: 'test'
                principals: [
                  principal: 'krbtgt/HADOOP.RYBA@USERS.RYBA'
                  password: 'test'
                ]
                kdc: ['master01.metal.ryba']
                admin_server: ['master01.metal.ryba']
                kpasswd_server: 'master01.metal.ryba'
      'masson/commons/git':
        affinity: type: 'tags', values: 'monit-environment': 'dev-monitoring'
        options:
          users:
            'ryba': config:
              "user": { "name": 'Ryba User', email: "ryba@ryba.io" }
      'masson/commons/docker':
        affinity: type: 'tags', values: 'monit-environment': 'dev-monitoring'
        options: other_args:
          'insecure-registry': 'bakalian.ryba:5000'
        # config: docker: other_args:
        #   'insecure-registry': 'bakalian.ryba:5000'
      'masson/commons/httpd':
        affinity: type: 'tags', values: 'monit-environment': 'dev-monitoring'
      ## Monitoring
      'ryba/commons/monitoring':
        affinity: type: 'tags', values: 'monit-environment': 'dev-monitoring'
        options:
          credentials:
            knox_user:
              username: 'shinken'
              password: 'Ryba4Shinken'
            sql_user:
              username: 'root'
              password: 'Maria123-'
            swarm_user: enabled: false
          clusters:
            'vagrant':
              realm: 'dev'
              config: require './config'
              # nodes: require '../../ryba-env-metal/env-metal.coffee'
          realms:
            All: members: ['dev']
            'dev': members: [ 'vagrant']
          contactgroups:
            admins: alias: 'Shinken Administrators'
            'SMS-contacts': alias: 'Shinken Users for SMS'
          contacts:
            admin:
              email: 'lucas.bakalian@gmail.com'
              register: '0'
              use: 'admin-contact'
            patrol:
              email: 'patrol@shinken'
              contactgroups: ['patrol']
              host_notification_options: 'd,r'
              host_notification_commands: 'notify-host-to-syslog'
              service_notification_options: 'c,r'
              service_notification_commands: 'notify-service-to-syslog'
              is_admin: '0'
              can_submit_commands: '0'
            guest:
              password: 'guest'
              alias: 'Guest'
              email: 'guest@shinken'
              use: 'admin-contact'            
              # use: 'readonly-contact'
            # Our users
            lucasbak:
              email: 'lucas.bakalian@gmail.com'
              use: 'admin-contact'
            lucasbak1:
              email: 'lucas.bakalian@gmail.com'
              use: 'readonly-contact'
            'SMS-contact':
              use: 'generic-contact'
              contactgroups: 'SMS-contacts'
              host_notification_options: 'd,r'
              host_notification_period: 'office'
              host_notification_commands: 'notify-host-by-sms'
              service_notification_options: 'c,r'
              service_notification_period: 'office'
              service_notification_commands: 'notify-service-by-sms'
              register: '0'
          commands:
            'notify-host-to-syslog': '/var/lib/shinken/print_loglvl.sh "$HOSTNAME$" "$HOSTSTATEID$" "$HOSTGROUPNAMES$" "$SERVICEGROUPNAMES$" "$SERVICEDESC$" "$TIMET$" "$HOSTSTATE$" "$HOSTOUTPUT$" "$LONGHOSTOUTPUT$" "$HOSTNOTES$"'
            'notify-service-to-syslog': '/var/lib/shinken/print_loglvl.sh "$HOSTNAME$" "$SERVICESTATEID$" "$HOSTGROUPNAMES$" "$SERVICEGROUPNAMES$" "$SERVICEDESC$" "$TIMET$" "$SERVICESTATE$" "$SERVICEOUTPUT$" "$LONGSERVICEOUTPUT$" "$HOSTNOTES$"'
            'service-start': '$DOCKER_EXEC$ sudo ./ssh_service.sh $HOSTNAME$ $SERVICESTATE$ $SERVICEATTEMPfT$ start $ARG1$'
          hosts:
            'generic-host':
              contactgroups: ['admins', 'readonly']
              escalations: ['to_mail','to_SMS', 'to_patrol']
          escalations:
            to_patrol:
              contactgroups: ['patrol']
              first_notification_time: '120'
              last_notification_time: '235'
              notification_interval: '120'
            to_mail:
              contactgroups: ['admins']
              first_notification_time: '0'
              last_notification_time: '115'
              notification_interval: '120'
            to_SMS:
              contactgroups: ['SMS-contacts']
              first_notification_time: '0'
              last_notification_time: '115'
              notification_interval: '120'
          services:
            'generic-service':
              flap_detection_enabled: '1'
              escalations: ['to_mail', 'to_SMS']
            'unit-service':
              escalations: ['to_mail', 'to_SMS', 'to_patrol']
              check_interval: '120'
              retry_interval: '30'
            'bp-service': notification_options: 'n' # Disable Business Rules services notifications
            'process-service':
              event_handler_enabled: '1'
              event_handler: 'service-start!$_SERVICEPROCESS_NAME$'
            'Knox - HBase Write':
              check_command: "check_hbase_write!8443!shinken:test!cf1!-S"
      ## Shinken
      'ryba/shinken/commons':
        affinity: type: 'tags', values: 'monit-environment': 'dev-monitoring'
        options:
          config:
            hard_ssl_name_check: '0'
      'ryba/shinken/arbiter':
        affinity: type: 'tags', values: 'monit-name': 'master01'
        options:
          config: 'hard_ssl_name_check': 0
      'ryba/shinken/broker':
        affinity: type: 'tags', values: 'monit-role': 'monit-master'
        options: 
          config: 'hard_ssl_name_check': 0
          modules:
            'livestatus':
              version: 'master'
              type: 'livestatus'
              config:
                host: '*'
                port: '50000'
            'webui2':
              config: uri:  'mongodb://localhost/'
              python_modules:
                #run yum install python-devel openldap-devel
                'python-ldap':
                  version: '2.4.41'
                  url: 'https://pypi.python.org/packages/13/09/717793422e2e86d3d6beb48f9532d4add36a75a7b655096d7fe672f418fd/python-ldap-2.4.41.tar.gz#md5=18db2d009150ec1864710fea3ed76173'
              modules:
                'auth-active-directory':
                  version: 'master'
                  type: 'ad_webui'
                  config:
                    ldap_uri: 'ldaps://master02.metal.ryba:636'
                    username: 'cn=ldapadm,dc=ryba'
                    password: 'test'
                    basedn: 'ou=users,dc=ryba'
                    mode: 'openldap'
            # python_modules:
            #   'python-ldap':
            #     version: '2.4.41'
            #     url: ''
      'ryba/shinken/poller':
        affinity: type: 'tags', values: 'monit-environment': 'dev-monitoring'
        options:
          config: 'hard_ssl_name_check': 0
          public_key: require('./ssh')['ssh'].public_key
          private_key: require('./ssh')['ssh'].private_key
          cache_dir: "#{__dirname}/../cache"
      'ryba/shinken/reactionner':
        affinity: type: 'tags', values: 'monit-environment': 'dev-monitoring'
        options: 
          config: 'hard_ssl_name_check': 0
      'ryba/shinken/receiver':
        affinity: type: 'tags', values: 'monit-environment': 'dev-monitoring'
        options: 
          config: 'hard_ssl_name_check': 0
      'ryba/shinken/scheduler':
        affinity: type: 'tags', values: 'monit-environment': 'dev-monitoring'
        options: 
          config: 'hard_ssl_name_check': 0
      'ryba/nagvis':
        affinity: type: 'tags', values: 'monit-role': 'monit-master'
      # "#{__dirname}/../lib/nagvis":
      #   affinity: type: 'tags', values: 'monit-name': 'master01'
      # "#{__dirname}/../lib/shinken":
      #   affinity: type: 'tags', values: 'monit-role': 'monit-master'
