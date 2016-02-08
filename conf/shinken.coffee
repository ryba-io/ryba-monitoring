
module.exports =
  ryba:
    shinken:
      exports_dir: "#{__dirname}/../resources/shinken"
      config:
        realms:
          All: members: ['pacy', 'noe']
          pacy: members: [ 'hadoop2']
          noe: members: [ 'hadoop1', 'hadoop_re7', 'hadoop_dev']
          hadoop1: {}
          hadoop2: {}
          hadoop_re7: {}
          hadoop_dev: {}
        contactgroups:
          admins:
            alias: 'Shinken Administrators'
            members: ['shinken']#, 'shinkenSMS']
        contacts:
          #guest:
          #  password: 'guest4hp'
          #  alias: 'HP Guest'
          #  email: ''
          shinken:
            email: 'pierre-externe.sauvage@edf.fr'
            password: 'shinken123'
            is_admin: '1'
            can_submit_commands: '1'
          # shinkenSMS:
          #   alias: 'Admin SMS'
          #   password: 'shinken123'
          #   email: '0682463372@smartpush.mailtosms.aw.atos.net'
          #   is_admin: '1'
          #   can_submit_commands: '1'
          #   service_notification_commands: 'notify-service-by-sms'
          #   host_notification_commands: 'notify-host-by-sms'
        commands:
          'notify-host-by-sms': '/usr/bin/printf "%b" "Shinken Notification\\n\\nType: $NOTIFICATIONTYPE$\\nHost: $HOSTNAME$\\nState: $HOSTSTATE$\\nAddress: $HOSTADDRESS$\\nDate: $SHORTDATETIME$\\nInfo: $HOSTOUTPUT$" | mailx -r "dsp-cspito-hadoop@edf.fr" -S smtp="mailhost.der.edf.fr:25" -s "host alert" $CONTACTEMAIL$'
          'notify-service-by-sms': '/usr/bin/printf "%b" "Shinken Notification\\n\\nNotification Type: $NOTIFICATIONTYPE$\\n\\nService: $SERVICEDESC$\\nHost:$HOSTALIAS$\\nAddress: $HOSTADDRESS$\\nState: $SERVICESTATE$\\nDate: $SHORTDATETIME$\\nInfo : $SERVICEOUTPUT$" | mailx -r "dsp-cspito-hadoop@edf.fr" -S smtp="mailhost.der.edf.fr:25" -s "service alert" $CONTACTEMAIL$'
      broker:
        modules:
          webui2:
            version: 'develop'
            modules:
              'ui-graphite':
                version: '2.1.1'
                config: uri: 'http://noeyy6z1.noe.edf.fr:3080/graphite/'
          'mongo-logs':
            archive: 'mod-mongo-logs-master'
