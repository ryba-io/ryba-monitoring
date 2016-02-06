
module.exports =
  servers:
    'monit1.ryba':
      ip: '10.10.10.20'
      modules: [
        'masson/core/reload'
        './lib/iptables'
        # Commons
        'masson/core/network'
        'masson/core/network_check'
        'masson/core/users'
        'masson/core/profile'
        'masson/core/ssh'
        #'masson/core/ntp'
        #'masson/core/proxy'
        #'masson/core/yum'
        # Security
        #'masson/core/security'
        #'masson/core/iptables'
        #'masson/core/krb5_client'
        'ryba/mongodb'
        'ryba/nagvis'
        'ryba/shinken/scheduler'
        'ryba/shinken/poller'
        'ryba/shinken/receiver'
        'ryba/shinken/reactionner'
        'ryba/shinken/broker'
        'ryba/shinken/arbiter'
        'masson/commons/anaconda'
      ]
