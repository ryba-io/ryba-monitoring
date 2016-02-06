
# Install IPTables

    module.exports = []
    module.exports.push 'masson/bootstrap/'

## Install

    module.exports.push header: 'IPTables # Centos 7 Fix', handler: ->
      @execute
        cmd: """
        systemctl stop firewalld
        systemctl mask firewalld
        yum install -y iptables-services
        """