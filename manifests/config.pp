# @summary Module to manage /etc/sudoers
#
#
# @param package_name [String]
#  The name of the package. Required here for dependencies
#  Default: $sudo::package_name
#
# @param user_alias [Hash]
#  Contains specifications for User_Alias
#  Default: {}
#
# @example Configuration for sudo::config::user_alias
#  [yaml
#  sudo::config::user_alias:
#    &ua_aliasname USER_ALIAS_NAME:
#    - username
#    - '%groupname'
#
#  [sudoers]
#  User_Alias USER_ALIAS_NAME = username, %groupname
#
# @param runas_alias [Hash]
#  Contains specifications for Runas_Alias
#  Default: {}
#
# @example Configuration for sudo::config::runas_alias
#  [yaml]
#  sudo::config::runas_alias:
#    &ra_runas RUNAS_ALIAS:
#    - alias_1
#    - alias_2
#
#  [sudoers]
#  Runas_Alias RUNAS_ALIAS = alias_1, alias_2
#
# @param host_alias [Hash]
#   Contains specifications for Host_Alias
#   Default: {}
#
# @example Configuration for sudo::config::host_alias
#  [yaml]
#  sudo::config::host_alias:
#    &ha_localhost LOCALHOST:
#    - '%{::hostname}'
#    - '%{::fqdn}'
#
#  [sudoers]
#  Host_Alias LOCALHOST = <hostname>, <fqdn>
#
# @param cmnd_alias [Hash]
#   Contains specifications for Cmnd_Alias
#   Default: {}
#
# @example Configuration for sudo::config::cmnd_alias
#  [yaml]
#  sudo::config::cmnd_alias:
#  &ca_killcmnd KILL:
#    /bin/kill:
#    /usr/bin/kill:
#    /usr/bin/killall:
#  &ca_svccmnd SERVICE:
#    /sbin/service <service> stop:
#    /sbin/service <serivce> start:
#  &ca_svccmnd_dgst SERVICE_WITH_DIGEST:
#    /sbin/service <service> stop: &digest_service
#      sha384: dyUwsFE+bqKFst+C+vjdQ2eY14swV3SPLTSr71l1HhLUU4gBVQCRtY4rJZ5Se6uG
#
#  [sudoers]
#  Cmnd_Alias KILL = /bin/kill, /usr/bin/kill, /usr/bin/killall
#  Cmnd_Alias SERVICE = /sbin/service <service> stop, /sbin/service <service> start
#  Cmnd_Alias SERVICE_WITH_DIGEST = sha384:dyUwsFE+bqKFst+C+vjdQ2eY14swV3SPLTSr71l1HhLUU4gBVQCRtY4rJZ5Se6uG /sbin/service <service> stop
#
# @param defaults [Hash]
#  Contains specifications for Defaults
#  Default: {}
#
# @example Configuration for sudo::config::defaults
#  [yaml]
#  sudo::config::defaults:
#    env_delete+:
#    - LD_LIBRARY_PATH
#    - LD_PRELOAD
#    env_keep+:
#    - LANG
#    - LANGUAGE
#    - LC_ALL
#    env_reset: true
#    insults: true
#    loglinelen: 0
#    passwd_timeout: 3
#    timestamp_timeout: 1
#    listpw: never
#    logfile: /var/log/sudo
#    user:
#      ALL:
#        noexec: true
#      root:
#        noexec: false
#        insults: never
#    runas:
#      root:
#        noexec: true
#    cmnd:
#      CMND_ALIAS:
#        noexec: false
#
#  [sudoers] -- line length defined by *slice_size*
#  Defaults env_delete+="LD_LIBRARY_PATH LD_PRELOAD"
#  Defaults env_keep+="LANG LANGUAGE LC_ALL"
#  Defaults env_reset,insults,loglinelen=0,passwd_timeout=3,timestamp_timeout=1
#  Defaults listpw,logfile=/var/log/sudo
#  Defaults:ALL noexec
#  Defaults:root !noexec,!insults
#  Defaults>root noexec
#  Defaults!CMND_ALIAS noexec
#
# @param rules [Hash]
#  Defines the rules
#  Default: {}
#
# @example Configuration for sudo::config::rules
#  [yaml]
#  sudo::config::rules:
#    USERALIAS:
#     CMND_ALIAS:
#       runas:
#         user:
#           - root
#         group:
#           - admin
#       tags:
#         - EXEC
#         - NOPASSWD
#         - LOG_OUTPUT
#       hosts:
#         - LOCALHOST
#
#  [sudoers]
#  USERALIAS LOCALHOST=(root : admin) EXEC:NOPASSWD:LOG_OUTPUT CMND_ALIAS
#
# @param sudoers [String]
#  The path to the sudoers configuration file
#  Default: /etc/sudoers
#
# @param sudoers_d [String]
#  The path to the sudoers.d directory
#  Default: /etc/sudoers.d
#
# @param config [String]
#  The path to the configuration file sudo.conf
#  Default: /etc/sudo.conf
#
# @param ldap_config [String]
#  The path to the configuration file sudo-ldap.conf
#  Default: /etc/sudo-ldap.conf
#
# @param ldap_content [String]
#  The path to the template file for ldap_config
#  Default: sudo/sudo-ldap.conf.epp
#
# @param conf_content [String]
#  The path to the template file for config
#  Default: sudo/sudo.conf.epp
#
# @param sudoers_content [String]
#  The path to the template file for sudoers
#  Default: sudo/sudoers.epp
#
# @param slice_size [Integer]
#  How many items per line should there be?
#  Default: 5
#
# @param merge_useralias [Boolean]
#  Merge configuration(s) for sudo::config::user_alias
#  Default: false
#
# @param merge_runasalias [Boolean]
#  Merge configuration(s) for sudo::config::runas_alias
#  Default: false
#
# @param merge_hostalias [Boolean]
#  Merge configuration(s) for sudo::config::host_alias
#  Default: false
#
# @param merge_cmndalias [Boolean]
#  Merge configuration(s) for sudo::config::cmnd_alias
#  Default: false
#
# @param merge_defaults [Boolean]
#  Merge configuration(s) for sudo::config::defaults
#  Default: false
#
# @param merge_rules [Boolean]
#  Merge configuration(s) for sudo::config::rules
#  Default: false
#
# @param manage [Boolean]
#  Manage sudoers?
#  Default: true

class sudo::config (
  Hash $user_alias          = {},
  Hash $runas_alias         = {},
  Hash $host_alias          = {},
  Hash $cmnd_alias          = {},
  Hash $defaults            = {},
  Hash $rules               = {},
  Hash $hiera               = {},

  String $package_name      = $sudo::package_name,
  String $sudoers           = '/etc/sudoers',
  String $sudoers_d         = '/etc/sudoers.d',
  String $config            = '/etc/sudo.conf',
  String $ldap_config       = '/etc/sudo-ldap.conf',
  String $conf_content      = 'sudo/sudo.conf.epp',
  String $ldap_content      = 'sudo/sudo-ldap.conf.epp',
  String $sudoers_content   = 'sudo/sudoers.epp',

  Integer $slice_size       = 5,
  Boolean $merge_useralias  = false,
  Boolean $merge_runasalias = false,
  Boolean $merge_hostalias  = false,
  Boolean $merge_cmndalias  = false,
  Boolean $merge_defaults   = false,
  Boolean $merge_rules      = false,

  Boolean $manage           = true,
  ){

  if $manage {
    if $merge_useralias {
      $__user_alias = lookup({
        'name' => 'sudo::config::user_alias',
        'value_type' => Hash,
        'merge' => {
          'strategy' => 'deep',
          'knockout_prefix' => '--',
        },
        'default_value' => $user_alias,
        })
    }
    else {
      $__user_alias = $user_alias
    }
    $__user_alias.each |$alias, $list| {
      # ensure alias name is all upper case
      $_alias = upcase($alias)

      # ensure alias name is valid. see sudoers(5)
      validate_legacy("Optional[String]", "validate_re", $_alias, '[A-Z]++(?:[A-Z0-9_]++)?')
    }
    $user_alias_real = $__user_alias

    if $merge_runasalias {
      $__runas_alias = lookup({
        'name' => 'sudo::config::runas_alias',
        'value_type' => Hash,
        'merge' => {
          'strategy' => 'deep',
          'knockout_prefix' => '--',
        },
        'default_value' => $runas_alias,
        })
    }
    else {
      $__runas_alias = $runas_alias
    }
    $__runas_alias.each |$alias, $list| {
      # ensure alias name is all upper case
      $_alias = upcase($alias)

      # ensure alias name is valid. see sudoers(5)
      validate_legacy("Optional[String]", "validate_re", $_alias, '[A-Z]++(?:[A-Z0-9_]++)?')
    }
    $runas_alias_real = $__runas_alias

    if $merge_hostalias {
      $__host_alias = lookup({
        'name' => 'sudo::config::host_alias',
        'value_type' => Hash,
        'merge' => {
          'strategy' => 'deep',
          'knockout_prefix' => '--',
        },
        'default_value' => $host_alias,
        })
    }
    else {
      $__host_alias = $host_alias
    }
    $__host_alias.each |$alias, $list| {
      # ensure alias name is all upper case
      $_alias = upcase($alias)

      # ensure alias name is valid. see sudoers(5)
      validate_legacy("Optional[String]", "validate_re", $_alias, '[A-Z]++(?:[A-Z0-9_]++)?')
    }
    $host_alias_real = $__host_alias

    if $merge_cmndalias {
      $__cmnd_alias = lookup({
        'name' => 'sudo::config::cmnd_alias',
        'value_type' => Hash,
        'merge' => {
          'strategy' => 'deep',
          'knockout_prefix' => '--',
        },
        'default_value' => $cmnd_alias,
        })
    }
    else {
      $__cmnd_alias = $cmnd_alias
    }
    $__cmnd_alias_real = $__cmnd_alias.map |$item| {
      # ensure alias name is all upper case
      $_alias = upcase($item[0])

      # ensure alias name is valid. see sudoers(5)
      validate_legacy("Optional[String]", "validate_re", $_alias, '[A-Z]++(?:[A-Z0-9_]++)?')

      $c = $item[1].map |$cmnd, $digest| {
        if $digest =~ Hash[String, Data, 1] {
          join([join_keys_to_values($digest, ':'), $cmnd], ' ')
        }
        else {
          $cmnd
        }
      }
      $x = {$_alias => $c}; $x
    }
    $cmnd_alias_real = $__cmnd_alias_real

    if $merge_defaults {
      $__defaults = lookup({
        'name' => 'sudo::config::defaults',
        'value_type' => Hash,
        'merge' => {
          'strategy' => 'deep',
          'knockout_prefix' => '--',
        },
        'default_value' => $defaults,
        })
    }
    else {
      $__defaults = $defaults
    }

    # filter out defaults by type to simplify logic of generating the content
    # for the lines in /etc/sudoers
    $defaults_boolean = $__defaults.filter |$item| { $item[1] =~ Variant[Boolean] }
    $defaults_numeric = $__defaults.filter |$item| { $item[1] =~ Variant[Integer, Float] }
    $defaults_string  = $__defaults.filter |$item| { $item[1] =~ Variant[String] }
    $defaults_seq     = $__defaults.filter |$item| { $item[1] =~ Variant[Array] }
    $defaults_map     = $__defaults.filter |$item| { $item[1] =~ Variant[Hash] }

    $defbool_real = $defaults_boolean.map |$item| {
      if $item[1] {
        $item[0]
      }
      else {
        join(['!', $item[0]], '')
      }
    }

    $defnum_real = $defaults_numeric.map |$item| {
      join($item, '=')
    }

    $defstr_real = $defaults_string.map |$item| {
      join($item, '=')
    }

    # no transformation required
    $defseq_real = $defaults_seq

    $defmap_real = $defaults_map.reduce({}) |$memo0, $item| {
      $result = $item[1].reduce({}) |$memo1, $i| {
        $alias = $i[0]
        $config = $i[1]
        $c = $config.map |$k, $v| {
          if $v =~ Boolean {
            if $v {
              $k
            }
            else {
              join(['!', $k], '')
            }
          }
          else {
            join([$k, $v], '=')
          }
        }

        case $item[0] {
          'runas': { $deftype = join(['>', $alias], '') }
          'cmnd' : { $deftype = join(['!', $alias], '') }
          'user' : { $deftype = join([':', $alias], '') }
          'host' : { $deftype = join(['@', $alias], '') }
          default: { fail("unknown '${item[0]}'") }
        }
        merge($memo1, {$deftype => $c})
      }
      merge($memo0, $result)
    }
    #notice("defmap_real: <$defmap_real>")

    if $merge_rules {
      $__rules = lookup({
        'name' => 'sudo::config::rules',
        'value_type' => Hash,
        'merge' => {
          'strategy' => 'deep',
          'knockout_prefix' => '--',
        },
        'default_value' => $rules,
        })
    }
    else {
      $__rules = $rules
    }

    # sudoers(5)
    # not supported yet:
    # Option_Spec ::= (SELinux_Spec | Date_Spec | Timemout_Spec)
    $__rules_real = $__rules.reduce({}) |$memo0, $entries| {
      # entries[0] ::= user_alias :: String
      # entries[1] ::= user_alias :: Hash
      $ua = $entries[0]

      $z = $entries[1].map |$rules_map| {
        $y = $rules_map.reduce({}) |$memo2, $rlmap| {
          # rlmap[0] ::= cmnd_alias :: String
          # rlmap[1] ::= cmnd_alias :: Hash
          if $rlmap[1] =~ Hash[String, Data, 1] {
            $dm = merge({'tags' => ['DEFAULT'], 'hosts' => ['LOCALHOST'], 'runas' => {}}, $rlmap[1])

            $tags   = empty($dm['tags']) ? {
              true  => [],
              false => [$dm['tags'], ''],
            }

            if $dm['runas'] =~ Hash[String, Data, 2, 2] {
              $p = [$dm['hosts'].join(', '), '=', '(', [$dm['runas']['user'].join(', '), $dm['runas']['group'].join(', ')].join(' : '), ')', $tags.join(':')].join(' ')
            }
            elsif $dm['runas'] =~ Hash[String, Data, 1, 1] {
              if has_key($dm['runas'], 'user') {
                $p = [$dm['hosts'].join(', '), '=', '(', $dm['runas']['user'].join(', '), ')', $tags.join(':')].join(' ')
              }
              elsif has_key($rm['runas'], 'group') {
                $p = [$dm['hosts'].join(', '), '=', '(', ':', $dm['runas']['group'].join(', '), ')', $tags.join(':')].join(' ')
              }
              else {
                $p = "runas: syntax error"
              }
            }
            else {
              $p = [$dm['hosts'].join(', '), '=', '(', ')', $tags.join(':')].join(' ')
            }
            $merged = {$rlmap[0] => $p}
            notice("merged: <$merged>")
          }
          else {
            $p = ['LOCALHOST', '=', '(', ')', ['PASSWD', 'LOG_OUTPUT'].join(':')].join(' ')
            $merged = {$rlmap[0] => $p}
          }
          merge($memo2, $merged)
        }
        $y
      }
      $v = merge($memo0, {$ua => $z})
      notice("v: <$v>")
    $v
    }
    $rules_real = $__rules_real

    file { $sudoers:
      ensure       => file,
      mode         => '0440',
      owner        => 'root',
      group        => 'root',
      content      => epp($sudoers_content),
      require      => Package[$package_name],
      validate_cmd => '/usr/sbin/visudo -c -f %',
    }

    # save .sudoers for validation if something goes wrong
    $__sudoers_check = [dirname($sudoers), ['.', basename($sudoers)].join].join('/')
    file { $__sudoers_check:
      mode    => '0400',
      owner   => 'root',
      group   => 'root',
      content => epp($sudoers_content),
      require => Package[$package_name],
    }

    file { $config:
      mode    => '0640',
      content => epp($conf_content),
      require => Package[$package_name],
    }

    file { $ldap_config:
      mode    => '0640',
      content => epp($ldap_content),
      require => Package[$package_name],
    }

    file { $sudoers_d:
      ensure  => 'directory',
      mode    => '0750',
      require => Package[$package_name],
    }
  }
}
