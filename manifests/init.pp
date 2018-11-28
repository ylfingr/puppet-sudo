# @summary installs sudo and loads the configuration
#
# @param package_name [String]
#  The name of the package to install
#  Default: sudo
#
# @param package_ensure [String]
#  Pin the package to install to a specific version
#  Default: latest
#
# @param init [Boolean]
#  Install and configure sudo?
#  Default: true
#
# @example Hiera configuration
#  sudo::package_name: sudo
#  sudo::package_ensure: latest
#  suod::init: true


class sudo (
  String $package_name      = 'sudo',
  String $package_ensure    = 'latest',
  Boolean $init             = true,
)
{
  if $init {
    package { $package_name:
      ensure => $package_ensure,
    }

    contain ::sudo::config
  }
}
