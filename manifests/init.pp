class winstig {
# # Open a command prompt with elevated privileges.
# # • Take ownership of the file with the command “takeown /f c:\windows\inf\sceregvl.inf”.

include winstig::pre

exec { 'Take ownership':
  command   => 'c:\\Windows\\System32\\takeown.exe /f c:\\windows\\inf\\sceregvl.inf',
}
# # # • Add Full permissions with the command “icacls c:\windows\inf\sceregvl.inf /grant username:f” where “username” is the administrator account.
exec { 'Add Full permissions':
  command   => 'c:\\Windows\\System32\\icacls c:\\windows\\inf\\sceregvl.inf /grant vagrant:f',
  provider  => powershell,
}
# # # • Rename the sceregvl.inf file in the %WinDir%\inf directory.
exec { 'Rename':
  command   => 'Rename-Item c:\\windows\\inf\\sceregvl.inf c:\\windows\\inf\\sceregvl.bak',
  provider  => powershell,
}
# • Copy the updated sceregvl.inf file to the %WinDir%\inf directory.
  file { 'c:\\windows\\inf\\sceregvl.inf':
    source => 'puppet:///modules/winstig/sceregvl.inf',
  }
  # • Re-register scecli.dll by executing “regsvr32 scecli.dll” in the command prompt with elevated privileges.
  exec { 'Re-register scecli.dll':
    command   =>'regsvr32 scecli.dll',
    provider  => powershell,
  }
  file { 'c:\\winstig':
    ensure => 'directory',
  }
  file { 'c:\\winstig\\lgpo.exe':
    ensure => 'present',
    source => 'puppet:///modules/winstig/lgpo.exe',
  }
  file { 'c:\\winstig\\backup.pol':
    ensure => 'present',
    source => 'puppet:///modules/winstig/backup.pol',
  }

  exec { 'Convert Policy':
    command => 'c:\\winstig\\lgpo.exe /r c:\\winstig\\backup.pol /w c:\\winstig\\registry.pol',
  }

  exec { 'Install Policy':
    command => 'c:\\winstig\\lgpo.exe /m c:\\winstig\\registry.pol',
  }
  include winstig::auditpol
  include winstig::policy


}
