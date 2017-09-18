class winstig::policy {

  local_security_policy { 'Account lockout threshold':
    ensure         => 'present',
    policy_setting => 'LockoutBadCount',
    policy_type    => 'System Access',
    policy_value   => '3',
  }
  local_security_policy { 'Reset account lockout counter after':
    ensure         => 'present',
    policy_setting => 'ResetLockoutCount',
    policy_type    => 'System Access',
    policy_value   => '60',
    tag            => 'V-1098',
  }
  local_security_policy { 'Account lockout duration':
    ensure         => 'present',
    policy_setting => 'LockoutDuration',
    policy_type    => 'System Access',
    policy_value   => '-1',
    tag            => 'V-1099',
  }
  local_security_policy { 'Act as part of the operating system':
    ensure         => 'absent',
    tag            => 'V-1102'
  }
  local_security_policy { 'Accounts: Limit local account use of blank passwords to console logon only':
    ensure         => 'present',
    policy_setting => 'MACHINE\System\CurrentControlSet\Control\Lsa\LimitBlankPasswordUse',
    policy_type    => 'Registry Values',
    policy_value   => '4,1',
  }
  local_security_policy { 'Accounts: Rename administrator account':
    ensure         => 'present',
    policy_setting => 'NewAdministratorName',
    policy_type    => 'System Access',
    policy_value   => '"WsEM88"',
    tag            => 'V-1115',
  }
  local_security_policy { 'Accounts: Rename guest account':
    ensure         => 'present',
    policy_setting => 'NewGuestName',
    policy_type    => 'System Access',
    policy_value   => '"Vc46bT"',
    tag            => 'V-1114',
  }
  local_security_policy { 'Allow log on through Remote Desktop Services':
    ensure         => 'present',
    policy_setting => 'SeRemoteInteractiveLogonRight',
    policy_type    => 'Privilege Rights',
    policy_value   => '*S-1-5-32-544',
  }
  local_security_policy { 'Audit: Audit the access of global system objects':
    ensure         => 'present',
    policy_setting => 'MACHINE\System\CurrentControlSet\Control\Lsa\AuditBaseObjects',
    policy_type    => 'Registry Values',
    policy_value   => '4,0',
  }
  local_security_policy { 'Audit: Audit the use of Backup and Restore privilege':
    ensure         => 'present',
    policy_setting => 'MACHINE\System\CurrentControlSet\Control\Lsa\FullPrivilegeAuditing',
    policy_type    => 'Registry Values',
    policy_value   => '3,0',
  }
  # local_security_policy { 'Audit: Shut down system immediately if unable to log security audits':
  #   ensure         => 'present',
  #   policy_setting => 'MACHINE\System\CurrentControlSet\Control\Lsa\CrashOnAuditFail',
  #   policy_type    => 'Registry Values',
  #   policy_value   => '4,0',
  # }
  local_security_policy { 'Back up files and directories':
    ensure         => 'present',
    policy_setting => 'SeBackupPrivilege',
    policy_type    => 'Privilege Rights',
    policy_value   => '*S-1-5-32-544',
  }
  # local_security_policy { 'Bypass traverse checking':
  #   ensure         => 'present',
  #   policy_setting => 'SeChangeNotifyPrivilege',
  #   policy_type    => 'Privilege Rights',
  #   policy_value   => '*S-1-1-0,*S-1-5-19,*S-1-5-20,*S-1-5-32-544,*S-1-5-32-545,*S-1-5-32-551,*S-1-5-90-0',
  # }
  local_security_policy { 'Change the system time':
    ensure         => 'present',
    policy_setting => 'SeSystemtimePrivilege',
    policy_type    => 'Privilege Rights',
    policy_value   => '*S-1-5-19,*S-1-5-32-544',
  }
  local_security_policy { 'Change the time zone':
    ensure         => 'present',
    policy_setting => 'SeTimeZonePrivilege',
    policy_type    => 'Privilege Rights',
    policy_value   => '*S-1-5-19,*S-1-5-32-544',
  }
  local_security_policy { 'Create a pagefile':
    ensure         => 'present',
    policy_setting => 'SeCreatePagefilePrivilege',
    policy_type    => 'Privilege Rights',
    policy_value   => '*S-1-5-32-544',
  }
  local_security_policy { 'Create a token object':
    ensure         => 'absent',
    # policy_setting => 'SeCreateTokenPrivilege',
    # policy_type    => 'Privilege Rights',
  }
  local_security_policy { 'Create global objects':
    ensure         => 'present',
    policy_setting => 'SeCreateGlobalPrivilege',
    policy_type    => 'Privilege Rights',
    policy_value   => '*S-1-5-19,*S-1-5-20,*S-1-5-32-544,*S-1-5-6',
  }
  local_security_policy { 'Create symbolic links':
    ensure         => 'present',
    policy_setting => 'SeCreateSymbolicLinkPrivilege',
    policy_type    => 'Privilege Rights',
    policy_value   => '*S-1-5-32-544',
  }
  local_security_policy { 'Create permanent shared objects':
    ensure         => 'absent',
    # policy_setting => 'SeCreatePermanentPrivilege',
    # policy_type    => 'Privilege Rights',
  }
  local_security_policy { 'Debug programs':
    ensure         => 'present',
    policy_setting => 'SeDebugPrivilege',
    policy_type    => 'Privilege Rights',
    policy_value   => '*S-1-5-32-544',
  }
  # local_security_policy { 'Devices: Allow undock without having to log on':
  #   ensure         => 'present',
  #   policy_setting => 'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\UndockWithoutLogon',
  #   policy_type    => 'Registry Values',
  #   policy_value   => '4,1',
  # }
  local_security_policy { 'Devices: Prevent users from installing printer drivers':
    ensure         => 'present',
    policy_setting => 'MACHINE\System\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers\AddPrinterDrivers',
    policy_type    => 'Registry Values',
    policy_value   => '4,1',
  }
  local_security_policy { 'Domain member: Digitally encrypt or sign secure channel data (always)':
    ensure         => 'present',
    policy_setting => 'MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\RequireSignOrSeal',
    policy_type    => 'Registry Values',
    policy_value   => '4,1',
  }
  local_security_policy { 'Domain member: Digitally encrypt secure channel data (when possible)':
    ensure         => 'present',
    policy_setting => 'MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\SealSecureChannel',
    policy_type    => 'Registry Values',
    policy_value   => '4,1',
    tag            => 'V-1163',
  }
  local_security_policy { 'Domain member: Digitally sign secure channel data (when possible)':
    ensure         => 'present',
    policy_setting => 'MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\SignSecureChannel',
    policy_type    => 'Registry Values',
    policy_value   => '4,1',
    tag            => 'V-1164',
  }
  local_security_policy { 'Domain member: Disable machine account password changes':
    ensure         => 'present',
    policy_setting => 'MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\DisablePasswordChange',
    policy_type    => 'Registry Values',
    policy_value   => '4,0',
    tag            => 'V-1165',
  }
  local_security_policy { 'Domain member: Maximum machine account password age':
    ensure         => 'present',
    policy_setting => 'MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\MaximumPasswordAge',
    policy_type    => 'Registry Values',
    policy_value   => '4,30',
  }
  local_security_policy { 'Domain member: Require strong (Windows 2000 or later) session key':
    ensure         => 'present',
    policy_setting => 'MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\RequireStrongKey',
    policy_type    => 'Registry Values',
    policy_value   => '4,1',
  }
  # local_security_policy { 'EnableAdminAccount':
  #   ensure         => 'present',
  #   policy_setting => 'EnableAdminAccount',
  #   policy_type    => 'System Access',
  #   policy_value   => '1',
  # }
  local_security_policy { 'EnableGuestAccount':
    ensure         => 'present',
    policy_setting => 'EnableGuestAccount',
    policy_type    => 'System Access',
    policy_value   => '0',
    tag            => 'V-1113'
  }
  local_security_policy { 'Enforce password history':
    ensure         => 'present',
    policy_setting => 'PasswordHistorySize',
    policy_type    => 'System Access',
    policy_value   => '24',
    tag            => 'V-1107',
  }
  local_security_policy { 'Force shutdown from a remote system':
    ensure         => 'present',
    policy_setting => 'SeRemoteShutdownPrivilege',
    policy_type    => 'Privilege Rights',
    policy_value   => '*S-1-5-32-544',
  }
  local_security_policy { 'Generate security audits':
    ensure         => 'present',
    policy_setting => 'SeAuditPrivilege',
    policy_type    => 'Privilege Rights',
    policy_value   => '*S-1-5-19,*S-1-5-20',
  }
  local_security_policy { 'Impersonate a client after authentication':
    ensure         => 'present',
    policy_setting => 'SeImpersonatePrivilege',
    policy_type    => 'Privilege Rights',
    policy_value   => '*S-1-5-19,*S-1-5-20,*S-1-5-32-544,*S-1-5-6',
  }
  # local_security_policy { 'Increase a process working set':
  #   ensure         => 'present',
  #   policy_setting => 'SeIncreaseWorkingSetPrivilege',
  #   policy_type    => 'Privilege Rights',
  #   policy_value   => '*S-1-5-32-545,*S-1-5-90-0',
  # }
  local_security_policy { 'Increase scheduling priority':
    ensure         => 'present',
    policy_setting => 'SeIncreaseBasePriorityPrivilege',
    policy_type    => 'Privilege Rights',
    policy_value   => '*S-1-5-32-544',
  }
  local_security_policy { 'Interactive logon: Do not display last user name':
    ensure         => 'present',
    policy_setting => 'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\DontDisplayLastUserName',
    policy_type    => 'Registry Values',
    policy_value   => '4,1',
  }
  local_security_policy { 'Interactive logon: Do not require CTRL+ALT+DEL':
    ensure         => 'present',
    policy_setting => 'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\DisableCAD',
    policy_type    => 'Registry Values',
    policy_value   => '4,0',
    tag            => 'V-1154',
  }
  local_security_policy { 'Interactive logon: Message text for users attempting to log on':
    ensure         => 'present',
    policy_setting => 'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\LegalNoticeText',
    policy_type    => 'Registry Values',
    policy_value   => '7,You are accessing a
        U.S. Government (USG) Information System (IS) that is provided for
        USG-authorized use only. By using this IS (which includes any device
        attached to this IS), you consent to the following conditions: -The USG
        routinely intercepts and monitors communications on this IS for purposes
        including, but not limited to, penetration testing, COMSEC monitoring,
        network operations and defense, personnel misconduct (PM), law
        enforcement (LE), and counterintelligence (CI) investigations. -At any
        time, the USG may inspect and seize data stored on this IS.
        -Communications using, or data stored on, this IS are not private, are
        subject to routine monitoring, interception, and search, and may be
        disclosed or used for any USG-authorized purpose. -This IS includes
        security measures (e.g., authentication and access controls) to protect
        USG interests--not for your personal benefit or privacy.
        -Notwithstanding the above, using this IS does not constitute consent to
        PM, LE or CI investigative searching or monitoring of the content of
        privileged communications, or work product, related to personal
        representation or services by attorneys, psychotherapists, or clergy,
        and their assistants. Such communications and work product are private
        and confidential. See User Agreement for details.',
  }
  local_security_policy { 'Interactive logon: Message title for users attempting to log on':
    ensure         => 'present',
    policy_setting => 'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\LegalNoticeCaption',
    policy_type    => 'Registry Values',
    policy_value   => '1,"You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.  By using this IS (which includes any device attached to this IS), you consent to the following conditions:

  -The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE) , and counterintelligence (CI) investigations.

  -At any time, the USG may inspect and seize data stored on this IS.

  -Communications using, or data stored on, this IS are not private, are subject to routing monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.

  -This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.

  -Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants.

  Such communications and work product are private and confidential."',
  }
  local_security_policy { 'Interactive logon: Number of previous logons to cache (in case domain controller is not available)':
    ensure         => 'present',
    policy_setting => 'MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\CachedLogonsCount',
    policy_type    => 'Registry Values',
    policy_value   => '1,"4"',
  }
  local_security_policy { 'Interactive logon: Prompt user to change password before expiration':
    ensure         => 'present',
    policy_setting => 'MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\PasswordExpiryWarning',
    policy_type    => 'Registry Values',
    policy_value   => '4,14',
  }
  # local_security_policy { 'Interactive logon: Require Domain Controller authentication to unlock workstation':
  #   ensure         => 'present',
  #   policy_setting => 'MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\ForceUnlockLogon',
  #   policy_type    => 'Registry Values',
  #   policy_value   => '4,0',
  # }
  # local_security_policy { 'Interactive logon: Require smart card':
  #   ensure         => 'present',
  #   policy_setting => 'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ScForceOption',
  #   policy_type    => 'Registry Values',
  #   policy_value   => '4,0',
  # }
  local_security_policy { 'Interactive logon: Smart card removal behavior':
    ensure         => 'present',
    policy_setting => 'MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\ScRemoveOption',
    policy_type    => 'Registry Values',
    policy_value   => '1,"1"',
    tag            => 'V-1157',
  }
  local_security_policy { 'Load and unload device drivers':
    ensure         => 'present',
    policy_setting => 'SeLoadDriverPrivilege',
    policy_type    => 'Privilege Rights',
    policy_value   => '*S-1-5-32-544',
  }
  # local_security_policy { 'Log on as a batch job':
  #   ensure         => 'present',
  #   policy_setting => 'SeBatchLogonRight',
  #   policy_type    => 'Privilege Rights',
  #   policy_value   => '*S-1-5-32-544,*S-1-5-32-551,*S-1-5-32-559',
  # }
  # local_security_policy { 'Log on as a service':
  #   ensure         => 'present',
  #   policy_setting => 'SeServiceLogonRight',
  #   policy_type    => 'Privilege Rights',
  #   policy_value   => '*S-1-5-80-0',
  # }
  local_security_policy { 'Manage auditing and security log':
    ensure         => 'present',
    policy_setting => 'SeSecurityPrivilege',
    policy_type    => 'Privilege Rights',
    policy_value   => '*S-1-5-32-544',
  }
  local_security_policy { 'Maximum password age':
    ensure         => 'present',
    policy_setting => 'MaximumPasswordAge',
    policy_type    => 'System Access',
    policy_value   => '60',
    tag            => 'V-1104',
  }
  local_security_policy { 'Microsoft network client: Digitally sign communications (always)':
    ensure         => 'present',
    policy_setting => 'MACHINE\System\CurrentControlSet\Services\LanmanWorkstation\Parameters\RequireSecuritySignature',
    policy_type    => 'Registry Values',
    policy_value   => '4,1',
  }
  local_security_policy { 'Microsoft network client: Digitally sign communications (if server agrees)':
    ensure         => 'present',
    policy_setting => 'MACHINE\System\CurrentControlSet\Services\LanmanWorkstation\Parameters\EnableSecuritySignature',
    policy_type    => 'Registry Values',
    policy_value   => '4,1',
    tag            => 'V-1166',
  }
  local_security_policy { 'Microsoft network client: Send unencrypted password to third-party SMB servers':
    ensure         => 'present',
    policy_setting => 'MACHINE\System\CurrentControlSet\Services\LanmanWorkstation\Parameters\EnablePlainTextPassword',
    policy_type    => 'Registry Values',
    policy_value   => '4,0',
    tag            => 'V-1141',
  }
  local_security_policy { 'Microsoft network server: Amount of idle time required before suspending session':
    ensure         => 'present',
    policy_setting => 'MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\AutoDisconnect',
    policy_type    => 'Registry Values',
    policy_value   => '4,15',
  }
  local_security_policy { 'Microsoft network server: Digitally sign communications (always)':
    ensure         => 'present',
    policy_setting => 'MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\RequireSecuritySignature',
    policy_type    => 'Registry Values',
    policy_value   => '4,1',
  }
  local_security_policy { 'Microsoft network server: Digitally sign communications (if client agrees)':
    ensure         => 'present',
    policy_setting => 'MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\EnableSecuritySignature',
    policy_type    => 'Registry Values',
    policy_value   => '4,1',
    tag            => 'V-1162',
  }
  local_security_policy { 'Microsoft network server: Disconnect clients when logon hours expire':
    ensure         => 'present',
    policy_setting => 'MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\EnableForcedLogOff',
    policy_type    => 'Registry Values',
    policy_value   => '4,1',
    tag            => 'V-1136',
  }
  local_security_policy { 'Minimum password age':
    ensure         => 'present',
    policy_setting => 'MinimumPasswordAge',
    policy_type    => 'System Access',
    policy_value   => '1',
    tag            => 'V-1105',
  }
  local_security_policy { 'Minimum password length':
    ensure         => 'present',
    policy_setting => 'MinimumPasswordLength',
    policy_type    => 'System Access',
    policy_value   => '14',
  }
  local_security_policy { 'Modify firmware environment values':
    ensure         => 'present',
    policy_setting => 'SeSystemEnvironmentPrivilege',
    policy_type    => 'Privilege Rights',
    policy_value   => '*S-1-5-32-544',
  }
  # local_security_policy { 'Network access: Allow anonymous SID/name translation':
  #   ensure         => 'present',
  #   policy_setting => 'LSAAnonymousNameLookup',
  #   policy_type    => 'System Access',
  #   policy_value   => '0',
  # }
  local_security_policy { 'Network access: Do not allow anonymous enumeration of SAM accounts':
    ensure         => 'present',
    policy_setting => 'MACHINE\System\CurrentControlSet\Control\Lsa\RestrictAnonymousSAM',
    policy_type    => 'Registry Values',
    policy_value   => '4,1',
  }
  local_security_policy { 'Network access: Do not allow anonymous enumeration of SAM accounts and shares':
    ensure         => 'present',
    policy_setting => 'MACHINE\System\CurrentControlSet\Control\Lsa\RestrictAnonymous',
    policy_type    => 'Registry Values',
    policy_value   => '4,1',
  }
  local_security_policy { 'Network access: Do not allow storage of passwords and credentials for network authentication':
    ensure         => 'present',
    policy_setting => 'MACHINE\System\CurrentControlSet\Control\Lsa\DisableDomainCreds',
    policy_type    => 'Registry Values',
    policy_value   => '4,1',
  }
  local_security_policy { 'Network access: Let Everyone permissions apply to anonymous users':
    ensure         => 'present',
    policy_setting => 'MACHINE\System\CurrentControlSet\Control\Lsa\EveryoneIncludesAnonymous',
    policy_type    => 'Registry Values',
    policy_value   => '4,0',
  }
  local_security_policy { 'Network access: Named Pipes that can be accessed anonymously':
    ensure         => 'present',
    policy_setting => 'MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\NullSessionPipes',
    policy_type    => 'Registry Values',
    policy_value   => '7,7',
  }
  local_security_policy { 'Network access: Remotely accessible registry paths':
    ensure         => 'present',
    policy_setting => 'MACHINE\System\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedExactPaths\Machine',
    policy_type    => 'Registry Values',
    policy_value   => '7,System\CurrentControlSet\Control\ProductOptions,System\CurrentControlSet\Control\Server Applications,Software\Microsoft\Windows NT\CurrentVersion',
  }
  local_security_policy { 'Network access: Remotely accessible registry paths and sub-paths':
    ensure         => 'present',
    policy_setting => 'MACHINE\System\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedPaths\Machine',
    policy_type    => 'Registry Values',
    policy_value   => '7,Software\Microsoft\OLAP Server,Software\Microsoft\Windows NT\CurrentVersion\Perflib,Software\Microsoft\Windows NT\CurrentVersion\Print,Software\Microsoft\Windows NT\CurrentVersion\Windows,System\CurrentControlSet\Control\ContentIndex,System\CurrentControlSet\Control\Print\Printers,System\CurrentControlSet\Control\Terminal Server,System\CurrentControlSet\Control\Terminal Server\UserConfig,System\CurrentControlSet\Control\Terminal Server\DefaultUserConfiguration,System\CurrentControlSet\Services\Eventlog,System\CurrentControlSet\Services\Sysmonlog',
  }
  local_security_policy { 'Network access: Restrict anonymous access to Named Pipes and Shares':
    ensure         => 'present',
    policy_setting => 'MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\RestrictNullSessAccess',
    policy_type    => 'Registry Values',
    policy_value   => '4,1',
  }
  local_security_policy { 'Network access: Sharing and security model for local accounts':
    ensure         => 'present',
    policy_setting => 'MACHINE\System\CurrentControlSet\Control\Lsa\ForceGuest',
    policy_type    => 'Registry Values',
    policy_value   => '4,0',
  }
  local_security_policy { 'Network security: Do not store LAN Manager hash value on next password change':
    ensure         => 'present',
    policy_setting => 'MACHINE\System\CurrentControlSet\Control\Lsa\NoLMHash',
    policy_type    => 'Registry Values',
    policy_value   => '4,1',
  }
  local_security_policy { 'Network security: Force logoff when logon hours expire':
    ensure         => 'present',
    policy_setting => 'ForceLogoffWhenHourExpire',
    policy_type    => 'System Access',
    policy_value   => '1',
  }
  local_security_policy { 'Network security: LDAP client signing requirements':
    ensure         => 'present',
    policy_setting => 'MACHINE\System\CurrentControlSet\Services\LDAP\LDAPClientIntegrity',
    policy_type    => 'Registry Values',
    policy_value   => '4,1',
  }
  local_security_policy { 'Network security: Minimum session security for NTLM SSP based (including secure RPC) clients':
    ensure         => 'present',
    policy_setting => 'MACHINE\System\CurrentControlSet\Control\Lsa\MSV1_0\NTLMMinClientSec',
    policy_type    => 'Registry Values',
    policy_value   => '4,537395200',
  }
  local_security_policy { 'Network security: Minimum session security for NTLM SSP based (including secure RPC) servers':
    ensure         => 'present',
    policy_setting => 'MACHINE\System\CurrentControlSet\Control\Lsa\MSV1_0\NTLMMinServerSec',
    policy_type    => 'Registry Values',
    policy_value   => '4,537395200',
  }
  local_security_policy { 'Password must meet complexity requirements':
    ensure         => 'present',
    policy_setting => 'PasswordComplexity',
    policy_type    => 'System Access',
    policy_value   => '1',
  }
  local_security_policy { 'Perform volume maintenance tasks':
    ensure         => 'present',
    policy_setting => 'SeManageVolumePrivilege',
    policy_type    => 'Privilege Rights',
    policy_value   => '*S-1-5-32-544',
  }
  local_security_policy { 'Profile single process':
    ensure         => 'present',
    policy_setting => 'SeProfileSingleProcessPrivilege',
    policy_type    => 'Privilege Rights',
    policy_value   => '*S-1-5-32-544',
  }
  local_security_policy { 'Profile system performance':
    ensure         => 'present',
    policy_setting => 'SeSystemProfilePrivilege',
    policy_type    => 'Privilege Rights',
    policy_value   => '*S-1-5-32-544,*S-1-5-80-3139157870-2983391045-3678747466-658725712-1809340420',
  }
  # local_security_policy { 'Recovery console: Allow automatic administrative logon':
  #   ensure         => 'present',
  #   policy_setting => 'MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Setup\RecoveryConsole\SecurityLevel',
  #   policy_type    => 'Registry Values',
  #   policy_value   => '4,0',
  # }
  # local_security_policy { 'Recovery console: Allow floppy copy and access to all drives and all folders':
  #   ensure         => 'present',
  #   policy_setting => 'MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Setup\RecoveryConsole\SetCommand',
  #   policy_type    => 'Registry Values',
  #   policy_value   => '4,0',
  # }
  # local_security_policy { 'Remove computer from docking station':
  #   ensure         => 'present',
  #   policy_setting => 'SeUndockPrivilege',
  #   policy_type    => 'Privilege Rights',
  #   policy_value   => '*S-1-5-32-544',
  # }
  local_security_policy { 'Replace a process level token':
    ensure         => 'present',
    policy_setting => 'SeAssignPrimaryTokenPrivilege',
    policy_type    => 'Privilege Rights',
    policy_value   => '*S-1-5-19,*S-1-5-20',
  }
  local_security_policy { 'Restore files and directories':
    ensure         => 'present',
    policy_setting => 'SeRestorePrivilege',
    policy_type    => 'Privilege Rights',
    policy_value   => '*S-1-5-32-544',
  }
  local_security_policy { 'Shut down the system':
    ensure         => 'present',
    policy_setting => 'SeShutdownPrivilege',
    policy_type    => 'Privilege Rights',
    policy_value   => '*S-1-5-32-544',
  }
  local_security_policy { 'Shutdown: Allow system to be shut down without having to log on':
    ensure         => 'present',
    policy_setting => 'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ShutdownWithoutLogon',
    policy_type    => 'Registry Values',
    policy_value   => '4,0',
  }
  local_security_policy { 'Store passwords using reversible encryption':
    ensure         => 'present',
    policy_setting => 'ClearTextPassword',
    policy_type    => 'System Access',
    policy_value   => '0',
  }
  local_security_policy { 'System cryptography: Use FIPS compliant algorithms for encryption, hashing, and signing':
    ensure         => 'present',
    policy_setting => 'MACHINE\System\CurrentControlSet\Control\Lsa\FIPSAlgorithmPolicy\Enabled',
    policy_type    => 'Registry Values',
    policy_value   => '4,1',
  }
  local_security_policy { 'System objects: Require case insensitivity for non-Windows subsystems':
    ensure         => 'present',
    policy_setting => 'MACHINE\System\CurrentControlSet\Control\Session Manager\Kernel\ObCaseInsensitive',
    policy_type    => 'Registry Values',
    policy_value   => '4,1',
  }
  local_security_policy { 'System objects: Strengthen default permissions of internal system objects (e.g., Symbolic Links)':
    ensure         => 'present',
    policy_setting => 'MACHINE\System\CurrentControlSet\Control\Session Manager\ProtectionMode',
    policy_type    => 'Registry Values',
    policy_value   => '4,1',
  }
  local_security_policy { 'System settings: Optional subsystems':
    ensure         => 'present',
    policy_setting => 'MACHINE\System\CurrentControlSet\Control\Session Manager\SubSystems\optional',
    policy_type    => 'Registry Values',
    policy_value   => '7,7',
  }
  # local_security_policy { 'System settings: Use Certificate Rules on Windows Executables for Software Restriction Policies':
  #   ensure         => 'present',
  #   policy_setting => 'MACHINE\Software\Policies\Microsoft\Windows\Safer\CodeIdentifiers\AuthenticodeEnabled',
  #   policy_type    => 'Registry Values',
  #   policy_value   => '4,0',
  # }
  local_security_policy { 'Take ownership of files or other objects':
    ensure         => 'present',
    policy_setting => 'SeTakeOwnershipPrivilege',
    policy_type    => 'Privilege Rights',
    policy_value   => '*S-1-5-32-544',
  }
  local_security_policy { 'User Account Control: Admin Approval Mode for the Built-in Administrator account':
    ensure         => 'present',
    policy_setting => 'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\FilterAdministratorToken',
    policy_type    => 'Registry Values',
    policy_value   => '4,1',
  }
  local_security_policy { 'User Account Control: Allow UIAccess applications to prompt for elevation without using the secure desktop':
    ensure         => 'present',
    policy_setting => 'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\EnableUIADesktopToggle',
    policy_type    => 'Registry Values',
    policy_value   => '4,0',
  }
  local_security_policy { 'User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode':
    ensure         => 'present',
    policy_setting => 'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin',
    policy_type    => 'Registry Values',
    policy_value   => '4,4',
  }
  local_security_policy { 'User Account Control: Behavior of the elevation prompt for standard users':
    ensure         => 'present',
    policy_setting => 'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorUser',
    policy_type    => 'Registry Values',
    policy_value   => '4,0',
  }
  local_security_policy { 'User Account Control: Detect application installations and prompt for elevation':
    ensure         => 'present',
    policy_setting => 'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\EnableInstallerDetection',
    policy_type    => 'Registry Values',
    policy_value   => '4,1',
  }
  local_security_policy { 'User Account Control: Only elevate UIAccess applications that are installed in secure locations':
    ensure         => 'present',
    policy_setting => 'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\EnableSecureUIAPaths',
    policy_type    => 'Registry Values',
    policy_value   => '4,1',
  }
  local_security_policy { 'User Account Control: Only elevate executables that are signed and validated':
    ensure         => 'present',
    policy_setting => 'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ValidateAdminCodeSignatures',
    policy_type    => 'Registry Values',
    policy_value   => '4,0',
  }
  local_security_policy { 'User Account Control: Run all administrators in Admin Approval Mode':
    ensure         => 'present',
    policy_setting => 'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA',
    policy_type    => 'Registry Values',
    policy_value   => '4,1',
  }
  local_security_policy { 'User Account Control: Switch to the secure desktop when prompting for elevation':
    ensure         => 'present',
    policy_setting => 'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\PromptOnSecureDesktop',
    policy_type    => 'Registry Values',
    policy_value   => '4,1',
  }
  local_security_policy { 'User Account Control: Virtualize file and registry write failures to per-user locations':
    ensure         => 'present',
    policy_setting => 'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\EnableVirtualization',
    policy_type    => 'Registry Values',
    policy_value   => '4,1',
  }
  local_security_policy { 'MSS: (AutoAdminLogon) Enable Automatic Logon (not recommended)':
    ensure         => 'present',
    policy_setting => 'MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\AutoAdminLogon',
    policy_type    => 'Registry Values',
    policy_value   => '1,"0"',
  }
  local_security_policy { 'Network security: LAN Manager authentication level':
    ensure         => 'present',
    policy_setting => 'MACHINE\System\CurrentControlSet\Control\Lsa\LmCompatibilityLevel',
    policy_type    => 'Registry Values',
    policy_value   => '4,4',
  }
  local_security_policy { 'Deny access to this computer from the network':
    ensure         => 'present',
    policy_setting => 'SeDenyNetworkLogonRight',
    policy_type    => 'Privilege Rights',
    policy_value   => '*S-1-5-32-546',
    tag            => 'V-1155',
  }
  local_security_policy { 'Devices: Allowed to format and eject removable media':
    ensure         => 'present',
    policy_setting => 'MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\AllocateDASD',
    policy_type    => 'Registry Values',
    policy_value   => '1,"0"',
    tag            => 'V-1171',
  }
  local_security_policy { 'Network access: Shares that can be accessed anonymously':
    ensure         => 'present',
    policy_setting => 'MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\NullSessionShares',
    policy_type    => 'Registry Values',
    policy_value   => '7,7',
  }
  local_security_policy { 'MSS: (SafeDllSearchMode) Enable Safe DLL search mode (recommended)':
    ensure         => 'present',
    policy_setting => 'MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\SafeDllSearchMode',
    policy_type    => 'Registry Values',
    policy_value   => '4,1',
  }
  local_security_policy { 'MSS: (WarningLevel) Percentage threshold for the security event log at which the system will generate a warning':
    ensure         => 'present',
    policy_setting => 'MACHINE\SYSTEM\CurrentControlSet\Services\Eventlog\Security\WarningLevel',
    policy_type    => 'Registry Values',
    policy_value   => '4,90',
  }
  local_security_policy { 'MSS: (DisableIPSourceRouting) IP source routing protection level (protects against packet spoofing)':
    ensure         => 'present',
    policy_setting => 'MACHINE\System\CurrentControlSet\Services\Tcpip\Parameters\DisableIPSourceRouting',
    policy_type    => 'Registry Values',
    policy_value   => '4,2',
  }
  local_security_policy { 'MSS: (EnableICMPRedirect) Allow ICMP redirects to override OSPF generated routes':
    ensure         => 'present',
    policy_setting => 'MACHINE\System\CurrentControlSet\Services\Tcpip\Parameters\EnableICMPRedirect',
    policy_type    => 'Registry Values',
    policy_value   => '4,0',
  }
  local_security_policy { 'MSS: (PerformRouterDiscovery) Allow IRDP to detect and configure Default Gateway addresses (could lead to DoS)':
    ensure         => 'present',
    policy_setting => 'MACHINE\System\CurrentControlSet\Services\Tcpip\Parameters\PerformRouterDiscovery',
    policy_type    => 'Registry Values',
    policy_value   => '4,0',
  }
  local_security_policy { 'MSS: (KeepAliveTime) How often keep-alive packets are sent in milliseconds':
    ensure         => 'present',
    policy_setting => 'MACHINE\System\CurrentControlSet\Services\Tcpip\Parameters\KeepAliveTime',
    policy_type    => 'Registry Values',
    policy_value   => '4,300000',
  }
  local_security_policy { 'MSS: (NoNameReleaseOnDemand) Allow the computer to ignore NetBIOS name release requests except from WINS servers':
    ensure         => 'present',
    policy_setting => 'MACHINE\System\CurrentControlSet\Services\Netbt\Parameters\NoNameReleaseOnDemand',
    policy_type    => 'Registry Values',
    policy_value   => '4,1',
  }
  local_security_policy { 'MSS: (TcpMaxDataRetransmissions) How many times unacknowledged data is retransmitted (3 recommended, 5 is default)':
    ensure         => 'present',
    policy_setting => 'MACHINE\System\CurrentControlSet\Services\Tcpip\Parameters\TcpMaxDataRetransmissions',
    policy_type    => 'Registry Values',
    policy_value   => '4,3',
  }
  local_security_policy { 'MSS: (ScreenSaverGracePeriod) The time in seconds before the screen saver grace period expires (0 recommended)':
    ensure         => 'present',
    policy_setting => 'MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\ScreenSaverGracePeriod',
    policy_type    => 'Registry Values',
    policy_value   => '1,"5"',
  }
  # local_security_policy { 'Network access: Shares that can be accessed anonymously':
  #   ensure         => 'present',
  #   policy_setting => 'MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\NullSessionShares',
  #   policy_type    => 'Registry Values',
  #   policy_value   => '7,',
  # }
  local_security_policy { 'Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings':
    ensure         => 'present',
    policy_setting => 'MACHINE\System\CurrentControlSet\Control\Lsa\SCENoApplyLegacyAuditPolicy',
    policy_type    => 'Registry Values',
    policy_value   => '4,1',
  }
  local_security_policy { 'MSS: (NoDefaultExempt) Configure IPSec exemptions for various types of network traffic.':
    ensure         => 'present',
    policy_setting => 'MACHINE\System\CurrentControlSet\Services\IPSEC\NoDefaultExempt',
    policy_type    => 'Registry Values',
    policy_value   => '4,3',
  }
  # local_security_policy { 'User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode':
  #   ensure         => 'present',
  #   policy_setting => 'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin',
  #   policy_type    => 'Registry Values',
  #   policy_value   => '4,4',
  # }
  local_security_policy { 'Network security: Allow Local System to use computer identity for NTLM':
    ensure         => 'present',
    policy_setting => 'MACHINE\System\CurrentControlSet\Control\Lsa\UseMachineId',
    policy_type    => 'Registry Values',
    policy_value   => '4,1',
  }
  local_security_policy { 'Network security: Allow LocalSystem NULL session fallback':
    ensure         => 'present',
    policy_setting => 'MACHINE\System\CurrentControlSet\Control\Lsa\MSV1_0\allownullsessionfallback',
    policy_type    => 'Registry Values',
    policy_value   => '4,0',
  }
  local_security_policy { 'Network security: Allow PKU2U authentication requests to this computer to use online identities':
    ensure         => 'present',
    policy_setting => 'MACHINE\System\CurrentControlSet\Control\Lsa\pku2u\AllowOnlineID',
    policy_type    => 'Registry Values',
    policy_value   => '4,0',
  }
  local_security_policy { 'MSS: (DisableIPSourceRouting IPv6) IP source routing protection level (protects against packet spoofing)':
    ensure         => 'present',
    policy_setting => 'MACHINE\System\CurrentControlSet\Services\Tcpip6\Parameters\DisableIPSourceRouting',
    policy_type    => 'Registry Values',
    policy_value   => '4,2',
  }
  local_security_policy { 'MSS: (TcpMaxDataRetransmissions IPv6) How many times unacknowledged data is retransmitted (3 recommended, 5 is default)':
    ensure         => 'present',
    policy_setting => 'MACHINE\System\CurrentControlSet\Services\Tcpip6\Parameters\TcpMaxDataRetransmissions',
    policy_type    => 'Registry Values',
    policy_value   => '4,3',
  }
  local_security_policy { 'Microsoft network server: Server SPN target name validation level':
    ensure         => 'absent',
    # policy_setting => 'MACHINE\System\CurrentControlSet\Services\LanmanServer\Parameters\SmbServerNameHardeningLevel',
    # policy_type    => 'Registry Values',
    # policy_value   => '4,0',
  }
  local_security_policy { 'Access Credential Manager as a trusted caller':
    ensure => 'absent',
  }
  local_security_policy { 'Access this computer from the network':
    ensure         => 'present',
    policy_setting => 'SeNetworkLogonRight',
    policy_type    => 'Privilege Rights',
    policy_value   => '*S-1-5-11,*S-1-5-32-544',
  }
  local_security_policy { 'Allow log on locally':
    ensure         => 'present',
    policy_setting => 'SeInteractiveLogonRight',
    policy_type    => 'Privilege Rights',
    policy_value   => '*S-1-5-32-544',
  }
  local_security_policy { 'Bypass traverse checking':
    ensure         => 'present',
    policy_setting => 'SeChangeNotifyPrivilege',
    policy_type    => 'Privilege Rights',
    policy_value   => '*S-1-5-11,*S-1-5-19,*S-1-5-20,*S-1-5-32-544,*S-1-5-90-0',
  }
  local_security_policy { 'Deny log on as a batch job':
    ensure         => 'present',
    policy_setting => 'SeDenyBatchLogonRight',
    policy_type    => 'Privilege Rights',
    policy_value   => '*S-1-5-32-546',
  }
  local_security_policy { 'Deny log on as a service':
    ensure => 'absent',
  }
  local_security_policy { 'Deny log on locally':
    ensure         => 'present',
    policy_setting => 'SeDenyInteractiveLogonRight',
    policy_type    => 'Privilege Rights',
    policy_value   => '*S-1-5-32-546',
  }
  local_security_policy { 'Deny log on through Remote Desktop Services':
    ensure         => 'present',
    policy_setting => 'SeDenyRemoteInteractiveLogonRight',
    policy_type    => 'Privilege Rights',
    policy_value   => '*S-1-5-32-546',
  }
  local_security_policy { 'Enable computer and user accounts to be trusted for delegation':
    ensure => 'absent',
  }
  local_security_policy { 'Lock pages in memory':
    ensure => 'absent',
  }
  local_security_policy { 'Modify an object label':
    ensure => 'absent',
  }
  local_security_policy { 'Interactive logon: Machine inactivity limit':
    ensure         => 'present',
    policy_setting => 'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\InactivityTimeoutSecs',
    policy_type    => 'Registry Values',
    policy_value   => '4,900',
  }
  local_security_policy { 'System cryptography: Force strong key protection for user keys stored on the computer':
    ensure         => 'present',
    policy_setting => 'MACHINE\Software\Policies\Microsoft\Cryptography\ForceKeyProtection',
    policy_type    => 'Registry Values',
    policy_value   => '4,2',
  }

}
