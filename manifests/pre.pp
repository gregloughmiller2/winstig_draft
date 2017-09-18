class winstig::pre {

  local_security_policy { 'Accounts: Block Microsoft accounts':
    ensure         => 'present',
    policy_setting => 'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\NoConnectedUser',
    policy_type    => 'Registry Values',
    policy_value   => '4,0',
  }

}
