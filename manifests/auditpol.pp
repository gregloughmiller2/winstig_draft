class winstig::auditpol {

  auditpol { 'Credential Validation':
    failure => 'enable',
    success => 'enable',
  }
  auditpol { 'Computer Account Management':
    failure => 'enable',
    success => 'enable',
  }
  auditpol { 'Other Account Management Events':
    failure => 'enable',
    success => 'enable',
  }
  auditpol { 'Security Group Management':
    failure => 'enable',
    success => 'enable',
  }
  auditpol { 'User Account Management':
    failure => 'enable',
    success => 'enable',
  }
  auditpol { 'Process Creation':
    failure => 'enable',
  }
  auditpol { 'Logoff':
    failure => 'disable',
    success => 'enable',
  }
  auditpol { 'Logon':
    failure => 'enable',
    success => 'enable',
  }
  auditpol { 'Special Logon':
    failure => 'disable',
    success => 'enable',
  }
  auditpol { 'Audit Policy Change':
    failure => 'enable',
    success => 'enable',
  }
  auditpol { 'Authentication Policy Change':
    failure => 'disable',
    success => 'enable',
  }
  auditpol { 'Sensitive Privilege Use':
    failure => 'enable',
    success => 'enable',
  }
  auditpol { 'IPsec Driver':
    failure => 'enable',
    success => 'enable',
  }
  auditpol { 'Security State Change':
    failure => 'enable',
    success => 'enable',
  }
  auditpol { 'Security System Extension':
    failure => 'enable',
    success => 'enable',
  }
  auditpol { 'System Integrity':
    failure => 'enable',
    success => 'enable',
  }
  auditpol { 'Authorization Policy Change':
    failure => 'enable',
    success => 'enable',
  }

}
