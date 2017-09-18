Dism {
  ensure => absent,
}

dism { 'FaxServiceRole': }

dism { 'FaxServiceConfigRole': }

dism { 'IIS-FTPServer': }

dism { 'IIS-FTPSvc': }
