

rule KatyushaRansomware {
   meta:
      description = "KatyushaRansomware"
      author = "Marco Cuccarini"
      reference = "marco.cuccarini1@gmail.com"
      date = "03-01-2020"
     
   strings:
     	$ce = { 43 72 79 70 74 45 6E 63 72 79 70 74 }  // CryptEncrypt

     
	$op1 = { 47 65 74 4D 6F 64 75 6C 65 48 61 6E }    // GetModuleHandleA
	$op2 = { 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 } // GetProcAddress
	$op3 = { 53 68 65 6C 6C 45 78 65 63 75 74 65 41 } //ShellExecute
        $op4 = { 47 65 74 49 70 41 64 64 72 54 61 62 6C 65} //GetIpAddrTable
       
        $y = {55 53 45 52 33 32 2E 64 6C 6C} //USER32.dll
        
        $x1 = {4B 45 52 4E 45 4C 33 32 2E 44 4C 4C} //KERNEL32.DLL
	$x2 = {57 53 32 5F 33 32 2E 64 6C 6C} //WS2_32.dll
	
	$x3 = {41 44 56 41 50 49 33 32 2E 64 6C 6C } //ADVAPI32.dll
        $x4 = {53 48 45 4C 4C 33 32 2E 64 6C 6C} //SHELL32.dll
	$x5 = {49 50 48 4C 50 41 50 49 2E 44 4C 4C} //IPPHLPAPI.DLL
        $x6 = {57 4C 44 41 50 33 32 2E 64 6C 6C} //WLDAP32.dll
        

   condition:
         filesize < 3000KB and ( 2 of ($op*) and 2 of ($x*) ) and $ce and $y
}




