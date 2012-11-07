#!/usr/bin/tcl

load ./libmcrypt1.0.so

set CIPHER_KEY	{}
set IV		{}
set sStr	"test"

if { 0 } {
	set td1	[ mcrypt_module_open MCRYPT_RIJNDAEL_128 "" MCRYPT_MODE_CBC "" ]
	puts	[ mcrypt_generic_init $td1 MCRYPT_RIJNDAEL_128 $CIPHER_KEY $IV ]
	puts	[ mcrypt_generic $td1 $sStr ]
	puts	[ mcrypt_generic_deinit $td1 ]
	puts	[ mcrypt_module_close $td1 ]
}
if { 0 } {
	puts "mcrypt_get_iv_size 	: [ mcrypt_get_iv_size MCRYPT_RIJNDAEL_128 MCRYPT_MODE_CBC ]"
	puts "mcrypt_create_iv 		: [ mcrypt_create_iv 16 MCRYPT_RAND ]"
	puts "mcrypt_list_algorithms: [ mcrypt_list_algorithms ]"
	puts "mcrypt_list_modes 	: [ mcrypt_list_modes ]"
	puts "mcrypt_get_key_size 	: [ mcrypt_get_key_size MCRYPT_RIJNDAEL_128 MCRYPT_MODE_CBC ]"
}

#http://kr.php.net/manual/kr/function.mcrypt-encrypt.php
#http://kr.php.net/manual/kr/function.mcrypt-decrypt.php
for { set i 0 } { $i < 1 } { incr i } {

	set K [binary format H* $CIPHER_KEY]
	set I [binary format H* $IV]

	set sEnc	[ mcrypt_encrypt MCRYPT_RIJNDAEL_128 $K $sStr MCRYPT_MODE_CBC $I ]
	set sDec	[ mcrypt_decrypt MCRYPT_RIJNDAEL_128 $K $sEnc MCRYPT_MODE_CBC $I ]
	#puts "enc : $sEnc"
	#puts "dec : $sDec"
}
