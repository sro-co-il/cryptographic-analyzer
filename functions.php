<?php // https://code.google.com/p/cryptographic-analyzer
error_reporting(0);

function action_list($action)
{
	$encode = array("htmlspecialchars","urlencode","base64_encode","convert_uuencode","utf8_encode","encode_to_hex","encode_to_dec","encode_to_oct","encode_to_bin");
	$decode = array("htmlspecialchars_decode","urldecode","base64_decode","convert_uudecode","utf8_decode","decode_from_hex","decode_from_dec","decode_from_oct","decode_from_bin");
	$symmetric = array("str_rot13", "ff");
	$hash = hash_algos();
		
	switch($action)
	{
	case 'encode':
		return array_merge(array("Plain"), $symmetric, $encode);
	case 'decode':
		return array_merge(array("Plain"), $symmetric, $decode);
	case 'hash':
		return array_merge(array("Plain"), $hash);
	case 'all':
		return array_merge(array("Plain"), $symmetric, $encode, $decode, $hash);
	default:
		return array();
	}
}

function encoding($text, $action)
{
	if(in_array($action, hash_algos()))
		return hash($action, $text);
	
	switch ($action)
	{
	case "html":
		$string = str_replace(";", "", $text);
		$string = str_replace("&#", " ", $string); //???? ???? ?? ???? ????        
		$string = explode(" ", substr($string, 1)); //????? ????? ????? ?????? ???????
	
		foreach ($string as $str)
		fill($str);
		break;

	case "Plain":
		return $text;
	
	case "htmlspecialchars":
	case "htmlspecialchars_decode":
	case "urlencode":
	case "urldecode":
	case "base64_encode":
	case "base64_decode":
	case "convert_uuencode":
	case "convert_uudecode":
	case "str_rot13":
	case "utf8_encode":
	case "utf8_decode":
		return $action($text);

	case "encode_to_hex":
		$text = str_split($text);
		foreach($text as &$txt)
			$txt = sprintf("%02x", ord($txt));
		return implode(",", $text);
	
	case "decode_from_hex":
		// delete any delimiters
		$text = str_replace(array(",", " "), "", $text);
		$text = str_split($text, 2);
		foreach($text as &$txt)
			$txt = chr(hexdec($txt));
		return implode("", $text);
	
	case "encode_to_dec":
		$text = str_split($text);
		foreach($text as &$txt)
			$txt = sprintf("%03d", ord($txt));
		return implode(",", $text);
		
	case "decode_from_dec":
		// delete any delimiters
		if(strpos($text, ",") !== false)
			$text = explode(",", $text);
		elseif(strpos($text, " ") !== false)
			$text = explode(" ", $text);
		else
			$text = str_split($text, 3);
		foreach($text as &$txt)
			$txt = chr($txt);
		return implode("", $text);
	
	case "encode_to_oct":
		$text = str_split($text);
		foreach($text as &$txt)
			$txt = sprintf("%03o", ord($txt));
		return implode(",", $text);
	
	case "decode_from_oct":
		// delete any delimiters
		if(strpos($text, ",") !== false)
			$text = explode(",", $text);
		elseif(strpos($text, " ") !== false)
			$text = explode(" ", $text);
		else
			$text = str_split($text, 3);
		foreach($text as &$txt)
			$txt = $txt = chr(octdec($txt));
		return implode("", $text);
	
	case "encode_to_bin":
		$text = str_split($text);
		foreach($text as &$txt)
			$txt = sprintf("%08b", ord($txt));
		return implode(",", $text);
	
	case "decode_from_bin":
		// delete any delimiters
		if(strpos($text, ",") !== false)
			$text = explode(",", $text);
		elseif(strpos($text, " ") !== false)
			$text = explode(" ", $text);
		else
			$text = str_split($text, 8);
		foreach($text as &$txt)
			$txt = $txt = chr(bindec($txt));
		return implode("", $text);
	
	case "ff":
		$text = str_split($text);
		foreach($text as &$txt)
		{
			$txt = ord($txt);
			$txt = 256 - $txt;
			$txt = chr($txt);
		}
		return implode("", $text);		
    }
}

function HashType($hash)
{
	$matches = array(); $len = strlen($hash);

	if ( preg_match('/^[a-f0-9]{4}$/i',$hash) )
		$matches = array_merge($matches,array('crc16','crc16ccitt','fcs16'));
	else if ( preg_match('/^[a-f0-9]{8}$/i',$hash) )
	{
		$matches = array_merge($matches,array('adler32','crc32','crc32b','ghash32-3','ghash32-5'));

		if ( preg_match('/^[0-9]{8}$/i',$hash) )
			$matches[] = 'xor-32';
	}
	else if ( preg_match('/^[a-z0-9\.\/]{13}$/i',$hash) )
		$matches[] = 'des(unix)';
	else if ( preg_match('/^[a-f0-9]{16}$/i',$hash) )
		$matches = array_merge($matches,array('md5(half)','md5(middle)','mysql4'));
	else if ( preg_match('/^(_([\.\/0-9a-z]{8}))[\.\/0-9a-z]{11}$/i',$hash) )
		$matches[] = 'crypt_ext_des'; # Extra: \\1 = salt, \\2 = inner salt
	else if ( preg_match('/^[a-f0-9]{32}$/i',$hash) )
		$matches = array_merge($matches,array('haval128-3','haval128-4','haval128-5','ripemd128','tiger128-3','tiger128-4','md2','md4','md5','ntlm','lm','mdc-2'));
	else if ( preg_match('/^0x[a-f0-9]{32}$/i',$hash) )
		$matches[] = 'lineage-II-C4';
	else if ( preg_match('/^[a-f0-9]{40}$/i',$hash) )
		$matches = array_merge($matches,array('haval160-3','haval160-4','haval160-5','sha1','rimped160','tiger160-3','tiger160-4','mysql5'));
	else if ( preg_match('/^[a-f0-9]{48}$/i',$hash) )
		$matches = array_merge($matches,array('haval192-3','haval192-4','haval192-5','tiger192-3','tiger192-4'));
	else if ( preg_match('/^[a-f0-9]{56}$/i',$hash) )
		$matches = array_merge($matches,array('haval224-3','haval224-4','haval224-5','sha224','sandstorm-224'));
	else if ( preg_match('/^\$2a\$((0[4,5,6,7,8,9])|((1|2)[0,1,2,3,4,5,6,7,8,9])|31)\$([\.\/\$0-9a-z]{21})[\.\/0-9a-z]{32}$/i',$hash) )
		$matches[] = 'crypt_blowfish'; # Extra: \\1 = cost parameter, \\5 = kind of inner salt
	else if ( preg_match('/^[a-f0-9]{64}$/i',$hash) )
		$matches = array_merge($matches,array('gost','haval256-4','haval256-5','haval256-3','rimped256','sha256','snefru','snefru256','blake-256','fork-256','sandstorm-256'));
	else if ( preg_match('/^[a-f0-9]{80}$/i',$hash) )
		$matches[] = 'rimped320';
	else if ( preg_match('/^[a-f0-9]{96}$/i',$hash) )
		$matches = array_merge('sha384','sandstorm-384');
	else if ( preg_match('/^[a-f0-9]{128}$/i',$hash) )
		$matches = array_merge($matches,array('salsa10','salsa20','sha512','whirlpool','blake-512','sandstorm-512'));
	else if ( $len > 3 && $len <= 33 && preg_match('/^(\$1\$([^\$]{0,8})\$)[a-z0-9]{22}$/i',$hash) )
		$matches[] = 'crypt_md5'; # Extra: \\1 = salt, \\2 = inner salt
	else if ( $len >= 46 && preg_match('/^\$5\$([^\$]*\$)?([^\$]{0,16})\$[\.\/0-9a-z]{43}$/i',$hash) )
		$matches[] = 'crypt_sha256'; # Extra: \\1 = rounds definition, \\2 = kind of inner salt
	else if ( $len >= 89 && preg_match('/^\$6\$([^\$]*\$)?([^\$]{0,16})\$[\.\/0-9a-z]{86}$/i',$hash) )
		$matches[] = 'crypt_sha512'; # Extra: \\1 = rounds definition, \\2 = kind of inner salt

	if ( preg_match('/^[a-z0-9\+\/]+={0,2}$/i',$hash) )
		$matches[] = 'base64';
	else if ( preg_match('/^[a-z0-9\-_]+={0,2}$/i',$hash) )
		$matches[] = 'base64(safe url/filename)';

	if ( preg_match('/[a-z]/i',$hash) ) $matches[] = 'rot13';
	if ( preg_match('/^[a-z2-7]+={0,3}$/i',$hash) ) $matches[] = 'base32';

	sort($matches);

	return $matches;
}

?>