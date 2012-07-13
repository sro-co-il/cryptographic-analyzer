<?php //https://code.google.com/p/cryptographic-analyzer
header("Content-type: text/html; charset=UTF-8");
error_reporting(0);

if (get_magic_quotes_gpc())
  {
  $_GET = array_map("stripslashes", $_GET);
  $_POST = array_map("stripslashes", $_POST);
  $_COOKIE = array_map("stripslashes", $_COOKIE);
  }

if(isset($_FILES['file']))
{
	$file['md5'] = md5_file($_FILES['file']['tmp_name']);
	$file['sha1'] = sha1_file($_FILES['file']['tmp_name']);
}
?>
<html>
<head>
<meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
</head>
<body>
<div style="float:left; width:100%">
<form enctype="multipart/form-data" action="" method="post" style="width:100%">
<h1>Files Sign Checking</h1>
<input type="file" name="file" /><br /><br />
<input type="submit" name="submit" value="Check" />
<?php
if(isset($file))
{
	echo "<xmp>\r\n";
	echo "md5: {$file['md5']}\r\n";
	echo "sha1: {$file['sha1']}\r\n";
	echo "</xmp>\r\n";
}
?>
</form>
</p></body></html>