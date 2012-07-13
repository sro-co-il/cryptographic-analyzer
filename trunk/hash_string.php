<?php //https://code.google.com/p/cryptographic-analyzer
header("Content-type: text/html; charset=UTF-8");
error_reporting(0);

if (get_magic_quotes_gpc())
  {
  $_GET = array_map("stripslashes", $_GET);
  $_POST = array_map("stripslashes", $_POST);
  $_COOKIE = array_map("stripslashes", $_COOKIE);
  }

if(isset($_POST['text']))
	$plain = $_POST['text'];
else
	$plain = "";

?>
<html>
<head>
<meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
</head>
<body>
<div style="float:left; width:100%">
<h1>Hashing</h1>
<form method="post" action="" ">
<textarea name="text" style="width:100%; height:50px; text-align:left; direction:ltr; display:block">
<?php echo htmlspecialchars($plain) ?></textarea>
<input type="submit" value="Make Hashing"></form>
<xmp style="width:100%; float:left"><?php
foreach (hash_algos() as $hash)
  echo sprintf("%-12s", $hash) . "  " . hash($hash, $plain) . "\r\n";
?></xmp></div>
</body></html>