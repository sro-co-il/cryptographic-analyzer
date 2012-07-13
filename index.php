<?php //https://code.google.com/p/cryptographic-analyzer
error_reporting(0);
include("functions.php");

header("Content-type: text/html; charset=UTF-8");

// unslash magic quotes
if (get_magic_quotes_gpc())
  {
  $_GET = array_map("stripslashes", $_GET);
  $_POST = array_map("stripslashes", $_POST);
  $_COOKIE = array_map("stripslashes", $_COOKIE);
  }

function board()
{
	$encoded = array();
	foreach(action_list($_GET['ajax']) as $action)
		$encoded[$action] = encoding($_POST['text'], $action);
	foreach($encoded as $enc=>$txt)
	{
		$e = htmlspecialchars($txt);
		$len = strlen($txt);
		echo <<<END
<div style="float:left;width:32%;border:0;margin:0;margin-left:1%">
<form method="post">
<strong>$enc</strong> Length: $len chars
<div style="float:right">
<input type="button" value="Send it to Workboard" onclick="javascript:send2workboard('$enc')" />
</div>
<textarea name="text" id="$enc" style="width:100%" rows=5>$e</textarea><br />
</form>
</div>
END;
	}
}

function multi()
{
	$text = $_POST['text'];
	$text = encoding($text, $_GET['action1']);
	$text = encoding($text, $_GET['action2']);
	$text = encoding($text, $_GET['action3']);

	$action1 = htmlspecialchars($_GET['action1']);
	$action2 = htmlspecialchars($_GET['action2']);
	$action3 = htmlspecialchars($_GET['action3']);

	$e = htmlspecialchars($text);
	$len = strlen($text);
		echo <<<END
<div style="width:100%;text-align:center">
<form method="post">
<strong>$action1=>$action2=>$action3</strong> | Length: $len chars | <input type="button" value="Send it to Workboard" onclick="javascript:send2workboard('multi')" /><br />
<textarea name="text" id="multi" style="width:50%" rows=5>$e</textarea><br />
</form>
</div>
END;
}

function detect()
{
	$matches = HashType($_POST['text']);
	if(count($matches > 0))
		echo "It can be:\n\n" . implode("\n", $matches) . "\n\nWritten by hacking.org.il";
	exit();	
}

if(isset($_GET['ajax']))
	{
	if($_GET['ajax'] == 'multi')
		multi();
	elseif($_GET['ajax'] == 'detect')
		detect();
	else
		board();
	exit();
	}
?>
<html>
<head>
	<meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
	<meta name="description" content="Encoder" />
	<meta name="keywords" content="Encoder" />
	<meta name="author" content="sro.co.il" />
	<title>Encoder</title>
</head>
<body>
<br />
<div style="width:100%;text-align:center">
<strong>WorkBoard</strong><br />
<textarea id="workboard" style="width:50%" rows=8></textarea><br />
<input type="button" value="Encode it" onclick="javascript:encodeIt('workboard','encode')" />
<input type="button" value="Decode it" onclick="javascript:encodeIt('workboard','decode')" />
<input type="button" value="Hash it" onclick="javascript:encodeIt('workboard','hash')" />
<input type="button" value="Detect it" onclick="javascript:detectIt()" />
<input type="button" id="btn-repbar" value="[Replace bar]" onclick="javascript:bar('repbar')" />
<input type="button" id="btn-multibar" value="[Multi bar]" onclick="javascript:bar('multibar')" />

<br />

<div id="repbar" style="display:none">Replace <input type="text" id="rep1" size=5 /> with <input type="text" id="rep2" size=5 /> <input type="button" onclick="javascript: replace()" value="replace" /></div>
<div id="multibar" style="display:none">
<select id="action1" name="action1">
<option value="Plain">Action 1</option>
<?php foreach(action_list('all') as $action)
		echo "<option value='$action'>$action</option>\r\n";?>
</select>
<select id="action2" name="action2">
<option value="Plain">Action 2</option>
<?php foreach(action_list('all') as $action)
		echo "<option value='$action'>$action</option>\r\n";?>
</select>
<select id="action3" name="action3">
<option value="Plain">Action 3</option>
<?php foreach(action_list('all') as $action)
		echo "<option value='$action'>$action</option>\r\n";?>
</select>
<input type="button" onclick="javascript: multiIt()" value="Encode" />
</div>

<br /><br />
</div>

<div id="board">
<?php board(); ?>
</div>

<script type="text/javascript">
function bar(id)
{
	if(getE(id).style.display == "none")
	{
		getE(id).style.display = "block";
		getE('btn-' + id).style.backgroundColor = "LightGray";
	}
	else
	{
		getE(id).style.display = "none";
		getE('btn-' + id).style.backgroundColor = "#F0F0F0";
	}
}

function getE(id)
{
	return document.getElementById(id);
}

function send2workboard(element)
{
	getE('workboard').value = getE(element).value;
}

function replace()
{
	var str = getE('workboard').value;
	getE('workboard').value = str.replace(new RegExp(getE('rep1').value, 'g'), getE('rep2').value);
}

function encodeIt(element, action)
{
	text = getE(element).value;
	var xmlhttp;
	if (window.XMLHttpRequest)
		xmlhttp=new XMLHttpRequest();
	else
		xmlhttp=new ActiveXObject("Microsoft.XMLHTTP");
	xmlhttp.onreadystatechange=function()
	{
		if (xmlhttp.readyState==4 && xmlhttp.status==200)
			getE("board").innerHTML=xmlhttp.responseText;
	}
	xmlhttp.open("POST","?ajax="+action,true);
	xmlhttp.setRequestHeader("Content-type","application/x-www-form-urlencoded");
	xmlhttp.send("text=" + escape(text));
}

function multiIt()
{
	text = getE('workboard').value;
	var xmlhttp;
	if (window.XMLHttpRequest)
		xmlhttp=new XMLHttpRequest();
	else
		xmlhttp=new ActiveXObject("Microsoft.XMLHTTP");
	xmlhttp.onreadystatechange=function()
	{
		if (xmlhttp.readyState==4 && xmlhttp.status==200)
			getE("board").innerHTML=xmlhttp.responseText;
	}
	xmlhttp.open("POST","?ajax=multi&action1="+getE('action1').value+"&action2="+getE('action2').value+"&action3="+getE('action3').value,true);
	xmlhttp.setRequestHeader("Content-type","application/x-www-form-urlencoded");
	xmlhttp.send("text=" + escape(text));
}

function detectIt()
{
	text = getE('workboard').value;
	var xmlhttp;
	if (window.XMLHttpRequest)
		xmlhttp=new XMLHttpRequest();
	else
		xmlhttp=new ActiveXObject("Microsoft.XMLHTTP");
	xmlhttp.onreadystatechange=function()
	{
		if (xmlhttp.readyState==4 && xmlhttp.status==200)
			if(xmlhttp.responseText!="")
				alert(xmlhttp.responseText);
	}
	xmlhttp.open("POST","?ajax=detect",true);
	xmlhttp.setRequestHeader("Content-type","application/x-www-form-urlencoded");
	xmlhttp.send("text=" + escape(text));
}
</script>
</body></html>
