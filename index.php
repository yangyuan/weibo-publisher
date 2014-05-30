<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
</head>
<body>
<?php
ini_set('display_errors', '1');
require('weibo.php');

$COOKIEFILE = 'cookie.txt';
$USERNAME = 'weibo%40weibo.cn';
$PASSWORD = 'weibo';



$userid = login($USERNAME, $PASSWORD, $COOKIEFILE);
echo $userid;

/*
$ret = weibo_publish('weibo', $COOKIEFILE);
if ($ret !== TRUE) {
	echo $ret;
} else {
	echo 'success';
}

// UPLOAD
$file = $_FILES['upload'];
$data = file_get_contents($file['tmp_name']);
$mime = urlencode($file["type"]);
$pid = weibo_upload_image($data, 'image/jpeg', $COOKIEFILE);
echo weibo_get_image_url($pid);	

// LOCAL
$data = file_get_contents('C:\test.jpg');
$pid = weibo_upload_image($data, 'image/jpeg', $COOKIEFILE);
echo weibo_get_image_url($pid);	
*/


?>
</body>
</html>