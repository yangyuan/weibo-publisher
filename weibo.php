<?php
ini_set('display_errors', '1');

function sys_microtime() {
	return floor(microtime(true)*1000);
}

function web_post($url, $data, $referer = null, $cookiefile = null, $header = null) {
	$ch = curl_init();
	curl_setopt($ch, CURLOPT_URL,$url);
	curl_setopt($ch, CURLOPT_HEADER, 0);
	curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
	curl_setopt($ch, CURLOPT_FOLLOWLOCATION, 1);
	curl_setopt($ch, CURLOPT_POST, 1);
	curl_setopt($ch, CURLOPT_USERAGENT,"Mozilla/5.0 (Windows NT 6.3; WOW64; rv:24.0) Gecko/20100101 Firefox/24.0");
	if ($referer != null) {
		curl_setopt($ch, CURLOPT_REFERER, $referer);
	}
	if ($cookiefile != null) {
		curl_setopt($ch, CURLOPT_COOKIEJAR, $cookiefile);
		curl_setopt($ch, CURLOPT_COOKIEFILE, $cookiefile);
	}
	if ($header != null) {
		curl_setopt($ch, CURLOPT_HTTPHEADER, $header);
	}
	curl_setopt($ch, CURLOPT_POSTFIELDS, $data);
	$data = curl_exec($ch);
	curl_close($ch);
	return $data;
}

function web_get($url, $referer = null, $cookiefile = null, $header = null) {
	$ch = curl_init();
	curl_setopt($ch, CURLOPT_URL,$url);
	curl_setopt($ch, CURLOPT_HEADER, 0);
	curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
	curl_setopt($ch, CURLOPT_POST, 0);
	curl_setopt($ch, CURLOPT_FOLLOWLOCATION, 1);
	curl_setopt($ch, CURLOPT_USERAGENT,"Mozilla/5.0 (Windows NT 6.3; WOW64; rv:24.0) Gecko/20100101 Firefox/24.0");
	if ($referer != null) {
		curl_setopt($ch, CURLOPT_REFERER, $referer);
	}
	if ($cookiefile != null) {
		curl_setopt($ch, CURLOPT_COOKIEJAR, $cookiefile);
		curl_setopt($ch, CURLOPT_COOKIEFILE, $cookiefile);
	}
	if ($header != null) {
		curl_setopt($ch, CURLOPT_HTTPHEADER, $header);
	}
	$data = curl_exec($ch);
	curl_close($ch);
	return $data;
}

function jsonp_decode_object($str) {
	// only work when this jsonp has one param
	$pattern_params = "/^[^\(]+\((.*)\)[;\s]*$/";
	if (1== preg_match($pattern_params, $str, $matches)) {
		$params = $matches[1];
		return json_decode ($params , true);
	} else {
		return FALSE;
	}
}

function str_crop($string, $start, $end, $ignore_case = FALSE)
{
	if (str_startswith($string, $start, $ignore_case)) {
		$string = substr($string, strlen($start)); 
	}
    if (str_endswith($string, $end, $ignore_case)) {
		$string = substr($string, 0, strlen($string)- strlen($end)); 
	}
	return $string;
}

function str_startswith($string, $start, $ignore_case = FALSE)
{
	if ($ignore_case) !strncasecmp ($string, $start, strlen($start));
    return !strncmp($string, $start, strlen($start));
}

function str_endswith($string, $end, $ignore_case = FALSE)
{
    $length = strlen($end);
    if ($length == 0) { return true; }
	$string_end = substr($string, -$length);
	if ($ignore_case) !strcasecmp ($string_end, $end);
    return !strcmp($string_end, $end);
}

function asn1_length($length)
{
    if ($length <= 0x7F) return chr($length);
	$temp = ltrim(pack('N', $length), chr(0));
    return pack('Ca*', 0x80 | strlen($temp), $temp);
}

function rsa_pkey($exponent, $modulus) {
	$modulus = pack('Ca*a*', 0x02, asn1_length(strlen($modulus)), $modulus);
    $exponent = pack('Ca*a*', 0x02, asn1_length(strlen($exponent)), $exponent);
	$oid = pack('H*', '300d06092a864886f70d0101010500');
	
	$pkey =	$modulus.$exponent;
	$pkey = pack('Ca*a*', 0x30, asn1_length(strlen($pkey)), $pkey);
	$pkey = pack('Ca*', 0x00, $pkey);
	$pkey = pack('Ca*a*', 0x03, asn1_length(strlen($pkey)), $pkey);
	$pkey = $oid.$pkey;
	$pkey = pack('Ca*a*', 0x30, asn1_length(strlen($pkey)), $pkey);
	$pkey = '-----BEGIN PUBLIC KEY-----'."\r\n".chunk_split(base64_encode($pkey)).'-----END PUBLIC KEY-----';
	return $pkey;
}

function rsa_encrypt($message, $e, $n) {
	$exponent = hex2bin($e);
	$modulus = hex2bin($n);
	$pkey = rsa_pkey($exponent, $modulus);
	openssl_public_encrypt($message, $result, $pkey, OPENSSL_PKCS1_PADDING);
	return $result;
}

function curl_parse_cookiefile($file) { 
	$cookies = array(); 
	$aLines = file($file); 
	foreach($aLines as $line){ 
		if('#'==$line{0}) continue; 
		$arr = explode("\t", $line); 
		if(isset($arr[5]) && isset($arr[6])) $cookies[$arr[5]] = trim($arr[6]); 
	}
	return $cookies; 
}

function url_query_parse($query)
{ 
    $queryParts = explode('&', $query); 
    $params = array(); 
    foreach ($queryParts as $param) 
	{ 
        $item = explode('=', $param); 
        $params[$item[0]] = $item[1]; 
    } 
    return $params; 
}

function login($username, $password, $cookiefile) {

	$url = 'http://login.sina.com.cn/sso/prelogin.php?entry=weibo&callback=sinaSSOController.preloginCallBack&su=&rsakt=mod&client=ssologin.js(v1.4.5)&_='.sys_microtime();
	$temp = web_get($url, null, $cookiefile, null);
	$data = jsonp_decode_object($temp);

	$servertime = $data['servertime'];
	$nonce = $data['nonce'];
	$pubkey = $data['pubkey'];
	$rsakv = $data['rsakv'];
	
	$message = $servertime."\t".$nonce."\n".$password;
	$ciphertext = rsa_encrypt($message, "010001", $pubkey);
	$ciphertext_web_safe = bin2hex($ciphertext);

	$data = array(
		'entry'=>'weibo',
		'gateway'=>'1',
		'from'=>'',
		'savestate'=>'7',
		'userticket'=>'1',
		'ssosimplelogin'=>'1',
		'vsnf'=>'1',
		'vsnval'=>'',
		'su'=>base64_encode($username),
		'service'=>'miniblog',
		'servertime'=>$servertime ,
		'nonce'=>$nonce,
		'pwencode'=>'rsa2',
		'sp'=>$ciphertext_web_safe,
		'encoding'=>'UTF-8',
		'url'=>'http://weibo.com/ajaxlogin.php?framelogin=1&callback=parent.sinaSSOController.feedBackUrlCallBack',
		'returntype'=>'META',
		'rsakv' =>$rsakv,
	);

	$temp = web_post('http://login.sina.com.cn/sso/login.php?client=ssologin.js(v1.4.5)', $data, null, $cookiefile, null);

	preg_match('/replace\(\'(.*?)\'\)/', $temp, $matchs);
	$url = $matchs[1];
	$temp = web_get($url, null, $cookiefile, null);
	preg_match('/"uniqueid":"(\d+)"/', $temp, $matchs);
	return $matchs[1];
}

function weibo_publish($content, $cookiefile, $widget = FALSE) {

	if ($widget) { // DEPRECATED
		$url = "http://widget.weibo.com/public/aj_addMblog.php";
		$referer = 'http://widget.weibo.com/dialog/publish.php?button=pubilish&language=zh_cn&refer=1&rnd=1391939263231';
		$data = array(
			'content'=>$content,
			'visible'=>'0',
			'refer'=>'',
			'url'=>'',
			'pic_url'=>'',
			'pic_id'=>'',
			'ext'=>'',
			'vsrc'=>'publish_web',
			'app_src'=>'69yt1V', // 69yt1V 3olT89
			'language'=>'zh_cn',
			'wsrc'=>'app_publish',
			'mid'=>'',
			'_t'=>'0',
		);
	} else {
		$cookies = curl_parse_cookiefile($cookiefile);
		$sup = urldecode($cookies['SUP']);
		$sup = url_query_parse($sup);
		$url = "http://weibo.com/aj/mblog/add?_wv=5&__".sys_microtime();
		$referer = 'http://weibo.com/u/'.$sup['uid'].'/home?topnav=1&wvr=5';
		$data = array(
			'text'=>$content,
			'pic_id'=>'',
			'rank'=>'0',
			'rankid'=>'',
			'_surl'=>'',
			'hottopicid'=>'',
			'location'=>'home',
			'module'=>'stissue',
			'_t'=>'0'
		);
	}
	
	$data = web_post($url, $data, $referer, $cookiefile, array("X-Requested-With: XMLHttpRequest"));
	
	$ret = json_decode ($data , true);
	if ($ret['code'] == '100000') {
		return TRUE;
	} else {
		return $data;
	}
}

function weibo_get_image_url($pid) {
	$zone = 0;
	$pid_zone = crc32 ($pid);
	$type = 'large'; //bmiddle
	if ($pid[9] == 'w') {
		$zone = ($pid_zone & 3) + 1;
		$ext = ($pid[21] == 'g') ? 'gif' : 'jpg';
		$url = 'http://ww'.$zone.'.sinaimg.cn/'.$type.'/'.$pid.'.'.$ext;
	} else {
		$zone = (hexdec(substr($pid, -2)) & 0xf) + 1;
		$url = 'http://ss'.$zone.'.sinaimg.cn/'.$type.'/'.$pid.'&690';
	}
	return $url;
}

function weibo_upload_image($data, $mime, $cookiefile) {
	$cookies = curl_parse_cookiefile($cookiefile);
	$sup = urldecode($cookies['SUP']);
	$sup = url_query_parse($sup);
    $url = "http://picupload.service.weibo.com/interface/pic_upload.php?&mime=".$mime."&data=1&url=0&markpos=1&logo=&nick=0&marks=1&app=miniblog";
	$referer = 'http://js.t.sinajs.cn/t5/home/static/swf/MultiFilesUpload.swf?version=27f562792e3b5f71';
	$data = web_post($url, $data, $referer, $cookiefile, array("X-Requested-With: XMLHttpRequest", 'Content-Type: application/octet-stream'));
	
	if (substr($data, 0, 139) != '<meta http-equiv="Content-Type" content="text/html; charset=utf-8" /><script type="text/javascript">document.domain="sina.com.cn";</script>') {
		return 'failed:'."\r\n".$data;
	} else {
		$data = substr($data, 139);
		$ret = json_decode ($data , true);
		if ($ret['code'] == 'A00006') {
			$pid = $ret['data']['pics']['pic_1']['pid'];
			return $pid;
		} else {
			return 'failed:'."\r\n".$data;
		}
	}
}