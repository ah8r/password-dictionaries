<?php

define('DICTCLEAN_VERSION', '0.2');

#
# 1. Options
#
$options = getopt('', array(
	'help',
	'list-encodings',
	'encoding:',
	'max-length:',
	'convert-html-entities',
	'remove-html',
	'remove-emails',
	'remove-urls',
	'dictfile:',
	'cleanfile:',
	'dirtyfile:'
));

# --help
if (isset($options['help'])) {
	echo 'dictclean ', DICTCLEAN_VERSION, ", T. Alexander Lystad <tal@lystadonline.no> (www.thepasswordproject.com), Adrian Hayter <adrianhayter@gmail.com> (cryptogasm.com)

Usage on Windows: php -f dictclean.php -- [switches]
Usage on Linux: ./dictclean.php -- [switches]

Example use on Windows: php -f dictclean.php -- --dictfile rockyou.txt --cleanfile rockyou.clean.txt
Example use on Linux: ./dictclean.php -- --dictfile rockyou.txt --cleanfile rockyou.clean.txt

Switches:
--help \t\t\t Show help
--list-encodings \t List available encodings
--encoding \t\t The encoding you want to check for. Must be listed in --list-encodings. Defaults to UTF-8. Example: --encoding ISO-8859-1
--max-length \t\t The maximum password length to allow. Passwords longer than this length will be removed.
--convert-html-entities\t Convert detected HTML entities into regular characters (e.g. &gt; to >), otherwise passwords containing them will be removed.
--remove-html \t\t Remove passwords containing valid HTML. This method may cause some false positives. Always check the removed passwords manually!
--remove-emails \t Remove passwords containing emails.
--remove-urls \t\t Remove passwords containing URLs.
--dictfile \t\t The file to analyze. Example: --dictfile dictfile.txt
--cleanfile \t\t Generate cleaned up dictfile. All lines from dictfile with valid encoding will be written to this file. Example: --cleanfile cleandict.txt
--dirtyfile \t\t Generate dirty dictfile. All lines from dictfile with invalid encoding will be written to this file. Example: --dirtyfile dirtydict.txt";
	exit;
}

# --list-encodings
if (isset($options['list-encodings'])) {
	echo 'Available encodings on your system: ', "\n", implode("\n", mb_list_encodings());
	exit;
}

# --encoding
if (isset($options['encoding'])) {
	define('WANTED_ENCODING', 'UTF-8');
}

if (!defined('WANTED_ENCODING')) {
	define('WANTED_ENCODING', 'UTF-8');
}

# --max-length
if (isset($options['max-length']))
{
	define('MAX_LENGTH', intval($options['max-length']));
}

# --convert-html-entities
if (isset($options['convert-html-entities']))
{
	define('CONVERT_HTML_ENTITIES', true);
}
else
{
	define('CONVERT_HTML_ENTITIES', false);
}

# --remove-html
if (isset($options['remove-html']))
{
	define('REMOVE_HTML', true);
}
else
{
	define('REMOVE_HTML', false);
}

# --remove-emails
if (isset($options['remove-emails']))
{
	define('REMOVE_EMAILS', true);
}
else
{
	define('REMOVE_EMAILS', false);
}

# --remove-urls
if (isset($options['remove-urls']))
{
	define('REMOVE_URLS', true);
}
else
{
	define('REMOVE_URLS', false);
}

# --dictfile
if (isset($options['dictfile'])) {
	define('DICTIONARY_FILE', $options['dictfile']);
}

if (!defined('DICTIONARY_FILE')) {
	echo 'You have to specify the file you want to analyze. Example: --dictfile dictionary.txt', "\n";
	exit;
}
if (!is_readable(DICTIONARY_FILE)) {
	echo 'Could not read file \'', DICTIONARY_FILE, '\'. Please specify a correct path for the file you want to analyze.', "\n";
	exit;
}

# --cleanfile
if (isset($options['cleanfile'])) {
	$cleanHandle = fopen($options['cleanfile'], 'w');
}

if (isset($options['dirtyfile'])) {
	$dirtyHandle = fopen($options['dirtyfile'], 'w');
}




#
# 2. Meat
#	
echo 'dictclean ', DICTCLEAN_VERSION, ' report (www.thepasswordproject.com)', "\n\n";
$invalidCount = 0;
$lineCount = 1;
$inHandle = fopen(DICTIONARY_FILE, 'r');
while (($line = fgets($inHandle)) !== false)
{
	// Trim line of \n \t and \r.
	$line = trim($line, "\n\t\r");

	$clean = true;
	
	// Convert or remove passwords with HTML entities.
	if ($clean)
	{
		if (strlen(html_entity_decode($line, ENT_QUOTES)) != strlen($line))
		{
			if (CONVERT_HTML_ENTITIES)
			{
				$line2 = html_entity_decode($line, ENT_QUOTES);
				echo 'Line ', $lineCount, ': Converted ', $line, ' to ', $line2, "\n";
				$line = $line2;
			}
			else
			{
				$clean = false;
				$detectedString = 'HTML entities detected';
			}
		}
	}
	
	// Remove passwords that contain HTML.
	if (REMOVE_HTML && $clean)
	{
		if (preg_match('#</?(!--|!doctype|a|abbr|acronym|address|applet|area|article|aside|audio|b|base|basefont|bdi|bdo|big|blockquote|body|br|button|canvas|caption|center|cite|code|col|colgroup|command|datalist|dd|del|details|dfn|dir|div|dl|dt|em|embed|fieldset|figcaption|figure|font|footer|form|frame|frameset|h1|h2|h3|h4|h5|h6|h7|head|header|hgroup|hr|html|i|iframe|img|input|ins|isindex|keygen|kbd|label|legend|li|link|map|mark|menu|meta|meter|nav|noframes|noscript|object|ol|optgroup|option|output|p|param|pre|progress|q|rp|rt|ruby|s|samp|script|section|select|small|source|span|strike|strong|style|sub|summary|sup|table|tbody|td|textarea|tfoot|th|thead|time|title|tr|track|tt|u|ul|var|video|wbr)( (?=[^<]*?)>?|/?>)#i', $line))
		{
			$clean = false;
			$detectedString = 'HTML detected';
		}
	}
	
	// Remove passwords with invalid encoding.
	if ($clean && !mb_check_encoding($line, WANTED_ENCODING))
	{
		$clean = false;
		
		$detectedEncoding = mb_detect_encoding($line, null, true);
		if ($detectedEncoding)
		{
			$detectedString = $detectedEncoding.' encoding was detected';
		}
		else
		{
			$detectedString = 'Encoding could not be detected';
		}
	}
	
	// Remove passwords longer than a specified maximum length.
	if (defined('MAX_LENGTH') && $clean)
	{
		if (strlen($line) > MAX_LENGTH)
		{
			$clean = false;
			$detectedString = 'Length exceeds ' . MAX_LENGTH . ' characters';
		}
	}
	
	// Remove passwords containing emails.
	if (REMOVE_EMAILS && $clean)
	{
		if (preg_match("#[a-z0-9\._-]+@([a-z0-9_-]\.)*[a-z0-9-]+\.[a-z]+(\.[a-z]+)?#i", $line))
		{
			$clean = false;
			$detectedString = 'Email detected';
		}
	}
	
	// Remove passwords containing URLs.
	if (REMOVE_URLS && $clean)
	{
		if (preg_match("#\b(([\w-]+://?|www[.])[^\s()<>]+(?:\([\w\d]+\)|([^[:punct:]\s]|/)))#i", $line))
		{
			$clean = false;
			$detectedString = 'URL detected';
		}
	}
	
	if ($clean)
	{
		if (strlen($line) > 0)
		{
			if (isset($cleanHandle))
			{
				fwrite($cleanHandle, $line . "\n");
			}
		}
		else
		{
			echo 'Error on line ', $lineCount, ': ', '(Empty String)', "\n";
			$invalidCount++;
		}
	}
	else
	{
		if (isset($dirtyHandle))
		{
			fwrite($dirtyHandle, $line . "\n");
		}
		
		echo 'Error on line ', $lineCount, ': \'', trim($line), '\' (', $detectedString, ')', "\n";
		$invalidCount++;
	}
	
	$lineCount++;
}
echo 'Lines with invalid passwords: ', $invalidCount, '/', $lineCount, ' (', round(($invalidCount/$lineCount)*100, 4), ' %)', "\n";