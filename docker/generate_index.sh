#!/bin/bash
#
#  Title:  generate_index.sh
#  Author: Shuichiro Endo
#

set -e

# clear
echo '' > /var/www/html/index.html

# make html
echo '
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>socks5-nginx-module test</title>
</head>

<body bgcolor="#181818">
<span style="font-family:monospace;font-size:14px;line-height:1.1ex;color:#c0c0c0;">
<pre>

' >> /var/www/html/index.html

echo "I &#9829; socks5" | /usr/games/cowsay -f $(ls /usr/share/cowsay/cows | shuf -n 1) | sed -z 's/\n/<br>\n/g'  >> /var/www/html/index.html

echo '

</pre>
</span>
</body>
</html>
' >> /var/www/html/index.html
