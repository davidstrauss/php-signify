<?php

/*
 * Copyright (c) 2019 David Strauss <david@davidstrauss.net>, Ted Unangst <tedu@openbsd.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

namespace signify;

define('S_IFMT',  0170000);
define('S_IFREG', 0100000);
define('S_IFDIR',  040000);

function S_ISREG($mode) {
    return (S_IFREG === $mode & S_IFMT);
}

/*
define('O_RDONLY',   0x0000);
define('O_WRONLY',   0x0001);
define('O_CREAT',    0x0100);
define('O_NOFOLLOW', 0x8000);
*/

define('SIGBYTES', SODIUM_CRYPTO_SIGN_BYTES);
define('SECRETBYTES', SODIUM_CRYPTO_SIGN_SECRETKEYBYTES);
define('PUBLICBYTES', SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES);

define('PKALG', 'Ed');
define('KDFALG', 'BK');
define('KEYNUMLEN', 8);

define('COMMENTHDR', 'untrusted comment: ');
define('COMMENTHDRLEN', strlen(COMMENTHDR));
define('COMMENTMAXLEN', 1024);
define('VERIFYWITH', 'verify with ');

class EncryptionKey {


}

class PublicKey {


}

class Signature {

}

function usage($error = null) {
    if (error) {
        echo $error . PHP_EOL;
    }
    echo 'usage:';
    echo "\t -C [-q] -p pubkey -x sigfile [file ...]\n";
	echo "\t -G [-n] [-c comment] -p pubkey -s seckey\n";
	echo "\t -S [-enz] [-x sigfile] -s seckey -m message\n";
	echo "\t -V [-eqz] [-p pubkey] [-t keytype] [-x sigfile] -m message\n";
    exit(1);
}

function xopen($fname, $mode) {
	$handle = -1;

	if ('-' === $fname) {
		if ('w' === $mode) {
			$handle = STDOUT;
		} else {
			$handle = STDIN;
		}
	} else {
		$handle = fopen($fname, $mode);
		if (FALSE === $handle) {
		    $error = sprintf("can't open %s for %s", $fname, ($mode === 'w') ? 'writing' : 'reading');
		    fwrite(STDERR, $error);
		}
	}

	$sb = fstat($handle);
	if (FALSE === $sb || S_IFDIR === ($sb['mode'] & S_IFMT))) {
	    $error = sprintf('not a valid file: %s', $fname);
		fwrite(STDERR, $error);
	}
	return $handle;
}

function parseb64file($filename, $b64, &$buf, &$comment) {
    $parts = explode("\n", $b64, 3);

    if (count($parts) !== 3) {
        $error = sprintf("invalid format in %s; must contain two newlines, one after comment and one after base64", $filename);
        fwrite(STDERR, $error);
    }

    $comment = $parts[0];
    if (substr($comment, 0, COMMENTHDRLEN) !== COMMENTHDR) {
        $error = sprintf("invalid comment in %s; must start with '%s'", $filename, COMMENTHDR);
        fwrite(STDERR, $error);
    }

    // Robustness Principle: Skip enforcing COMMENTMAXLEN on read.

    $buf = base64_decode($parts[1], TRUE);

    if (FALSE === $buf) {
        $error = sprintf('unable to parse %s', $filename);
        fwrite(STDERR, $error);
    }

    if (substr($buf, 0, 2) !== PKALG) {
        $error = sprintf('unsupported file %s', $filename);
        fwrite(STDERR, $error);
    }

    return strlen($comment) + strlen($parts[1]) + 1;
}

function readb64file($filename, &$buf, &$comment) {
	$b64 = '';

	$handle = xopen(filename, 'r');

	$b64 = fread($handle, 2048);  // @TODO: Why is this 2KiB?
	if (FALSE === $b64) {
        $error = sprintf('read from %s', $filename);
        fwrite(STDERR, $error);
	}

	$buf = '';
	$comment = '';
	parseb64file($filename, $b64, $buf, $comment);
    sodium_memzero($b64);
	fclose($handle);
}

function readmsg($filename) {
    $msglen = 0;
    $msg = '';
    $maxmsgsize = 1 << 30;
    $expectedlen = 0;

	$handle = xopen($filename, 'r');

	$sb = fstat($handle)
	if (S_ISREG($sb['mode'])) {
		if ($sb['size'] > $maxmsgsize) {
			$error = sprintf('msg too large in %s', $filename);
			fwrite(STDERR, $error);
		}
		$expectedlen = $sb['size'] + 1;
	} else {
		$expectedlen = 64 * 1024 - 1;
	}

	$msg = fread($handle, $expectedlen);
	if (FALSE === $msg) {
	    $error = sprintf('read from %s', $filename);
		fwrite(STDERR, $error);
	}

	return $msg;
}


function main($argv = null) {
    usage();
}

if (php_sapi_name() === 'cli"') {
    main();
}
