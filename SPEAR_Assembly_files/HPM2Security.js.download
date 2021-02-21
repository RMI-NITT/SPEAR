/**
 * This file combines 7 separated files includes:
 * Hosted/lite/js/pidcrypt.js
 * Hosted/lite/js/pidcrypt_util.js
 * Hosted/lite/js/asn1.js
 * Hosted/lite/js/jsbn.js
 * Hosted/lite/js/rng.js
 * Hosted/lite/js/prng4.js
 * Hosted/lite/js/rsa.js
 * 
 * If you only want to affect the HPM 1.0 and HPM lite version1, 
 * you should modify the files in path Hosted/lite/js/
 * If you only want to affect HPM 2.0 lite version 2,
 * you should modify code here.
 */ 

//HPM Security pidcrypt.js
/*!Copyright (c) 2009 pidder <www.pidder.com>*/
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU General Public License as
// published by the Free Software Foundation; either version 2 of the
// License, or (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program; if not, write to the Free Software
// Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA
// 02111-1307 USA or check at http://www.gnu.org/licenses/gpl.html

/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -  */
/* pidCrypt is pidders JavaScript Crypto Library - www.pidder.com/pidcrypt
 * Version 0.04, 10/2009

 *
 * pidCrypt is a combination of different JavaScript functions for client side
 * encryption technologies with enhancements for openssl compatibility cast into
 * a modular class concept.
 *
 * Client side encryption is a must have for developing host proof applications:
 * There must be no knowledge of the clear text data at the server side, all
 * data is enrycpted prior to being submitted to the server.
 * Client side encryption is mandatory for protecting the privacy of the users.
 * "Dont't trust us, check our source code!"
 *
 * "As a cryptography and computer security expert, I have never understood
 * the current fuss about the open source software movement. In the
 * cryptography world, we consider open source necessary for good security;
 * we have for decades. Public security is always more secure than proprietary
 * security. It's true for cryptographic algorithms, security protocols, and
 * security source code. For us, open source isn't just a business model;
 * it's smart engineering practice."
 * Bruce Schneier, Crypto-Gram 1999/09/15
 * copied form keepassx site - keepassx is a cross plattform password manager
 *
 * pidCrypt comes with modules under different licenses and copyright terms.
 * Make sure that you read and respect the individual module license conditions
 * before using it.
 *
 * The pidCrypt base library contains:
 * 1. pidcrypt.js
 *    class pidCrypt: the base class of the library
 * 2. pidcrypt_util.js
 *    base64 en-/decoding as new methods of the JavaScript String class
 *    UTF8 en-/decoding as new methods of the JavaScript String class
 *    String/HexString conversions as new methods of the JavaScript String class
 *
 * The pidCrypt v0.01 modules and the original authors (see files for detailed
 * copyright and license terms) are:
 *
 * - md5.js:      MD5 (Message-Digest Algorithm), www.webtoolkit.info
 * - aes_core.js: AES (Advanced Encryption Standard ) Core algorithm, B. Poettering
 * - aes-ctr.js:  AES CTR (Counter) Mode, Chis Veness
 * - aes-cbc.js:  AES CBC (Cipher Block Chaining) Mode, pidder
 * - jsbn.js:     BigInteger for JavaScript, Tom Wu
 * - prng.js:     PRNG (Pseudo-Random Number Generator), Tom Wu
 * - rng.js:      Random Numbers, Tom Wu
 * - rsa.js:      RSA (Rivest, Shamir, Adleman Algorithm), Tom Wu
 * - oids.js:     oids (Object Identifiers found in ASN.1), Peter Gutmann
 * - asn1.js:     ASN1 (Abstract Syntax Notation One) parser, Lapo Luchini
 * - sha256.js    SHA-256 hashing, Angel Marin 
 * - sha2.js:     SHA-384 and SHA-512 hashing, Brian Turek
 *
 * IMPORTANT:
 * Please report any bugs at http://sourceforge.net/projects/pidcrypt/
 * Vist http://www.pidder.com/pidcrypt for online demo an documentation
 */
/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -  */

function pidCrypt(){
  //TODO: better radomness!
  function getRandomBytes(len){
    if(!len) len = 8;
    var bytes = new Array(len);
    var field = [];
    for(var i=0;i<256;i++) field[i] = i;
    for(i=0;i<bytes.length;i++)
      bytes[i] = field[Math.floor(Math.random()*field.length)];
    return bytes
  }

  this.setDefaults = function(){
     this.params.nBits = 256;
  //salt should always be a Hex String e.g. AD0E76FF6535AD...
     this.params.salt = getRandomBytes(8);
     this.params.salt = pidCryptUtil.byteArray2String(this.params.salt);
     this.params.salt = pidCryptUtil.convertToHex(this.params.salt);
     this.params.blockSize = 16;
     this.params.UTF8 = true;
     this.params.A0_PAD = true;
  }

  this.debug = true;
  this.params = {};
  //setting default values for params
  this.params.dataIn = '';
  this.params.dataOut = '';
  this.params.decryptIn = '';
  this.params.decryptOut = '';
  this.params.encryptIn = '';
  this.params.encryptOut = '';
  //key should always be a Hex String e.g. AD0E76FF6535AD...
  this.params.key = '';
  //iv should always be a Hex String e.g. AD0E76FF6535AD...
  this.params.iv = '';
  this.params.clear = true;
  this.setDefaults();
  this.errors = '';
  this.warnings = '';
  this.infos = '';
  this.debugMsg = '';
  //set and get methods for base class
  this.setParams = function(pObj){
    if(!pObj) pObj = {};
    for(var p in pObj)
      this.params[p] = pObj[p];
  }
  this.getParams = function(){
    return this.params;
  }
  this.getParam = function(p){
    return this.params[p] || '';
  }
  this.clearParams = function(){
      this.params= {};
  }
  this.getNBits = function(){
    return this.params.nBits;
  }
  this.getOutput = function(){
    return this.params.dataOut;
  }
  this.setError = function(str){
    this.error = str;
  }
  this.appendError = function(str){
    this.errors += str;
    return '';
  }
  this.getErrors = function(){
    return this.errors;
  }
  this.isError = function(){
    if(this.errors.length>0)
      return true;
    return false
  }
  this.appendInfo = function(str){
    this.infos += str;
    return '';
  }
  this.getInfos = function()
  {
    return this.infos;
  }
  this.setDebug = function(flag){
    this.debug = flag;
  }
  this.appendDebug = function(str)
  {
    this.debugMsg += str;
    return '';
  }
  this.isDebug = function(){
    return this.debug;
  }
  this.getAllMessages = function(options){
    var defaults = {lf:'\n',
                    clr_mes: false,
                    verbose: 15//verbose level bits = 1111
        };
    if(!options) options = defaults;
    for(var d in defaults)
      if(typeof(options[d]) == 'undefined') options[d] = defaults[d];
    var mes = '';
    var tmp = '';
    for(var p in this.params){
      switch(p){
        case 'encryptOut':
          tmp = pidCryptUtil.toByteArray(this.params[p].toString());
          tmp = pidCryptUtil.fragment(tmp.join(),64, options.lf)
          break;
        case 'key': 
        case 'iv':
          tmp = pidCryptUtil.formatHex(this.params[p],48);
          break;
        default:
          tmp = pidCryptUtil.fragment(this.params[p].toString(),64, options.lf);
      }  
      mes += '<p><b>'+p+'</b>:<pre>' + tmp + '</pre></p>';
    }  
    if(this.debug) mes += 'debug: ' + this.debug + options.lf;
    if(this.errors.length>0 && ((options.verbose & 1) == 1)) mes += 'Errors:' + options.lf + this.errors + options.lf;
    if(this.warnings.length>0 && ((options.verbose & 2) == 2)) mes += 'Warnings:' +options.lf + this.warnings + options.lf;
    if(this.infos.length>0 && ((options.verbose & 4) == 4)) mes += 'Infos:' +options.lf+ this.infos + options.lf;
    if(this.debug && ((options.verbose & 8) == 8)) mes += 'Debug messages:' +options.lf+ this.debugMsg + options.lf;
    if(options.clr_mes)
      this.errors = this.infos = this.warnings = this.debug = '';
    return mes;
  }
  this.getRandomBytes = function(len){
    return getRandomBytes(len);
  }
  //TODO warnings
}



//HPM Security pidcrypt_util.js
/*----------------------------------------------------------------------------*/
// Copyright (c) 2009 pidder <www.pidder.com>
// Permission to use, copy, modify, and/or distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice appear in all copies.
//
// THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
// WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
// ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
// WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
// ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
// OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
/*----------------------------------------------------------------------------*/
/*  (c) Chris Veness 2005-2008
* You are welcome to re-use these scripts [without any warranty express or
* implied] provided you retain my copyright notice and when possible a link to
* my website (under a LGPL license). §ection numbers relate the code back to
* sections in the standard.
/*----------------------------------------------------------------------------*/
/* Helper methods (base64 conversion etc.) needed for different operations in
* encryption.

/*----------------------------------------------------------------------------*/
/* Intance methods extanding the String object                                */
/*----------------------------------------------------------------------------*/
/**
* Encode string into Base64, as defined by RFC 4648 [http://tools.ietf.org/html/rfc4648]
* As per RFC 4648, no newlines are added.
*
* @param utf8encode optional parameter, if set to true Unicode string is
*                   encoded into UTF-8 before conversion to base64;
*                   otherwise string is assumed to be 8-bit characters
* @return coded     base64-encoded string
*/
pidCryptUtil = {};
pidCryptUtil.encodeBase64 = function(str,utf8encode) {  // http://tools.ietf.org/html/rfc4648
 if(!str) str = "";
 var b64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
 utf8encode =  (typeof utf8encode == 'undefined') ? false : utf8encode;
 var o1, o2, o3, bits, h1, h2, h3, h4, e=[], pad = '', c, plain, coded;

 plain = utf8encode ? pidCryptUtil.encodeUTF8(str) : str;

 c = plain.length % 3;  // pad string to length of multiple of 3
 if (c > 0) { while (c++ < 3) { pad += '='; plain += '\0'; } }
 // note: doing padding here saves us doing special-case packing for trailing 1 or 2 chars

 for (c=0; c<plain.length; c+=3) {  // pack three octets into four hexets
   o1 = plain.charCodeAt(c);
   o2 = plain.charCodeAt(c+1);
   o3 = plain.charCodeAt(c+2);

   bits = o1<<16 | o2<<8 | o3;

   h1 = bits>>18 & 0x3f;
   h2 = bits>>12 & 0x3f;
   h3 = bits>>6 & 0x3f;
   h4 = bits & 0x3f;

   // use hextets to index into b64 string
   e[c/3] = b64.charAt(h1) + b64.charAt(h2) + b64.charAt(h3) + b64.charAt(h4);
 }
 coded = e.join('');  // join() is far faster than repeated string concatenation

 // replace 'A's from padded nulls with '='s
 coded = coded.slice(0, coded.length-pad.length) + pad;
 return coded;
}

/**
* Decode string from Base64, as defined by RFC 4648 [http://tools.ietf.org/html/rfc4648]
* As per RFC 4648, newlines are not catered for.
*
* @param utf8decode optional parameter, if set to true UTF-8 string is decoded
*                   back into Unicode after conversion from base64
* @return           decoded string
*/
pidCryptUtil.decodeBase64 = function(str,utf8decode) {
 if(!str) str = "";
 var b64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
 utf8decode =  (typeof utf8decode == 'undefined') ? false : utf8decode;
 var o1, o2, o3, h1, h2, h3, h4, bits, d=[], plain, coded;

 coded = utf8decode ? pidCryptUtil.decodeUTF8(str) : str;

 for (var c=0; c<coded.length; c+=4) {  // unpack four hexets into three octets
   h1 = b64.indexOf(coded.charAt(c));
   h2 = b64.indexOf(coded.charAt(c+1));
   h3 = b64.indexOf(coded.charAt(c+2));
   h4 = b64.indexOf(coded.charAt(c+3));

   bits = h1<<18 | h2<<12 | h3<<6 | h4;

   o1 = bits>>>16 & 0xff;
   o2 = bits>>>8 & 0xff;
   o3 = bits & 0xff;

   d[c/4] = String.fromCharCode(o1, o2, o3);
   // check for padding
   if (h4 == 0x40) d[c/4] = String.fromCharCode(o1, o2);
   if (h3 == 0x40) d[c/4] = String.fromCharCode(o1);
 }
 plain = d.join('');  // join() is far faster than repeated string concatenation

 plain = utf8decode ? pidCryptUtil.decodeUTF8(plain) : plain

 return plain;
}

/**
* Encode multi-byte Unicode string into utf-8 multiple single-byte characters
* (BMP / basic multilingual plane only)
*
* Chars in range U+0080 - U+07FF are encoded in 2 chars, U+0800 - U+FFFF in 3 chars
*
* @return encoded string
*/
pidCryptUtil.encodeUTF8 = function(str) {
 if(!str) str = "";
 // use regular expressions & String.replace callback function for better efficiency
 // than procedural approaches
 str = str.replace(
     /[\u0080-\u07ff]/g,  // U+0080 - U+07FF => 2 bytes 110yyyyy, 10zzzzzz
     function(c) {
       var cc = c.charCodeAt(0);
       return String.fromCharCode(0xc0 | cc>>6, 0x80 | cc&0x3f); }
   );
 str = str.replace(
     /[\u0800-\uffff]/g,  // U+0800 - U+FFFF => 3 bytes 1110xxxx, 10yyyyyy, 10zzzzzz
     function(c) {
       var cc = c.charCodeAt(0);
       return String.fromCharCode(0xe0 | cc>>12, 0x80 | cc>>6&0x3F, 0x80 | cc&0x3f); }
   );
 return str;
}

//If you encounter problems with the UTF8 encode function (e.g. for use in a
//Firefox) AddOn) you can use the following instead.
//code from webtoolkit.com

//pidCryptUtil.encodeUTF8 = function(str) {
//		str = str.replace(/\r\n/g,"\n");
//		var utftext = "";
//
//		for (var n = 0; n < str.length; n++) {
//
//			var c = str.charCodeAt(n);
//
//			if (c < 128) {
//				utftext += String.fromCharCode(c);
//			}
//			else if((c > 127) && (c < 2048)) {
//				utftext += String.fromCharCode((c >> 6) | 192);
//				utftext += String.fromCharCode((c & 63) | 128);
//			}
//			else {
//				utftext += String.fromCharCode((c >> 12) | 224);
//				utftext += String.fromCharCode(((c >> 6) & 63) | 128);
//				utftext += String.fromCharCode((c & 63) | 128);
//			}
//
//		}
//
// return utftext;
//}



/**
* Decode utf-8 encoded string back into multi-byte Unicode characters
*
* @return decoded string
*/
pidCryptUtil.decodeUTF8 = function(str) {
 if(!str) str = "";
 str = str.replace(
     /[\u00c0-\u00df][\u0080-\u00bf]/g,                 // 2-byte chars
     function(c) {  // (note parentheses for precence)
       var cc = (c.charCodeAt(0)&0x1f)<<6 | c.charCodeAt(1)&0x3f;
       return String.fromCharCode(cc); }
   );
 str = str.replace(
     /[\u00e0-\u00ef][\u0080-\u00bf][\u0080-\u00bf]/g,  // 3-byte chars
     function(c) {  // (note parentheses for precence)
       var cc = ((c.charCodeAt(0)&0x0f)<<12) | ((c.charCodeAt(1)&0x3f)<<6) | ( c.charCodeAt(2)&0x3f);
       return String.fromCharCode(cc); }
   );
 return str;
}

//If you encounter problems with the UTF8 decode function (e.g. for use in a
//Firefox) AddOn) you can use the following instead.
//code from webtoolkit.com

//pidCryptUtil.decodeUTF8 = function(utftext) {
//   var str = "";
//		var i = 0;
//		var c = 0;
//   var c1 = 0;
//   var c2 = 0;
//
//		while ( i < utftext.length ) {
//
//			c = utftext.charCodeAt(i);
//
//			if (c < 128) {
//				str += String.fromCharCode(c);
//				i++;
//			}
//			else if((c > 191) && (c < 224)) {
//				c1 = utftext.charCodeAt(i+1);
//				str += String.fromCharCode(((c & 31) << 6) | (c1 & 63));
//				i += 2;
//			}
//			else {
//				c1 = utftext.charCodeAt(i+1);
//				c2 = utftext.charCodeAt(i+2);
//				str += String.fromCharCode(((c & 15) << 12) | ((c1 & 63) << 6) | (c2 & 63));
//				i += 3;
//			}
//
//		}
//
//
// return str;
//}




/**
* Converts a string into a hexadecimal string
* returns the characters of a string to their hexadecimal charcode equivalent
* Works only on byte chars with charcode < 256. All others chars are converted
* into "xx"
*
* @return hex string e.g. "hello world" => "68656c6c6f20776f726c64"
*/
pidCryptUtil.convertToHex = function(str) {
 if(!str) str = "";
 var hs ='';
 var hv ='';
 for (var i=0; i<str.length; i++) {
   hv = str.charCodeAt(i).toString(16);
   hs += (hv.length == 1) ? '0'+hv : hv;
 }
 return hs;
}

/**
* Converts a hex string into a string
* returns the characters of a hex string to their char of charcode
*
* @return hex string e.g. "68656c6c6f20776f726c64" => "hello world"
*/
pidCryptUtil.convertFromHex = function(str){
 if(!str) str = "";
 var s = "";
 for(var i= 0;i<str.length;i+=2){
   s += String.fromCharCode(parseInt(str.substring(i,i+2),16));
 }
 return s
}

/**
* strips off all linefeeds from a string
* returns the the strong without line feeds
*
* @return string
*/
pidCryptUtil.stripLineFeeds = function(str){
 if(!str) str = "";
// var re = RegExp(String.fromCharCode(13),'g');//\r
// var re = RegExp(String.fromCharCode(10),'g');//\n
 var s = '';
 s = str.replace(/\n/g,'');
 s = s.replace(/\r/g,'');
 return s;
}

/**
* Converts a string into an array of char code bytes
* returns the characters of a hex string to their char of charcode
*
* @return hex string e.g. "68656c6c6f20776f726c64" => "hello world"
*/
pidCryptUtil.toByteArray = function(str){
 if(!str) str = "";
 var ba = [];
 for(var i=0;i<str.length;i++)
    ba[i] = str.charCodeAt(i);

 return ba;
}


/**
* Fragmentize a string into lines adding a line feed (lf) every length
* characters
*
* @return string e.g. length=3 "abcdefghi" => "abc\ndef\nghi\n"
*/
pidCryptUtil.fragment = function(str,length,lf){
 if(!str) str = "";
 if(!length || length>=str.length) return str;
 if(!lf) lf = '\n'
 var tmp='';
 for(var i=0;i<str.length;i+=length)
   tmp += str.substr(i,length) + lf;
 return tmp;
}

/**
* Formats a hex string in two lower case chars + : and lines of given length
* characters
*
* @return string e.g. "68656C6C6F20" => "68:65:6c:6c:6f:20:\n"
*/
pidCryptUtil.formatHex = function(str,length){
 if(!str) str = "";
   if(!length) length = 45;
   var str_new='';
   var j = 0;
   var hex = str.toLowerCase();
   for(var i=0;i<hex.length;i+=2)
     str_new += hex.substr(i,2) +':';
   hex = this.fragment(str_new,length);

 return hex;
}


/*----------------------------------------------------------------------------*/
/* End of intance methods of the String object                                */
/*----------------------------------------------------------------------------*/

pidCryptUtil.byteArray2String = function(b){
// var out ='';
 var s = '';
 for(var i=0;i<b.length;i++){
    s += String.fromCharCode(b[i]);
//    out += b[i]+':';
 }
// alert(out);
 return s;
}


//HPM Security asn1.js

/*----------------------------------------------------------------------------*/
// Copyright (c) 2009 pidder <www.pidder.com>
// Permission to use, copy, modify, and/or distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice appear in all copies.
//
// THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
// WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
// ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
// WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
// ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
// OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
/*----------------------------------------------------------------------------*/
/*
*  ASN1 parser for use in pidCrypt Library
*  The pidCrypt ASN1 parser is based on the implementation
*  by Lapo Luchini 2008-2009. See http://lapo.it/asn1js/ for details and
*  for his great job.
*
*  Depends on pidCrypt (pcrypt.js & pidcrypt_util).
*  For supporting Object Identifiers found in ASN.1 structure you must
*  include oids (oids.js).
*  But be aware that oids.js is really big (~> 1500 lines).
*/
/*----------------------------------------------------------------------------*/
//ASN.1 JavaScript decoder
//Copyright (c) 2008-2009 Lapo Luchini <lapo@lapo.it>

//Permission to use, copy, modify, and/or distribute this software for any
//purpose with or without fee is hereby granted, provided that the above
//copyright notice and this permission notice appear in all copies.
//
//THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
//WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
//MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
//ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
//WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
//ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
//OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
/*----------------------------------------------------------------------------*/

function Stream(enc, pos) {
 if (enc instanceof Stream) {
   this.enc = enc.enc;
   this.pos = enc.pos;
 } else {
   this.enc = enc;
   this.pos = pos;
 }
}

//pidCrypt extensions start
//hex string
Stream.prototype.parseStringHex = function(start, end) {
 if(typeof(end) == 'undefined') end = this.enc.length;
 var s = "";
 for (var i = start; i < end; ++i) {
   var h = this.get(i);
   s += this.hexDigits.charAt(h >> 4) + this.hexDigits.charAt(h & 0xF);
 }
 return s;
}
//pidCrypt extensions end

Stream.prototype.get = function(pos) {
 if (pos == undefined)
	  pos = this.pos++;
 if (pos >= this.enc.length)
	  throw 'Requesting byte offset ' + pos + ' on a stream of length ' + this.enc.length;

 return this.enc[pos];
}
Stream.prototype.hexDigits = "0123456789ABCDEF";
Stream.prototype.hexDump = function(start, end) {
 var s = "";
 for (var i = start; i < end; ++i) {
   var h = this.get(i);
   s += this.hexDigits.charAt(h >> 4) + this.hexDigits.charAt(h & 0xF);
   if ((i & 0xF) == 0x7)
     s += ' ';
   s += ((i & 0xF) == 0xF) ? '\n' : ' ';
 }

 return s;
}
Stream.prototype.parseStringISO = function(start, end) {
 var s = "";
 for (var i = start; i < end; ++i)
	  s += String.fromCharCode(this.get(i));

 return s;
}
Stream.prototype.parseStringUTF = function(start, end) {
 var s = "", c = 0;
 for (var i = start; i < end; ) {
	  var c = this.get(i++);
	  if (c < 128)
	    s += String.fromCharCode(c);
   else
     if ((c > 191) && (c < 224))
       s += String.fromCharCode(((c & 0x1F) << 6) | (this.get(i++) & 0x3F));
     else
       s += String.fromCharCode(((c & 0x0F) << 12) | ((this.get(i++) & 0x3F) << 6) | (this.get(i++) & 0x3F));
	//TODO: this doesn't check properly 'end', some char could begin before and end after
 }
 return s;
}
Stream.prototype.reTime = /^((?:1[89]|2\d)?\d\d)(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])([01]\d|2[0-3])(?:([0-5]\d)(?:([0-5]\d)(?:[.,](\d{1,3}))?)?)?(Z|[-+](?:[0]\d|1[0-2])([0-5]\d)?)?$/;
Stream.prototype.parseTime = function(start, end) {
 var s = this.parseStringISO(start, end);
 var m = this.reTime.exec(s);
 if (!m)
	  return "Unrecognized time: " + s;
 s = m[1] + "-" + m[2] + "-" + m[3] + " " + m[4];
 if (m[5]) {
	  s += ":" + m[5];
	  if (m[6]) {
	    s += ":" + m[6];
	    if (m[7])
		    s += "." + m[7];
	  }
 }
 if (m[8]) {
	  s += " UTC";
	  if (m[8] != 'Z') {
	    s += m[8];
	    if (m[9])
		    s += ":" + m[9];
	  }
 }
 return s;
}
Stream.prototype.parseInteger = function(start, end) {
 if ((end - start) > 4)
	  return undefined;
 //TODO support negative numbers
 var n = 0;
 for (var i = start; i < end; ++i)
	  n = (n << 8) | this.get(i);

 return n;
}
Stream.prototype.parseOID = function(start, end) {
 var s, n = 0, bits = 0;
 for (var i = start; i < end; ++i) {
	  var v = this.get(i);
	  n = (n << 7) | (v & 0x7F);
	  bits += 7;
	  if (!(v & 0x80)) { // finished
	    if (s == undefined)
		    s = parseInt(n / 40) + "." + (n % 40);
	    else
		    s += "." + ((bits >= 31) ? "big" : n);
	    n = bits = 0;
	  }
	  s += String.fromCharCode();
 }
 return s;
}

if(typeof(pidCrypt) != 'undefined')
{
 pidCrypt.ASN1 = function(stream, header, length, tag, sub) {
   this.stream = stream;
   this.header = header;
   this.length = length;
   this.tag = tag;
   this.sub = sub;
 }
 //pidCrypt extensions start
 //
 //gets the ASN data as tree of hex strings
 //@returns node: as javascript object tree with hex strings as values
 //e.g. RSA Public Key gives
 // {
 //   SEQUENCE:
 //              {
 //                  INTEGER: modulus,
 //                  INTEGER: public exponent
 //              }
 //}
 pidCrypt.ASN1.prototype.toHexTree = function() {
   var node = {};
   node.type = this.typeName();
   if(node.type != 'SEQUENCE')
     node.value = this.stream.parseStringHex(this.posContent(),this.posEnd());
   if (this.sub != null) {
     node.sub = [];
     for (var i = 0, max = this.sub.length; i < max; ++i)
       node.sub[i] = this.sub[i].toHexTree();
   }
   return node;
 }
 //pidCrypt extensions end

 pidCrypt.ASN1.prototype.typeName = function() {
   if (this.tag == undefined)
   return "unknown";
   var tagClass = this.tag >> 6;
   var tagConstructed = (this.tag >> 5) & 1;
   var tagNumber = this.tag & 0x1F;
   switch (tagClass) {
     case 0: // universal
       switch (tagNumber) {
         case 0x00: return "EOC";
         case 0x01: return "BOOLEAN";
         case 0x02: return "INTEGER";
         case 0x03: return "BIT_STRING";
         case 0x04: return "OCTET_STRING";
         case 0x05: return "NULL";
         case 0x06: return "OBJECT_IDENTIFIER";
         case 0x07: return "ObjectDescriptor";
         case 0x08: return "EXTERNAL";
         case 0x09: return "REAL";
         case 0x0A: return "ENUMERATED";
         case 0x0B: return "EMBEDDED_PDV";
         case 0x0C: return "UTF8String";
         case 0x10: return "SEQUENCE";
         case 0x11: return "SET";
         case 0x12: return "NumericString";
         case 0x13: return "PrintableString"; // ASCII subset
         case 0x14: return "TeletexString"; // aka T61String
         case 0x15: return "VideotexString";
         case 0x16: return "IA5String"; // ASCII
         case 0x17: return "UTCTime";
         case 0x18: return "GeneralizedTime";
         case 0x19: return "GraphicString";
         case 0x1A: return "VisibleString"; // ASCII subset
         case 0x1B: return "GeneralString";
         case 0x1C: return "UniversalString";
         case 0x1E: return "BMPString";
         default: return "Universal_" + tagNumber.toString(16);
       }
     case 1: return "Application_" + tagNumber.toString(16);
     case 2: return "[" + tagNumber + "]"; // Context
     case 3: return "Private_" + tagNumber.toString(16);
   }
 }
 pidCrypt.ASN1.prototype.content = function() {
   if (this.tag == undefined)
     return null;
   var tagClass = this.tag >> 6;
   if (tagClass != 0) // universal
     return null;
   var tagNumber = this.tag & 0x1F;
   var content = this.posContent();
   var len = Math.abs(this.length);
   switch (tagNumber) {
   case 0x01: // BOOLEAN
     return (this.stream.get(content) == 0) ? "false" : "true";
   case 0x02: // INTEGER
     return this.stream.parseInteger(content, content + len);
   //case 0x03: // BIT_STRING
   //case 0x04: // OCTET_STRING
   //case 0x05: // NULL
   case 0x06: // OBJECT_IDENTIFIER
     return this.stream.parseOID(content, content + len);
   //case 0x07: // ObjectDescriptor
   //case 0x08: // EXTERNAL
   //case 0x09: // REAL
   //case 0x0A: // ENUMERATED
   //case 0x0B: // EMBEDDED_PDV
   //case 0x10: // SEQUENCE
   //case 0x11: // SET
   case 0x0C: // UTF8String
     return this.stream.parseStringUTF(content, content + len);
   case 0x12: // NumericString
   case 0x13: // PrintableString
   case 0x14: // TeletexString
   case 0x15: // VideotexString
   case 0x16: // IA5String
   //case 0x19: // GraphicString
   case 0x1A: // VisibleString
   //case 0x1B: // GeneralString
   //case 0x1C: // UniversalString
   //case 0x1E: // BMPString
     return this.stream.parseStringISO(content, content + len);
   case 0x17: // UTCTime
   case 0x18: // GeneralizedTime
     return this.stream.parseTime(content, content + len);
   }
   return null;
 }
 pidCrypt.ASN1.prototype.toString = function() {
   return this.typeName() + "@" + this.stream.pos + "[header:" + this.header + ",length:" + this.length + ",sub:" + ((this.sub == null) ? 'null' : this.sub.length) + "]";
 }
 pidCrypt.ASN1.prototype.print = function(indent) {
   if (indent == undefined) indent = '';
     document.writeln(indent + this);
   if (this.sub != null) {
     indent += '  ';
   for (var i = 0, max = this.sub.length; i < max; ++i)
     this.sub[i].print(indent);
   }
 }
 pidCrypt.ASN1.prototype.toPrettyString = function(indent) {
   if (indent == undefined) indent = '';
   var s = indent + this.typeName() + " @" + this.stream.pos;
   if (this.length >= 0)
     s += "+";
   s += this.length;
   if (this.tag & 0x20)
     s += " (constructed)";
   else
     if (((this.tag == 0x03) || (this.tag == 0x04)) && (this.sub != null))
       s += " (encapsulates)";
   s += "\n";
   if (this.sub != null) {
     indent += '  ';
     for (var i = 0, max = this.sub.length; i < max; ++i)
       s += this.sub[i].toPrettyString(indent);
   }
   return s;
 }
 pidCrypt.ASN1.prototype.toDOM = function() {
   var node = document.createElement("div");
   node.className = "node";
   node.asn1 = this;
   var head = document.createElement("div");
   head.className = "head";
   var s = this.typeName();
   head.innerHTML = s;
   node.appendChild(head);
   this.head = head;
   var value = document.createElement("div");
   value.className = "value";
   s = "Offset: " + this.stream.pos + "<br/>";
   s += "Length: " + this.header + "+";
   if (this.length >= 0)
     s += this.length;
   else
     s += (-this.length) + " (undefined)";
   if (this.tag & 0x20)
     s += "<br/>(constructed)";
   else if (((this.tag == 0x03) || (this.tag == 0x04)) && (this.sub != null))
     s += "<br/>(encapsulates)";
   var content = this.content();
   if (content != null) {
     s += "<br/>Value:<br/><b>" + content + "</b>";
     if ((typeof(oids) == 'object') && (this.tag == 0x06)) {
       var oid = oids[content];
       if (oid) {
         if (oid.d) s += "<br/>" + oid.d;
         if (oid.c) s += "<br/>" + oid.c;
         if (oid.w) s += "<br/>(warning!)";
       }
     }
   }
   value.innerHTML = s;
   node.appendChild(value);
   var sub = document.createElement("div");
   sub.className = "sub";
   if (this.sub != null) {
     for (var i = 0, max = this.sub.length; i < max; ++i)
       sub.appendChild(this.sub[i].toDOM());
   }
   node.appendChild(sub);
   head.switchNode = node;
   head.onclick = function() {
     var node = this.switchNode;
     node.className = (node.className == "node collapsed") ? "node" : "node collapsed";
   };
   return node;
 }
 pidCrypt.ASN1.prototype.posStart = function() {
   return this.stream.pos;
 }
 pidCrypt.ASN1.prototype.posContent = function() {
   return this.stream.pos + this.header;
 }
 pidCrypt.ASN1.prototype.posEnd = function() {
   return this.stream.pos + this.header + Math.abs(this.length);
 }
 pidCrypt.ASN1.prototype.toHexDOM_sub = function(node, className, stream, start, end) {
   if (start >= end)
     return;
   var sub = document.createElement("span");
   sub.className = className;
   sub.appendChild(document.createTextNode(
   stream.hexDump(start, end)));
   node.appendChild(sub);
 }
 pidCrypt.ASN1.prototype.toHexDOM = function() {
   var node = document.createElement("span");
   node.className = 'hex';
   this.head.hexNode = node;
   this.head.onmouseover = function() { this.hexNode.className = 'hexCurrent'; }
   this.head.onmouseout  = function() { this.hexNode.className = 'hex'; }
   this.toHexDOM_sub(node, "tag", this.stream, this.posStart(), this.posStart() + 1);
   this.toHexDOM_sub(node, (this.length >= 0) ? "dlen" : "ulen", this.stream, this.posStart() + 1, this.posContent());
   if (this.sub == null)
     node.appendChild(document.createTextNode(
       this.stream.hexDump(this.posContent(), this.posEnd())));
   else if (this.sub.length > 0) {
   var first = this.sub[0];
   var last = this.sub[this.sub.length - 1];
   this.toHexDOM_sub(node, "intro", this.stream, this.posContent(), first.posStart());
   for (var i = 0, max = this.sub.length; i < max; ++i)
       node.appendChild(this.sub[i].toHexDOM());
   this.toHexDOM_sub(node, "outro", this.stream, last.posEnd(), this.posEnd());
   }
   return node;
 }

 /*
 pidCrypt.ASN1.prototype.getValue = function() {
     TODO
 }
 */
 pidCrypt.ASN1.decodeLength = function(stream) {
     var buf = stream.get();
     var len = buf & 0x7F;
     if (len == buf)
         return len;
     if (len > 3)
         throw "Length over 24 bits not supported at position " + (stream.pos - 1);
     if (len == 0)
     return -1; // undefined
     buf = 0;
     for (var i = 0; i < len; ++i)
         buf = (buf << 8) | stream.get();
     return buf;
 }
 pidCrypt.ASN1.hasContent = function(tag, len, stream) {
     if (tag & 0x20) // constructed
     return true;
     if ((tag < 0x03) || (tag > 0x04))
     return false;
     var p = new Stream(stream);
     if (tag == 0x03) p.get(); // BitString unused bits, must be in [0, 7]
     var subTag = p.get();
     if ((subTag >> 6) & 0x01) // not (universal or context)
     return false;
     try {
     var subLength = pidCrypt.ASN1.decodeLength(p);
     return ((p.pos - stream.pos) + subLength == len);
     } catch (exception) {
     return false;
     }
 }
 pidCrypt.ASN1.decode = function(stream) {
   if (!(stream instanceof Stream))
       stream = new Stream(stream, 0);
   var streamStart = new Stream(stream);
   var tag = stream.get();
   var len = pidCrypt.ASN1.decodeLength(stream);
   var header = stream.pos - streamStart.pos;
   var sub = null;
   if (pidCrypt.ASN1.hasContent(tag, len, stream)) {
   // it has content, so we decode it
   var start = stream.pos;
   if (tag == 0x03) stream.get(); // skip BitString unused bits, must be in [0, 7]
       sub = [];
   if (len >= 0) {
       // definite length
       var end = start + len;
       while (stream.pos < end)
       sub[sub.length] = pidCrypt.ASN1.decode(stream);
       if (stream.pos != end)
       throw "Content size is not correct for container starting at offset " + start;
   } else {
       // undefined length
       try {
       for (;;) {
           var s = pidCrypt.ASN1.decode(stream);
           if (s.tag == 0)
           break;
           sub[sub.length] = s;
       }
       len = start - stream.pos;
       } catch (e) {
       throw "Exception while decoding undefined length content: " + e;
       }
   }
   } else
       stream.pos += len; // skip content
   return new pidCrypt.ASN1(streamStart, header, len, tag, sub);
 }
 pidCrypt.ASN1.test = function() {
   var test = [
     { value: [0x27],                   expected: 0x27     },
     { value: [0x81, 0xC9],             expected: 0xC9     },
     { value: [0x83, 0xFE, 0xDC, 0xBA], expected: 0xFEDCBA },
   ];
   for (var i = 0, max = test.length; i < max; ++i) {
     var pos = 0;
     var stream = new Stream(test[i].value, 0);
     var res = pidCrypt.ASN1.decodeLength(stream);
     if (res != test[i].expected)
       document.write("In test[" + i + "] expected " + test[i].expected + " got " + res + "\n");
   }
 }
}



//HPM Security jsbn.js

/*
 * Copyright (c) 2003-2005  Tom Wu
 * All Rights Reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS-IS" AND WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS, IMPLIED OR OTHERWISE, INCLUDING WITHOUT LIMITATION, ANY
 * WARRANTY OF MERCHANTABILITY OR FITNESS FOR A PARTICULAR PURPOSE.
 *
 * IN NO EVENT SHALL TOM WU BE LIABLE FOR ANY SPECIAL, INCIDENTAL,
 * INDIRECT OR CONSEQUENTIAL DAMAGES OF ANY KIND, OR ANY DAMAGES WHATSOEVER
 * RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER OR NOT ADVISED OF
 * THE POSSIBILITY OF DAMAGE, AND ON ANY THEORY OF LIABILITY, ARISING OUT
 * OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 * In addition, the following condition applies:
 *
 * All redistributions must retain an intact copy of this copyright notice
 * and disclaimer.
 */
//Address all questions regarding this license to:
//  Tom Wu
//  tjw@cs.Stanford.EDU
// Basic JavaScript BN library - subset useful for RSA encryption.

// Bits per digit
var dbits;

// JavaScript engine analysis
var canary = 0xdeadbeefcafe;
var j_lm = ((canary&0xffffff)==0xefcafe);

// (public) Constructor
function BigInteger(a,b,c) {

  if(a != null)
    if("number" == typeof a) this.fromNumber(a,b,c);
    else if(b == null && "string" != typeof a) this.fromString(a,256);
    else this.fromString(a,b);
}

// return new, unset BigInteger
function nbi() { return new BigInteger(null); }

// am: Compute w_j += (x*this_i), propagate carries,
// c is initial carry, returns final carry.
// c < 3*dvalue, x < 2*dvalue, this_i < dvalue
// We need to select the fastest one that works in this environment.

// am1: use a single mult and divide to get the high bits,
// max digit bits should be 26 because
// max internal value = 2*dvalue^2-2*dvalue (< 2^53)
function am1(i,x,w,j,c,n) {
  while(--n >= 0) {
    var v = x*this[i++]+w[j]+c;
    c = Math.floor(v/0x4000000);
    w[j++] = v&0x3ffffff;
  }
  return c;
}
// am2 avoids a big mult-and-extract completely.
// Max digit bits should be <= 30 because we do bitwise ops
// on values up to 2*hdvalue^2-hdvalue-1 (< 2^31)
function am2(i,x,w,j,c,n) {
  var xl = x&0x7fff, xh = x>>15;
  while(--n >= 0) {
    var l = this[i]&0x7fff;
    var h = this[i++]>>15;
    var m = xh*l+h*xl;
    l = xl*l+((m&0x7fff)<<15)+w[j]+(c&0x3fffffff);
    c = (l>>>30)+(m>>>15)+xh*h+(c>>>30);
    w[j++] = l&0x3fffffff;
  }
  return c;
}
// Alternately, set max digit bits to 28 since some
// browsers slow down when dealing with 32-bit numbers.
function am3(i,x,w,j,c,n) {
  var xl = x&0x3fff, xh = x>>14;
  while(--n >= 0) {
    var l = this[i]&0x3fff;
    var h = this[i++]>>14;
    var m = xh*l+h*xl;
    l = xl*l+((m&0x3fff)<<14)+w[j]+c;
    c = (l>>28)+(m>>14)+xh*h;
    w[j++] = l&0xfffffff;
  }
  return c;
}
if(j_lm && (navigator.appName == "Microsoft Internet Explorer")) {
  BigInteger.prototype.am = am2;
  dbits = 30;
}
else if(j_lm && (navigator.appName != "Netscape")) {
  BigInteger.prototype.am = am1;
  dbits = 26;
}
else { // Mozilla/Netscape seems to prefer am3
  BigInteger.prototype.am = am3;
  dbits = 28;
}

BigInteger.prototype.DB = dbits;
BigInteger.prototype.DM = ((1<<dbits)-1);
BigInteger.prototype.DV = (1<<dbits);

var BI_FP = 52;
BigInteger.prototype.FV = Math.pow(2,BI_FP);
BigInteger.prototype.F1 = BI_FP-dbits;
BigInteger.prototype.F2 = 2*dbits-BI_FP;

// Digit conversions
var BI_RM = "0123456789abcdefghijklmnopqrstuvwxyz";
var BI_RC = new Array();
var rr,vv;
rr = "0".charCodeAt(0);
for(vv = 0; vv <= 9; ++vv) BI_RC[rr++] = vv;
rr = "a".charCodeAt(0);
for(vv = 10; vv < 36; ++vv) BI_RC[rr++] = vv;
rr = "A".charCodeAt(0);
for(vv = 10; vv < 36; ++vv) BI_RC[rr++] = vv;

function int2char(n) { return BI_RM.charAt(n); }
function intAt(s,i) {
  var c = BI_RC[s.charCodeAt(i)];
  return (c==null)?-1:c;
}

// (protected) copy this to r
function bnpCopyTo(r) {
  for(var i = this.t-1; i >= 0; --i) r[i] = this[i];
  r.t = this.t;
  r.s = this.s;
}

// (protected) set from integer value x, -DV <= x < DV
function bnpFromInt(x) {
  this.t = 1;
  this.s = (x<0)?-1:0;
  if(x > 0) this[0] = x;
  else if(x < -1) this[0] = x+DV;
  else this.t = 0;
}

// return bigint initialized to value
function nbv(i) { var r = nbi(); r.fromInt(i); return r; }

// (protected) set from string and radix
function bnpFromString(s,b) {
  var k;
  if(b == 16) k = 4;
  else if(b == 8) k = 3;
  else if(b == 256) k = 8; // byte array
  else if(b == 2) k = 1;
  else if(b == 32) k = 5;
  else if(b == 4) k = 2;
  else { this.fromRadix(s,b); return; }
  this.t = 0;
  this.s = 0;
  var i = s.length, mi = false, sh = 0;
  while(--i >= 0) {
    var x = (k==8)?s[i]&0xff:intAt(s,i);
    if(x < 0) {
      if(s.charAt(i) == "-") mi = true;
      continue;
    }
    mi = false;
    if(sh == 0)
      this[this.t++] = x;
    else if(sh+k > this.DB) {
      this[this.t-1] |= (x&((1<<(this.DB-sh))-1))<<sh;
      this[this.t++] = (x>>(this.DB-sh));
    }
    else
      this[this.t-1] |= x<<sh;
    sh += k;
    if(sh >= this.DB) sh -= this.DB;
  }
  if(k == 8 && (s[0]&0x80) != 0) {
    this.s = -1;
    if(sh > 0) this[this.t-1] |= ((1<<(this.DB-sh))-1)<<sh;
  }
  this.clamp();
  if(mi) BigInteger.ZERO.subTo(this,this);
}

// (protected) clamp off excess high words
function bnpClamp() {
  var c = this.s&this.DM;
  while(this.t > 0 && this[this.t-1] == c) --this.t;
}

// (public) return string representation in given radix
function bnToString(b) {
  if(this.s < 0) return "-"+this.negate().toString(b);
  var k;
  if(b == 16) k = 4;
  else if(b == 8) k = 3;
  else if(b == 2) k = 1;
  else if(b == 32) k = 5;
  else if(b == 4) k = 2;
  else return this.toRadix(b);
  var km = (1<<k)-1, d, m = false, r = "", i = this.t;
  var p = this.DB-(i*this.DB)%k;
  if(i-- > 0) {
    if(p < this.DB && (d = this[i]>>p) > 0) { m = true; r = int2char(d); }
    while(i >= 0) {
      if(p < k) {
        d = (this[i]&((1<<p)-1))<<(k-p);
        d |= this[--i]>>(p+=this.DB-k);
      }
      else {
        d = (this[i]>>(p-=k))&km;
        if(p <= 0) { p += this.DB; --i; }
      }
      if(d > 0) m = true;
      if(m) r += int2char(d);
    }
  }
  return m?r:"0";
}

// (public) -this
function bnNegate() { var r = nbi(); BigInteger.ZERO.subTo(this,r); return r; }

// (public) |this|
function bnAbs() { return (this.s<0)?this.negate():this; }

// (public) return + if this > a, - if this < a, 0 if equal
function bnCompareTo(a) {
  var r = this.s-a.s;
  if(r != 0) return r;
  var i = this.t;
  r = i-a.t;
  if(r != 0) return r;
  while(--i >= 0) if((r=this[i]-a[i]) != 0) return r;
  return 0;
}

// returns bit length of the integer x
function nbits(x) {
  var r = 1, t;
  if((t=x>>>16) != 0) { x = t; r += 16; }
  if((t=x>>8) != 0) { x = t; r += 8; }
  if((t=x>>4) != 0) { x = t; r += 4; }
  if((t=x>>2) != 0) { x = t; r += 2; }
  if((t=x>>1) != 0) { x = t; r += 1; }
  return r;
}

// (public) return the number of bits in "this"
function bnBitLength() {
  if(this.t <= 0) return 0;
  return this.DB*(this.t-1)+nbits(this[this.t-1]^(this.s&this.DM));
}

// (protected) r = this << n*DB
function bnpDLShiftTo(n,r) {
  var i;
  for(i = this.t-1; i >= 0; --i) r[i+n] = this[i];
  for(i = n-1; i >= 0; --i) r[i] = 0;
  r.t = this.t+n;
  r.s = this.s;
}

// (protected) r = this >> n*DB
function bnpDRShiftTo(n,r) {
  for(var i = n; i < this.t; ++i) r[i-n] = this[i];
  r.t = Math.max(this.t-n,0);
  r.s = this.s;
}

// (protected) r = this << n
function bnpLShiftTo(n,r) {
  var bs = n%this.DB;
  var cbs = this.DB-bs;
  var bm = (1<<cbs)-1;
  var ds = Math.floor(n/this.DB), c = (this.s<<bs)&this.DM, i;
  for(i = this.t-1; i >= 0; --i) {
    r[i+ds+1] = (this[i]>>cbs)|c;
    c = (this[i]&bm)<<bs;
  }
  for(i = ds-1; i >= 0; --i) r[i] = 0;
  r[ds] = c;
  r.t = this.t+ds+1;
  r.s = this.s;
  r.clamp();
}

// (protected) r = this >> n
function bnpRShiftTo(n,r) {
  r.s = this.s;
  var ds = Math.floor(n/this.DB);
  if(ds >= this.t) { r.t = 0; return; }
  var bs = n%this.DB;
  var cbs = this.DB-bs;
  var bm = (1<<bs)-1;
  r[0] = this[ds]>>bs;
  for(var i = ds+1; i < this.t; ++i) {
    r[i-ds-1] |= (this[i]&bm)<<cbs;
    r[i-ds] = this[i]>>bs;
  }
  if(bs > 0) r[this.t-ds-1] |= (this.s&bm)<<cbs;
  r.t = this.t-ds;
  r.clamp();
}

// (protected) r = this - a
function bnpSubTo(a,r) {
  var i = 0, c = 0, m = Math.min(a.t,this.t);
  while(i < m) {
    c += this[i]-a[i];
    r[i++] = c&this.DM;
    c >>= this.DB;
  }
  if(a.t < this.t) {
    c -= a.s;
    while(i < this.t) {
      c += this[i];
      r[i++] = c&this.DM;
      c >>= this.DB;
    }
    c += this.s;
  }
  else {
    c += this.s;
    while(i < a.t) {
      c -= a[i];
      r[i++] = c&this.DM;
      c >>= this.DB;
    }
    c -= a.s;
  }
  r.s = (c<0)?-1:0;
  if(c < -1) r[i++] = this.DV+c;
  else if(c > 0) r[i++] = c;
  r.t = i;
  r.clamp();
}

// (protected) r = this * a, r != this,a (HAC 14.12)
// "this" should be the larger one if appropriate.
function bnpMultiplyTo(a,r) {
  var x = this.abs(), y = a.abs();
  var i = x.t;
  r.t = i+y.t;
  while(--i >= 0) r[i] = 0;
  for(i = 0; i < y.t; ++i) r[i+x.t] = x.am(0,y[i],r,i,0,x.t);
  r.s = 0;
  r.clamp();
  if(this.s != a.s) BigInteger.ZERO.subTo(r,r);
}

// (protected) r = this^2, r != this (HAC 14.16)
function bnpSquareTo(r) {
  var x = this.abs();
  var i = r.t = 2*x.t;
  while(--i >= 0) r[i] = 0;
  for(i = 0; i < x.t-1; ++i) {
    var c = x.am(i,x[i],r,2*i,0,1);
    if((r[i+x.t]+=x.am(i+1,2*x[i],r,2*i+1,c,x.t-i-1)) >= x.DV) {
      r[i+x.t] -= x.DV;
      r[i+x.t+1] = 1;
    }
  }
  if(r.t > 0) r[r.t-1] += x.am(i,x[i],r,2*i,0,1);
  r.s = 0;
  r.clamp();
}

// (protected) divide this by m, quotient and remainder to q, r (HAC 14.20)
// r != q, this != m.  q or r may be null.
function bnpDivRemTo(m,q,r) {
  var pm = m.abs();
  if(pm.t <= 0) return;
  var pt = this.abs();
  if(pt.t < pm.t) {
    if(q != null) q.fromInt(0);
    if(r != null) this.copyTo(r);
    return;
  }
  if(r == null) r = nbi();
  var y = nbi(), ts = this.s, ms = m.s;
  var nsh = this.DB-nbits(pm[pm.t-1]);	// normalize modulus
  if(nsh > 0) { pm.lShiftTo(nsh,y); pt.lShiftTo(nsh,r); }
  else { pm.copyTo(y); pt.copyTo(r); }
  var ys = y.t;
  var y0 = y[ys-1];
  if(y0 == 0) return;
  var yt = y0*(1<<this.F1)+((ys>1)?y[ys-2]>>this.F2:0);
  var d1 = this.FV/yt, d2 = (1<<this.F1)/yt, e = 1<<this.F2;
  var i = r.t, j = i-ys, t = (q==null)?nbi():q;
  y.dlShiftTo(j,t);
  if(r.compareTo(t) >= 0) {
    r[r.t++] = 1;
    r.subTo(t,r);
  }
  BigInteger.ONE.dlShiftTo(ys,t);
  t.subTo(y,y);	// "negative" y so we can replace sub with am later
  while(y.t < ys) y[y.t++] = 0;
  while(--j >= 0) {
    // Estimate quotient digit
    var qd = (r[--i]==y0)?this.DM:Math.floor(r[i]*d1+(r[i-1]+e)*d2);
    if((r[i]+=y.am(0,qd,r,j,0,ys)) < qd) {	// Try it out
      y.dlShiftTo(j,t);
      r.subTo(t,r);
      while(r[i] < --qd) r.subTo(t,r);
    }
  }
  if(q != null) {
    r.drShiftTo(ys,q);
    if(ts != ms) BigInteger.ZERO.subTo(q,q);
  }
  r.t = ys;
  r.clamp();
  if(nsh > 0) r.rShiftTo(nsh,r);	// Denormalize remainder
  if(ts < 0) BigInteger.ZERO.subTo(r,r);
}

// (public) this mod a
function bnMod(a) {
  var r = nbi();
  this.abs().divRemTo(a,null,r);
  if(this.s < 0 && r.compareTo(BigInteger.ZERO) > 0) a.subTo(r,r);
  return r;
}

// Modular reduction using "classic" algorithm
function Classic(m) { this.m = m; }
function cConvert(x) {
  if(x.s < 0 || x.compareTo(this.m) >= 0) return x.mod(this.m);
  else return x;
}
function cRevert(x) { return x; }
function cReduce(x) { x.divRemTo(this.m,null,x); }
function cMulTo(x,y,r) { x.multiplyTo(y,r); this.reduce(r); }
function cSqrTo(x,r) { x.squareTo(r); this.reduce(r); }

Classic.prototype.convert = cConvert;
Classic.prototype.revert = cRevert;
Classic.prototype.reduce = cReduce;
Classic.prototype.mulTo = cMulTo;
Classic.prototype.sqrTo = cSqrTo;

// (protected) return "-1/this % 2^DB"; useful for Mont. reduction
// justification:
//         xy == 1 (mod m)
//         xy =  1+km
//   xy(2-xy) = (1+km)(1-km)
// x[y(2-xy)] = 1-k^2m^2
// x[y(2-xy)] == 1 (mod m^2)
// if y is 1/x mod m, then y(2-xy) is 1/x mod m^2
// should reduce x and y(2-xy) by m^2 at each step to keep size bounded.
// JS multiply "overflows" differently from C/C++, so care is needed here.
function bnpInvDigit() {
  if(this.t < 1) return 0;
  var x = this[0];
  if((x&1) == 0) return 0;
  var y = x&3;		// y == 1/x mod 2^2
  y = (y*(2-(x&0xf)*y))&0xf;	// y == 1/x mod 2^4
  y = (y*(2-(x&0xff)*y))&0xff;	// y == 1/x mod 2^8
  y = (y*(2-(((x&0xffff)*y)&0xffff)))&0xffff;	// y == 1/x mod 2^16
  // last step - calculate inverse mod DV directly;
  // assumes 16 < DB <= 32 and assumes ability to handle 48-bit ints
  y = (y*(2-x*y%this.DV))%this.DV;		// y == 1/x mod 2^dbits
  // we really want the negative inverse, and -DV < y < DV
  return (y>0)?this.DV-y:-y;
}

// Montgomery reduction
function Montgomery(m) {
  this.m = m;
  this.mp = m.invDigit();
  this.mpl = this.mp&0x7fff;
  this.mph = this.mp>>15;
  this.um = (1<<(m.DB-15))-1;
  this.mt2 = 2*m.t;
}

// xR mod m
function montConvert(x) {
  var r = nbi();
  x.abs().dlShiftTo(this.m.t,r);
  r.divRemTo(this.m,null,r);
  if(x.s < 0 && r.compareTo(BigInteger.ZERO) > 0) this.m.subTo(r,r);
  return r;
}

// x/R mod m
function montRevert(x) {
  var r = nbi();
  x.copyTo(r);
  this.reduce(r);
  return r;
}

// x = x/R mod m (HAC 14.32)
function montReduce(x) {
  while(x.t <= this.mt2)	// pad x so am has enough room later
    x[x.t++] = 0;
  for(var i = 0; i < this.m.t; ++i) {
    // faster way of calculating u0 = x[i]*mp mod DV
    var j = x[i]&0x7fff;
    var u0 = (j*this.mpl+(((j*this.mph+(x[i]>>15)*this.mpl)&this.um)<<15))&x.DM;
    // use am to combine the multiply-shift-add into one call
    j = i+this.m.t;
    x[j] += this.m.am(0,u0,x,i,0,this.m.t);
    // propagate carry
    while(x[j] >= x.DV) { x[j] -= x.DV; x[++j]++; }
  }
  x.clamp();
  x.drShiftTo(this.m.t,x);
  if(x.compareTo(this.m) >= 0) x.subTo(this.m,x);
}

// r = "x^2/R mod m"; x != r
function montSqrTo(x,r) { x.squareTo(r); this.reduce(r); }

// r = "xy/R mod m"; x,y != r
function montMulTo(x,y,r) { x.multiplyTo(y,r); this.reduce(r); }

Montgomery.prototype.convert = montConvert;
Montgomery.prototype.revert = montRevert;
Montgomery.prototype.reduce = montReduce;
Montgomery.prototype.mulTo = montMulTo;
Montgomery.prototype.sqrTo = montSqrTo;

// (protected) true iff this is even
function bnpIsEven() { return ((this.t>0)?(this[0]&1):this.s) == 0; }

// (protected) this^e, e < 2^32, doing sqr and mul with "r" (HAC 14.79)
function bnpExp(e,z) {
  if(e > 0xffffffff || e < 1) return BigInteger.ONE;
  var r = nbi(), r2 = nbi(), g = z.convert(this), i = nbits(e)-1;
  g.copyTo(r);
  while(--i >= 0) {
    z.sqrTo(r,r2);
    if((e&(1<<i)) > 0) z.mulTo(r2,g,r);
    else { var t = r; r = r2; r2 = t; }
  }
  return z.revert(r);
}

// (public) this^e % m, 0 <= e < 2^32
function bnModPowInt(e,m) {
  var z;
  if(e < 256 || m.isEven()) z = new Classic(m); else z = new Montgomery(m);
  return this.exp(e,z);
}

// protected
BigInteger.prototype.copyTo = bnpCopyTo;
BigInteger.prototype.fromInt = bnpFromInt;
BigInteger.prototype.fromString = bnpFromString;
BigInteger.prototype.clamp = bnpClamp;
BigInteger.prototype.dlShiftTo = bnpDLShiftTo;
BigInteger.prototype.drShiftTo = bnpDRShiftTo;
BigInteger.prototype.lShiftTo = bnpLShiftTo;
BigInteger.prototype.rShiftTo = bnpRShiftTo;
BigInteger.prototype.subTo = bnpSubTo;
BigInteger.prototype.multiplyTo = bnpMultiplyTo;
BigInteger.prototype.squareTo = bnpSquareTo;
BigInteger.prototype.divRemTo = bnpDivRemTo;
BigInteger.prototype.invDigit = bnpInvDigit;
BigInteger.prototype.isEven = bnpIsEven;
BigInteger.prototype.exp = bnpExp;

// public
BigInteger.prototype.toString = bnToString;
BigInteger.prototype.negate = bnNegate;
BigInteger.prototype.abs = bnAbs;
BigInteger.prototype.compareTo = bnCompareTo;
BigInteger.prototype.bitLength = bnBitLength;
BigInteger.prototype.mod = bnMod;
BigInteger.prototype.modPowInt = bnModPowInt;

// "constants"
BigInteger.ZERO = nbv(0);
BigInteger.ONE = nbv(1);


// Extended JavaScript BN functions, required for RSA private ops.

// (public)
function bnClone() { var r = nbi(); this.copyTo(r); return r; }

// (public) return value as integer
function bnIntValue() {
  if(this.s < 0) {
    if(this.t == 1) return this[0]-this.DV;
    else if(this.t == 0) return -1;
  }
  else if(this.t == 1) return this[0];
  else if(this.t == 0) return 0;
  // assumes 16 < DB < 32
  return ((this[1]&((1<<(32-this.DB))-1))<<this.DB)|this[0];
}

// (public) return value as byte
function bnByteValue() { return (this.t==0)?this.s:(this[0]<<24)>>24; }

// (public) return value as short (assumes DB>=16)
function bnShortValue() { return (this.t==0)?this.s:(this[0]<<16)>>16; }

// (protected) return x s.t. r^x < DV
function bnpChunkSize(r) { return Math.floor(Math.LN2*this.DB/Math.log(r)); }

// (public) 0 if this == 0, 1 if this > 0
function bnSigNum() {
  if(this.s < 0) return -1;
  else if(this.t <= 0 || (this.t == 1 && this[0] <= 0)) return 0;
  else return 1;
}

// (protected) convert to radix string
function bnpToRadix(b) {
  if(b == null) b = 10;
  if(this.signum() == 0 || b < 2 || b > 36) return "0";
  var cs = this.chunkSize(b);
  var a = Math.pow(b,cs);
  var d = nbv(a), y = nbi(), z = nbi(), r = "";
  this.divRemTo(d,y,z);
  while(y.signum() > 0) {
    r = (a+z.intValue()).toString(b).substr(1) + r;
    y.divRemTo(d,y,z);
  }
  return z.intValue().toString(b) + r;
}

// (protected) convert from radix string
function bnpFromRadix(s,b) {
  this.fromInt(0);
  if(b == null) b = 10;
  var cs = this.chunkSize(b);
  var d = Math.pow(b,cs), mi = false, j = 0, w = 0;
  for(var i = 0; i < s.length; ++i) {
    var x = intAt(s,i);
    if(x < 0) {
      if(s.charAt(i) == "-" && this.signum() == 0) mi = true;
      continue;
    }
    w = b*w+x;
    if(++j >= cs) {
      this.dMultiply(d);
      this.dAddOffset(w,0);
      j = 0;
      w = 0;
    }
  }
  if(j > 0) {
    this.dMultiply(Math.pow(b,j));
    this.dAddOffset(w,0);
  }
  if(mi) BigInteger.ZERO.subTo(this,this);
}

// (protected) alternate constructor
function bnpFromNumber(a,b,c) {
if("number" == typeof b) {
    // new BigInteger(int,int,RNG)
    if(a < 2) this.fromInt(1);
    else {
      this.fromNumber(a,c);
      if(!this.testBit(a-1))	// force MSB set
        this.bitwiseTo(BigInteger.ONE.shiftLeft(a-1),op_or,this);
      if(this.isEven()) this.dAddOffset(1,0); // force odd
      while(!this.isProbablePrime(b)) {
        this.dAddOffset(2,0);
        if(this.bitLength() > a) this.subTo(BigInteger.ONE.shiftLeft(a-1),this);
      }
    }
  }
  else {
    // new BigInteger(int,RNG)
    var x = new Array(), t = a&7;
    x.length = (a>>3)+1;
    b.nextBytes(x);
    if(t > 0) x[0] &= ((1<<t)-1); else x[0] = 0;
    this.fromString(x,256);
  }
}

// (public) convert to bigendian byte array
function bnToByteArray() {
  var i = this.t, r = new Array();
  r[0] = this.s;
  var p = this.DB-(i*this.DB)%8, d, k = 0;
  if(i-- > 0) {
    if(p < this.DB && (d = this[i]>>p) != (this.s&this.DM)>>p)
      r[k++] = d|(this.s<<(this.DB-p));
    while(i >= 0) {
      if(p < 8) {
        d = (this[i]&((1<<p)-1))<<(8-p);
        d |= this[--i]>>(p+=this.DB-8);
      }
      else {
        d = (this[i]>>(p-=8))&0xff;
        if(p <= 0) { p += this.DB; --i; }
      }
      if((d&0x80) != 0) d |= -256;
      if(k == 0 && (this.s&0x80) != (d&0x80)) ++k;
      if(k > 0 || d != this.s) r[k++] = d;
    }
  }
  return r;
}

function bnEquals(a) { return(this.compareTo(a)==0); }
function bnMin(a) { return(this.compareTo(a)<0)?this:a; }
function bnMax(a) { return(this.compareTo(a)>0)?this:a; }

// (protected) r = this op a (bitwise)
function bnpBitwiseTo(a,op,r) {
  var i, f, m = Math.min(a.t,this.t);
  for(i = 0; i < m; ++i) r[i] = op(this[i],a[i]);
  if(a.t < this.t) {
    f = a.s&this.DM;
    for(i = m; i < this.t; ++i) r[i] = op(this[i],f);
    r.t = this.t;
  }
  else {
    f = this.s&this.DM;
    for(i = m; i < a.t; ++i) r[i] = op(f,a[i]);
    r.t = a.t;
  }
  r.s = op(this.s,a.s);
  r.clamp();
}

// (public) this & a
function op_and(x,y) { return x&y; }
function bnAnd(a) { var r = nbi(); this.bitwiseTo(a,op_and,r); return r; }

// (public) this | a
function op_or(x,y) { return x|y; }
function bnOr(a) { var r = nbi(); this.bitwiseTo(a,op_or,r); return r; }

// (public) this ^ a
function op_xor(x,y) { return x^y; }
function bnXor(a) { var r = nbi(); this.bitwiseTo(a,op_xor,r); return r; }

// (public) this & ~a
function op_andnot(x,y) { return x&~y; }
function bnAndNot(a) { var r = nbi(); this.bitwiseTo(a,op_andnot,r); return r; }

// (public) ~this
function bnNot() {
  var r = nbi();
  for(var i = 0; i < this.t; ++i) r[i] = this.DM&~this[i];
  r.t = this.t;
  r.s = ~this.s;
  return r;
}

// (public) this << n
function bnShiftLeft(n) {
  var r = nbi();
  if(n < 0) this.rShiftTo(-n,r); else this.lShiftTo(n,r);
  return r;
}

// (public) this >> n
function bnShiftRight(n) {
  var r = nbi();
  if(n < 0) this.lShiftTo(-n,r); else this.rShiftTo(n,r);
  return r;
}

// return index of lowest 1-bit in x, x < 2^31
function lbit(x) {
  if(x == 0) return -1;
  var r = 0;
  if((x&0xffff) == 0) { x >>= 16; r += 16; }
  if((x&0xff) == 0) { x >>= 8; r += 8; }
  if((x&0xf) == 0) { x >>= 4; r += 4; }
  if((x&3) == 0) { x >>= 2; r += 2; }
  if((x&1) == 0) ++r;
  return r;
}

// (public) returns index of lowest 1-bit (or -1 if none)
function bnGetLowestSetBit() {
  for(var i = 0; i < this.t; ++i)
    if(this[i] != 0) return i*this.DB+lbit(this[i]);
  if(this.s < 0) return this.t*this.DB;
  return -1;
}

// return number of 1 bits in x
function cbit(x) {
  var r = 0;
  while(x != 0) { x &= x-1; ++r; }
  return r;
}

// (public) return number of set bits
function bnBitCount() {
  var r = 0, x = this.s&this.DM;
  for(var i = 0; i < this.t; ++i) r += cbit(this[i]^x);
  return r;
}

// (public) true iff nth bit is set
function bnTestBit(n) {
  var j = Math.floor(n/this.DB);
  if(j >= this.t) return(this.s!=0);
  return((this[j]&(1<<(n%this.DB)))!=0);
}

// (protected) this op (1<<n)
function bnpChangeBit(n,op) {
  var r = BigInteger.ONE.shiftLeft(n);
  this.bitwiseTo(r,op,r);
  return r;
}

// (public) this | (1<<n)
function bnSetBit(n) { return this.changeBit(n,op_or); }

// (public) this & ~(1<<n)
function bnClearBit(n) { return this.changeBit(n,op_andnot); }

// (public) this ^ (1<<n)
function bnFlipBit(n) { return this.changeBit(n,op_xor); }

// (protected) r = this + a
function bnpAddTo(a,r) {
  var i = 0, c = 0, m = Math.min(a.t,this.t);
  while(i < m) {
    c += this[i]+a[i];
    r[i++] = c&this.DM;
    c >>= this.DB;
  }
  if(a.t < this.t) {
    c += a.s;
    while(i < this.t) {
      c += this[i];
      r[i++] = c&this.DM;
      c >>= this.DB;
    }
    c += this.s;
  }
  else {
    c += this.s;
    while(i < a.t) {
      c += a[i];
      r[i++] = c&this.DM;
      c >>= this.DB;
    }
    c += a.s;
  }
  r.s = (c<0)?-1:0;
  if(c > 0) r[i++] = c;
  else if(c < -1) r[i++] = this.DV+c;
  r.t = i;
  r.clamp();
}

// (public) this + a
function bnAdd(a) { var r = nbi(); this.addTo(a,r); return r; }

// (public) this - a
function bnSubtract(a) { var r = nbi(); this.subTo(a,r); return r; }

// (public) this * a
function bnMultiply(a) { var r = nbi(); this.multiplyTo(a,r); return r; }

// (public) this / a
function bnDivide(a) { var r = nbi(); this.divRemTo(a,r,null); return r; }

// (public) this % a
function bnRemainder(a) { var r = nbi(); this.divRemTo(a,null,r); return r; }

// (public) [this/a,this%a]
function bnDivideAndRemainder(a) {
  var q = nbi(), r = nbi();
  this.divRemTo(a,q,r);
  return new Array(q,r);
}

// (protected) this *= n, this >= 0, 1 < n < DV
function bnpDMultiply(n) {
  this[this.t] = this.am(0,n-1,this,0,0,this.t);
  ++this.t;
  this.clamp();
}

// (protected) this += n << w words, this >= 0
function bnpDAddOffset(n,w) {
  while(this.t <= w) this[this.t++] = 0;
  this[w] += n;
  while(this[w] >= this.DV) {
    this[w] -= this.DV;
    if(++w >= this.t) this[this.t++] = 0;
    ++this[w];
  }
}

// A "null" reducer
function NullExp() {}
function nNop(x) { return x; }
function nMulTo(x,y,r) { x.multiplyTo(y,r); }
function nSqrTo(x,r) { x.squareTo(r); }

NullExp.prototype.convert = nNop;
NullExp.prototype.revert = nNop;
NullExp.prototype.mulTo = nMulTo;
NullExp.prototype.sqrTo = nSqrTo;

// (public) this^e
function bnPow(e) { return this.exp(e,new NullExp()); }

// (protected) r = lower n words of "this * a", a.t <= n
// "this" should be the larger one if appropriate.
function bnpMultiplyLowerTo(a,n,r) {
  var i = Math.min(this.t+a.t,n);
  r.s = 0; // assumes a,this >= 0
  r.t = i;
  while(i > 0) r[--i] = 0;
  var j;
  for(j = r.t-this.t; i < j; ++i) r[i+this.t] = this.am(0,a[i],r,i,0,this.t);
  for(j = Math.min(a.t,n); i < j; ++i) this.am(0,a[i],r,i,0,n-i);
  r.clamp();
}

// (protected) r = "this * a" without lower n words, n > 0
// "this" should be the larger one if appropriate.
function bnpMultiplyUpperTo(a,n,r) {
  --n;
  var i = r.t = this.t+a.t-n;
  r.s = 0; // assumes a,this >= 0
  while(--i >= 0) r[i] = 0;
  for(i = Math.max(n-this.t,0); i < a.t; ++i)
    r[this.t+i-n] = this.am(n-i,a[i],r,0,0,this.t+i-n);
  r.clamp();
  r.drShiftTo(1,r);
}

// Barrett modular reduction
function Barrett(m) {
  // setup Barrett
  this.r2 = nbi();
  this.q3 = nbi();
  BigInteger.ONE.dlShiftTo(2*m.t,this.r2);
  this.mu = this.r2.divide(m);
  this.m = m;
}

function barrettConvert(x) {
  if(x.s < 0 || x.t > 2*this.m.t) return x.mod(this.m);
  else if(x.compareTo(this.m) < 0) return x;
  else { var r = nbi(); x.copyTo(r); this.reduce(r); return r; }
}

function barrettRevert(x) { return x; }

// x = x mod m (HAC 14.42)
function barrettReduce(x) {
  x.drShiftTo(this.m.t-1,this.r2);
  if(x.t > this.m.t+1) { x.t = this.m.t+1; x.clamp(); }
  this.mu.multiplyUpperTo(this.r2,this.m.t+1,this.q3);
  this.m.multiplyLowerTo(this.q3,this.m.t+1,this.r2);
  while(x.compareTo(this.r2) < 0) x.dAddOffset(1,this.m.t+1);
  x.subTo(this.r2,x);
  while(x.compareTo(this.m) >= 0) x.subTo(this.m,x);
}

// r = x^2 mod m; x != r
function barrettSqrTo(x,r) { x.squareTo(r); this.reduce(r); }

// r = x*y mod m; x,y != r
function barrettMulTo(x,y,r) { x.multiplyTo(y,r); this.reduce(r); }

Barrett.prototype.convert = barrettConvert;
Barrett.prototype.revert = barrettRevert;
Barrett.prototype.reduce = barrettReduce;
Barrett.prototype.mulTo = barrettMulTo;
Barrett.prototype.sqrTo = barrettSqrTo;

// (public) this^e % m (HAC 14.85)
function bnModPow(e,m) {
  var i = e.bitLength(), k, r = nbv(1), z;
  if(i <= 0) return r;
  else if(i < 18) k = 1;
  else if(i < 48) k = 3;
  else if(i < 144) k = 4;
  else if(i < 768) k = 5;
  else k = 6;
  if(i < 8)
    z = new Classic(m);
  else if(m.isEven())
    z = new Barrett(m);
  else
    z = new Montgomery(m);

  // precomputation
  var g = new Array(), n = 3, k1 = k-1, km = (1<<k)-1;
  g[1] = z.convert(this);
  if(k > 1) {
    var g2 = nbi();
    z.sqrTo(g[1],g2);
    while(n <= km) {
      g[n] = nbi();
      z.mulTo(g2,g[n-2],g[n]);
      n += 2;
    }
  }

  var j = e.t-1, w, is1 = true, r2 = nbi(), t;
  i = nbits(e[j])-1;
  while(j >= 0) {
    if(i >= k1) w = (e[j]>>(i-k1))&km;
    else {
      w = (e[j]&((1<<(i+1))-1))<<(k1-i);
      if(j > 0) w |= e[j-1]>>(this.DB+i-k1);
    }

    n = k;
    while((w&1) == 0) { w >>= 1; --n; }
    if((i -= n) < 0) { i += this.DB; --j; }
    if(is1) {	// ret == 1, don't bother squaring or multiplying it
      g[w].copyTo(r);
      is1 = false;
    }
    else {
      while(n > 1) { z.sqrTo(r,r2); z.sqrTo(r2,r); n -= 2; }
      if(n > 0) z.sqrTo(r,r2); else { t = r; r = r2; r2 = t; }
      z.mulTo(r2,g[w],r);
    }

    while(j >= 0 && (e[j]&(1<<i)) == 0) {
      z.sqrTo(r,r2); t = r; r = r2; r2 = t;
      if(--i < 0) { i = this.DB-1; --j; }
    }
  }
  return z.revert(r);
}

// (public) gcd(this,a) (HAC 14.54)
function bnGCD(a) {
  var x = (this.s<0)?this.negate():this.clone();
  var y = (a.s<0)?a.negate():a.clone();
  if(x.compareTo(y) < 0) { var t = x; x = y; y = t; }
  var i = x.getLowestSetBit(), g = y.getLowestSetBit();
  if(g < 0) return x;
  if(i < g) g = i;
  if(g > 0) {
    x.rShiftTo(g,x);
    y.rShiftTo(g,y);
  }
  while(x.signum() > 0) {
    if((i = x.getLowestSetBit()) > 0) x.rShiftTo(i,x);
    if((i = y.getLowestSetBit()) > 0) y.rShiftTo(i,y);
    if(x.compareTo(y) >= 0) {
      x.subTo(y,x);
      x.rShiftTo(1,x);
    }
    else {
      y.subTo(x,y);
      y.rShiftTo(1,y);
    }
  }
  if(g > 0) y.lShiftTo(g,y);
  return y;
}

// (protected) this % n, n < 2^26
function bnpModInt(n) {
  if(n <= 0) return 0;
  var d = this.DV%n, r = (this.s<0)?n-1:0;
  if(this.t > 0)
    if(d == 0) r = this[0]%n;
    else for(var i = this.t-1; i >= 0; --i) r = (d*r+this[i])%n;
  return r;
}

// (public) 1/this % m (HAC 14.61)
function bnModInverse(m) {
  var ac = m.isEven();
  if((this.isEven() && ac) || m.signum() == 0) return BigInteger.ZERO;
  var u = m.clone(), v = this.clone();
  var a = nbv(1), b = nbv(0), c = nbv(0), d = nbv(1);
  while(u.signum() != 0) {
    while(u.isEven()) {
      u.rShiftTo(1,u);
      if(ac) {
        if(!a.isEven() || !b.isEven()) { a.addTo(this,a); b.subTo(m,b); }
        a.rShiftTo(1,a);
      }
      else if(!b.isEven()) b.subTo(m,b);
      b.rShiftTo(1,b);
    }
    while(v.isEven()) {
      v.rShiftTo(1,v);
      if(ac) {
        if(!c.isEven() || !d.isEven()) { c.addTo(this,c); d.subTo(m,d); }
        c.rShiftTo(1,c);
      }
      else if(!d.isEven()) d.subTo(m,d);
      d.rShiftTo(1,d);
    }
    if(u.compareTo(v) >= 0) {
      u.subTo(v,u);
      if(ac) a.subTo(c,a);
      b.subTo(d,b);
    }
    else {
      v.subTo(u,v);
      if(ac) c.subTo(a,c);
      d.subTo(b,d);
    }
  }
  if(v.compareTo(BigInteger.ONE) != 0) return BigInteger.ZERO;
  if(d.compareTo(m) >= 0) return d.subtract(m);
  if(d.signum() < 0) d.addTo(m,d); else return d;
  if(d.signum() < 0) return d.add(m); else return d;
}

var lowprimes = [2,3,5,7,11,13,17,19,23,29,31,37,41,43,47,53,59,61,67,71,73,79,83,89,97,101,103,107,109,113,127,131,137,139,149,151,157,163,167,173,179,181,191,193,197,199,211,223,227,229,233,239,241,251,257,263,269,271,277,281,283,293,307,311,313,317,331,337,347,349,353,359,367,373,379,383,389,397,401,409,419,421,431,433,439,443,449,457,461,463,467,479,487,491,499,503,509];
var lplim = (1<<26)/lowprimes[lowprimes.length-1];

// (public) test primality with certainty >= 1-.5^t
function bnIsProbablePrime(t) {
  var i, x = this.abs();
  if(x.t == 1 && x[0] <= lowprimes[lowprimes.length-1]) {
    for(i = 0; i < lowprimes.length; ++i)
      if(x[0] == lowprimes[i]) return true;
    return false;
  }
  if(x.isEven()) return false;
  i = 1;
  while(i < lowprimes.length) {
    var m = lowprimes[i], j = i+1;
    while(j < lowprimes.length && m < lplim) m *= lowprimes[j++];
    m = x.modInt(m);
    while(i < j) if(m%lowprimes[i++] == 0) return false;
  }
  return x.millerRabin(t);
}

// (protected) true if probably prime (HAC 4.24, Miller-Rabin)
function bnpMillerRabin(t) {
  var n1 = this.subtract(BigInteger.ONE);
  var k = n1.getLowestSetBit();
  if(k <= 0) return false;
  var r = n1.shiftRight(k);
  t = (t+1)>>1;
  if(t > lowprimes.length) t = lowprimes.length;
  var a = nbi();
  for(var i = 0; i < t; ++i) {
    a.fromInt(lowprimes[i]);
    var y = a.modPow(r,this);
    if(y.compareTo(BigInteger.ONE) != 0 && y.compareTo(n1) != 0) {
      var j = 1;
      while(j++ < k && y.compareTo(n1) != 0) {
        y = y.modPowInt(2,this);
        if(y.compareTo(BigInteger.ONE) == 0) return false;
      }
      if(y.compareTo(n1) != 0) return false;
    }
  }
  return true;
}

// protected
BigInteger.prototype.chunkSize = bnpChunkSize;
BigInteger.prototype.toRadix = bnpToRadix;
BigInteger.prototype.fromRadix = bnpFromRadix;
BigInteger.prototype.fromNumber = bnpFromNumber;
BigInteger.prototype.bitwiseTo = bnpBitwiseTo;
BigInteger.prototype.changeBit = bnpChangeBit;
BigInteger.prototype.addTo = bnpAddTo;
BigInteger.prototype.dMultiply = bnpDMultiply;
BigInteger.prototype.dAddOffset = bnpDAddOffset;
BigInteger.prototype.multiplyLowerTo = bnpMultiplyLowerTo;
BigInteger.prototype.multiplyUpperTo = bnpMultiplyUpperTo;
BigInteger.prototype.modInt = bnpModInt;
BigInteger.prototype.millerRabin = bnpMillerRabin;

// public
BigInteger.prototype.clone = bnClone;
BigInteger.prototype.intValue = bnIntValue;
BigInteger.prototype.byteValue = bnByteValue;
BigInteger.prototype.shortValue = bnShortValue;
BigInteger.prototype.signum = bnSigNum;
BigInteger.prototype.toByteArray = bnToByteArray;
BigInteger.prototype.equals = bnEquals;
BigInteger.prototype.min = bnMin;
BigInteger.prototype.max = bnMax;
BigInteger.prototype.and = bnAnd;
BigInteger.prototype.or = bnOr;
BigInteger.prototype.xor = bnXor;
BigInteger.prototype.andNot = bnAndNot;
BigInteger.prototype.not = bnNot;
BigInteger.prototype.shiftLeft = bnShiftLeft;
BigInteger.prototype.shiftRight = bnShiftRight;
BigInteger.prototype.getLowestSetBit = bnGetLowestSetBit;
BigInteger.prototype.bitCount = bnBitCount;
BigInteger.prototype.testBit = bnTestBit;
BigInteger.prototype.setBit = bnSetBit;
BigInteger.prototype.clearBit = bnClearBit;
BigInteger.prototype.flipBit = bnFlipBit;
BigInteger.prototype.add = bnAdd;
BigInteger.prototype.subtract = bnSubtract;
BigInteger.prototype.multiply = bnMultiply;
BigInteger.prototype.divide = bnDivide;
BigInteger.prototype.remainder = bnRemainder;
BigInteger.prototype.divideAndRemainder = bnDivideAndRemainder;
BigInteger.prototype.modPow = bnModPow;
BigInteger.prototype.modInverse = bnModInverse;
BigInteger.prototype.pow = bnPow;
BigInteger.prototype.gcd = bnGCD;
BigInteger.prototype.isProbablePrime = bnIsProbablePrime;

// BigInteger interfaces not implemented in jsbn:

// BigInteger(int signum, byte[] magnitude)
// double doubleValue()
// float floatValue()
// int hashCode()
// long longValue()
// static BigInteger valueOf(long val)




//HPM Security rng.js
//Author: Tom Wu
//tjw@cs.Stanford.EDU
//Random number generator - requires a PRNG backend, e.g. prng4.js

//For best results, put code like
//<body onClick='rng_seed_time();' onKeyPress='rng_seed_time();'>
//in your main HTML document.

function SecureRandom() {
this.rng_state;
this.rng_pool;
this.rng_pptr;


// Mix in a 32-bit integer into the pool
this.rng_seed_int = function(x) {
  this.rng_pool[this.rng_pptr++] ^= x & 255;
  this.rng_pool[this.rng_pptr++] ^= (x >> 8) & 255;
  this.rng_pool[this.rng_pptr++] ^= (x >> 16) & 255;
  this.rng_pool[this.rng_pptr++] ^= (x >> 24) & 255;
  if(this.rng_pptr >= rng_psize) this.rng_pptr -= rng_psize;
}

// Mix in the current time (w/milliseconds) into the pool
this.rng_seed_time = function() {
  this.rng_seed_int(new Date().getTime());
}

// Initialize the pool with junk if needed.
if(this.rng_pool == null) {
  this.rng_pool = new Array();
  this.rng_pptr = 0;
  var t;
  if(navigator.appName == "Netscape" && navigator.appVersion < "5" && window.crypto && window.crypto.random) {
    // Extract entropy (256 bits) from NS4 RNG if available
    var z = window.crypto.random(32);
    for(t = 0; t < z.length; ++t)
      this.rng_pool[this.rng_pptr++] = z.charCodeAt(t) & 255;
  }
  while(this.rng_pptr < rng_psize) {  // extract some randomness from Math.random()
    t = Math.floor(65536 * Math.random());
    this.rng_pool[this.rng_pptr++] = t >>> 8;
    this.rng_pool[this.rng_pptr++] = t & 255;
  }
  this.rng_pptr = 0;
  this.rng_seed_time();
  //this.rng_seed_int(window.screenX);
  //this.rng_seed_int(window.screenY);
}

this.rng_get_byte = function() {
  if(this.rng_state == null) {
   this.rng_seed_time();
    this.rng_state = prng_newstate();
    this.rng_state.init(this.rng_pool);
    for(this.rng_pptr = 0; this.rng_pptr < this.rng_pool.length; ++this.rng_pptr)
      this.rng_pool[this.rng_pptr] = 0;
    this.rng_pptr = 0;
    //this.rng_pool = null;
  }
  // TODO: allow reseeding after first request
  return this.rng_state.next();
}

//public function
this.nextBytes = function(ba) {
  var i;
  for(i = 0; i < ba.length; ++i) ba[i] = this.rng_get_byte();
}
}






//HPM Security prng4.js
//Author: Tom Wu
//tjw@cs.Stanford.EDU
//prng4.js - uses Arcfour as a PRNG

function Arcfour() {
this.i = 0;
this.j = 0;
this.S = new Array();
}

//Initialize arcfour context from key, an array of ints, each from [0..255]
function ARC4init(key) {
var i, j, t;
for(i = 0; i < 256; ++i)
this.S[i] = i;
j = 0;
for(i = 0; i < 256; ++i) {
j = (j + this.S[i] + key[i % key.length]) & 255;
t = this.S[i];
this.S[i] = this.S[j];
this.S[j] = t;
}
this.i = 0;
this.j = 0;
}

function ARC4next() {
var t;
this.i = (this.i + 1) & 255;
this.j = (this.j + this.S[this.i]) & 255;
t = this.S[this.i];
this.S[this.i] = this.S[this.j];
this.S[this.j] = t;
return this.S[(t + this.S[this.i]) & 255];
}

Arcfour.prototype.init = ARC4init;
Arcfour.prototype.next = ARC4next;

//Plug in your RNG constructor here
function prng_newstate() {
return new Arcfour();
}

//Pool size must be a multiple of 4 and greater than 32.
//An array of bytes the size of the pool will be passed to init()
var rng_psize = 256;





//HPM Security rsa.js
/*----------------------------------------------------------------------------*/
// Copyright (c) 2009 pidder <www.pidder.com>
// Permission to use, copy, modify, and/or distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice appear in all copies.
//
// THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
// WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
// ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
// WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
// ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
// OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
/*----------------------------------------------------------------------------*/
/**
*
*  PKCS#1 encryption-style padding (type 2) En- / Decryption for use in
*  pidCrypt Library. The pidCrypt RSA module is based on the implementation
*  by Tom Wu.
*  See http://www-cs-students.stanford.edu/~tjw/jsbn/ for details and for his
*  great job.
*
*  Depends on pidCrypt (pidcrypt.js, pidcrypt_util.js), BigInteger (jsbn.js),
*  random number generator (rng.js) and a PRNG backend (prng4.js) (the random
*  number scripts are only needed for key generation).
/*----------------------------------------------------------------------------*/
/*
* Copyright (c) 2003-2005  Tom Wu
* All Rights Reserved.
*
* Permission is hereby granted, free of charge, to any person obtaining
* a copy of this software and associated documentation files (the
* "Software"), to deal in the Software without restriction, including
* without limitation the rights to use, copy, modify, merge, publish,
* distribute, sublicense, and/or sell copies of the Software, and to
* permit persons to whom the Software is furnished to do so, subject to
* the following conditions:
*
* The above copyright notice and this permission notice shall be
* included in all copies or substantial portions of the Software.
*
* THE SOFTWARE IS PROVIDED "AS-IS" AND WITHOUT WARRANTY OF ANY KIND,
* EXPRESS, IMPLIED OR OTHERWISE, INCLUDING WITHOUT LIMITATION, ANY
* WARRANTY OF MERCHANTABILITY OR FITNESS FOR A PARTICULAR PURPOSE.
*
* IN NO EVENT SHALL TOM WU BE LIABLE FOR ANY SPECIAL, INCIDENTAL,
* INDIRECT OR CONSEQUENTIAL DAMAGES OF ANY KIND, OR ANY DAMAGES WHATSOEVER
* RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER OR NOT ADVISED OF
* THE POSSIBILITY OF DAMAGE, AND ON ANY THEORY OF LIABILITY, ARISING OUT
* OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
*
* In addition, the following condition applies:
*
* All redistributions must retain an intact copy of this copyright notice
* and disclaimer.
*/
//Address all questions regarding this license to:
// Tom Wu
// tjw@cs.Stanford.EDU
/*----------------------------------------------------------------------------*/
if(typeof(pidCrypt) != 'undefined' &&
  typeof(BigInteger) != 'undefined' &&//must have for rsa
  typeof(SecureRandom) != 'undefined' &&//only needed for key generation
  typeof(Arcfour) != 'undefined'//only needed for key generation
)
{

// Author: Tom Wu
// tjw@cs.Stanford.EDU
   // convert a (hex) string to a bignum object
       function parseBigInt(str,r) {
         return new BigInteger(str,r);
       }

       function linebrk(s,n) {
         var ret = "";
         var i = 0;
         while(i + n < s.length) {
           ret += s.substring(i,i+n) + "\n";
           i += n;
         }
         return ret + s.substring(i,s.length);
       }

       function byte2Hex(b) {
         if(b < 0x10)
           return "0" + b.toString(16);
         else
           return b.toString(16);
       }

       // Undo PKCS#1 (type 2, random) padding and, if valid, return the plaintext
       function pkcs1unpad2(d,n) {
         var b = d.toByteArray();
         var i = 0;
         while(i < b.length && b[i] == 0) ++i;
         if(b.length-i != n-1 || b[i] != 2)
           return null;
         ++i;
         while(b[i] != 0)
           if(++i >= b.length) return null;
         var ret = "";
         while(++i < b.length)
           ret += String.fromCharCode(b[i]);
         return ret;
       }

   // PKCS#1 (type 2, random) pad input string s to n bytes, and return a bigint
       function pkcs1pad2(s,n) {
         if(n < s.length + 11) {
           alert("Message too long for RSA");
           return null;
         }
         var ba = new Array();
         var i = s.length - 1;
         while(i >= 0 && n > 0) {ba[--n] = s.charCodeAt(i--);};
         ba[--n] = 0;
         var rng = new SecureRandom();
         var x = new Array();
         while(n > 2) { // random non-zero pad
           x[0] = 0;
           while(x[0] == 0) rng.nextBytes(x);
           ba[--n] = x[0];
         }
         ba[--n] = 2;
         ba[--n] = 0;
         return new BigInteger(ba);
       }
   //RSA key constructor
   pidCrypt.RSA = function() {
     this.n = null;
     this.e = 0;
     this.d = null;
     this.p = null;
     this.q = null;
     this.dmp1 = null;
     this.dmq1 = null;
     this.coeff = null;

   }
   // protected
   // Perform raw private operation on "x": return x^d (mod n)
   pidCrypt.RSA.prototype.doPrivate = function(x) {
     if(this.p == null || this.q == null)
       return x.modPow(this.d, this.n);

     // TODO: re-calculate any missing CRT params
     var xp = x.mod(this.p).modPow(this.dmp1, this.p);
     var xq = x.mod(this.q).modPow(this.dmq1, this.q);

     while(xp.compareTo(xq) < 0)
       xp = xp.add(this.p);
     return xp.subtract(xq).multiply(this.coeff).mod(this.p).multiply(this.q).add(xq);
   }


   // Set the public key fields N and e from hex strings
   pidCrypt.RSA.prototype.setPublic = function(N,E,radix) {
     if (typeof(radix) == 'undefined') radix = 16;

     if(N != null && E != null && N.length > 0 && E.length > 0) {
       this.n = parseBigInt(N,radix);
       this.e = parseInt(E,radix);
     }
     else
       alert("Invalid RSA public key");

//      alert('N='+this.n+'\nE='+this.e);
//document.writeln('Schlüssellaenge = ' + this.n.toString().length +'<BR>');
   }

   // Perform raw public operation on "x": return x^e (mod n)
   pidCrypt.RSA.prototype.doPublic = function(x) {
     return x.modPowInt(this.e, this.n);
   }

   // Return the PKCS#1 RSA encryption of "text" as an even-length hex string
   pidCrypt.RSA.prototype.encryptRaw = function(text) {
     var m = pkcs1pad2(text,(this.n.bitLength()+7)>>3);
     if(m == null) return null;
     var c = this.doPublic(m);
     if(c == null) return null;
     var h = c.toString(16);
     if((h.length & 1) == 0) return h; else return "0" + h;
   }

   pidCrypt.RSA.prototype.encrypt = function(text) {
     //base64 coding for supporting 8bit chars
     // PAY-7219: In order to support 16-bit characters, set optional parameter 'utf8encode' to 'true'
     // then it will encode Unicode string into UTF-8. On the server side, we always decode string as UTF-8 already.
     text = pidCryptUtil.encodeBase64(text, true);
     return this.encryptRaw(text)
   }
   // Return the PKCS#1 RSA decryption of "ctext".
   // "ctext" is an even-length hex string and the output is a plain string.
   pidCrypt.RSA.prototype.decryptRaw = function(ctext) {
//    alert('N='+this.n+'\nE='+this.e+'\nD='+this.d+'\nP='+this.p+'\nQ='+this.q+'\nDP='+this.dmp1+'\nDQ='+this.dmq1+'\nC='+this.coeff);
     var c = parseBigInt(ctext, 16);
     var m = this.doPrivate(c);
     if(m == null) return null;
     return pkcs1unpad2(m, (this.n.bitLength()+7)>>3)
   }

   pidCrypt.RSA.prototype.decrypt = function(ctext) {
     var str = this.decryptRaw(ctext)
     //base64 coding for supporting 8bit chars
     // According to PAY-7219, set optional parameter 'utf8encode' to 'true'
     // to properly decode multi-bytes character.
     str = (str) ? pidCryptUtil.decodeBase64(str, true) : "";
     return str;
   }

/*
   // Return the PKCS#1 RSA encryption of "text" as a Base64-encoded string
   pidCrypt.RSA.prototype.b64_encrypt = function(text) {
     var h = this.encrypt(text);
     if(h) return hex2b64(h); else return null;
   }
*/
   // Set the private key fields N, e, and d from hex strings
   pidCrypt.RSA.prototype.setPrivate = function(N,E,D,radix) {
     if (typeof(radix) == 'undefined') radix = 16;

     if(N != null && E != null && N.length > 0 && E.length > 0) {
       this.n = parseBigInt(N,radix);
       this.e = parseInt(E,radix);
       this.d = parseBigInt(D,radix);
     }
     else
       alert("Invalid RSA private key");
   }

   // Set the private key fields N, e, d and CRT params from hex strings
   pidCrypt.RSA.prototype.setPrivateEx = function(N,E,D,P,Q,DP,DQ,C,radix) {
       if (typeof(radix) == 'undefined') radix = 16;

       if(N != null && E != null && N.length > 0 && E.length > 0) {
       this.n = parseBigInt(N,radix);//modulus
       this.e = parseInt(E,radix);//publicExponent
       this.d = parseBigInt(D,radix);//privateExponent
       this.p = parseBigInt(P,radix);//prime1
       this.q = parseBigInt(Q,radix);//prime2
       this.dmp1 = parseBigInt(DP,radix);//exponent1
       this.dmq1 = parseBigInt(DQ,radix);//exponent2
       this.coeff = parseBigInt(C,radix);//coefficient
     }
     else
       alert("Invalid RSA private key");
//    alert('N='+this.n+'\nE='+this.e+'\nD='+this.d+'\nP='+this.p+'\nQ='+this.q+'\nDP='+this.dmp1+'\nDQ='+this.dmq1+'\nC='+this.coeff);

   }

   // Generate a new random private key B bits long, using public expt E
   pidCrypt.RSA.prototype.generate = function(B,E) {
     var rng = new SecureRandom();
     var qs = B>>1;
     this.e = parseInt(E,16);
     var ee = new BigInteger(E,16);
     for(;;) {
       for(;;) {
         this.p = new BigInteger(B-qs,1,rng);
         if(this.p.subtract(BigInteger.ONE).gcd(ee).compareTo(BigInteger.ONE) == 0 && this.p.isProbablePrime(10)) break;
       }
       for(;;) {
         this.q = new BigInteger(qs,1,rng);
         if(this.q.subtract(BigInteger.ONE).gcd(ee).compareTo(BigInteger.ONE) == 0 && this.q.isProbablePrime(10)) break;
       }
       if(this.p.compareTo(this.q) <= 0) {
         var t = this.p;
         this.p = this.q;
         this.q = t;
       }
       var p1 = this.p.subtract(BigInteger.ONE);
       var q1 = this.q.subtract(BigInteger.ONE);
       var phi = p1.multiply(q1);
       if(phi.gcd(ee).compareTo(BigInteger.ONE) == 0) {
         this.n = this.p.multiply(this.q);
         this.d = ee.modInverse(phi);
         this.dmp1 = this.d.mod(p1);
         this.dmq1 = this.d.mod(q1);
         this.coeff = this.q.modInverse(this.p);
         break;
       }
     }
   }


//pidCrypt extensions start
//
   pidCrypt.RSA.prototype.getASNData = function(tree) {
       var params = {};
       var data = [];
       var p=0;

       if(tree.value && tree.type == 'INTEGER')
         data[p++] = tree.value;
       if(tree.sub)
          for(var i=0;i<tree.sub.length;i++)
          data = data.concat(this.getASNData(tree.sub[i]));

     return data;
   }

//
//
//get parameters from ASN1 structure object created from pidCrypt.ASN1.toHexTree
//e.g. A RSA Public Key gives the ASN structure object:
//{
//  SEQUENCE:
//             {
//                 INTEGER: modulus,
//                 INTEGER: public exponent
//             }
//}
   pidCrypt.RSA.prototype.setKeyFromASN = function(key,asntree) {
      var keys = ['N','E','D','P','Q','DP','DQ','C'];
      var params = {};

      var asnData = this.getASNData(asntree);
      switch(key){
          case 'Public':
          case 'public':
               for(var i=0;i<asnData.length;i++)
                 params[keys[i]] = asnData[i].toLowerCase();
               this.setPublic(params.N,params.E,16);
           break;
          case 'Private':
          case 'private':
               for(var i=1;i<asnData.length;i++)
                 params[keys[i-1]] = asnData[i].toLowerCase();
               this.setPrivateEx(params.N,params.E,params.D,params.P,params.Q,params.DP,params.DQ,params.C,16);
//                 this.setPrivate(params.N,params.E,params.D);
           break;
       }

   }

/**
* Init RSA Encryption with public key.
* @param  asntree: ASN1 structure object created from pidCrypt.ASN1.toHexTree
*/
  pidCrypt.RSA.prototype.setPublicKeyFromASN = function(asntree) {
       this.setKeyFromASN('public',asntree);

   }

/**
* Init RSA Encryption with private key.
* @param  asntree: ASN1 structure object created from pidCrypt.ASN1.toHexTree
*/
   pidCrypt.RSA.prototype.setPrivateKeyFromASN = function(asntree) {
       this.setKeyFromASN('private',asntree);
   }
/**
* gets the current paramters as object.
* @return params: object with RSA parameters
*/
   pidCrypt.RSA.prototype.getParameters = function() {
     var params = {}
     if(this.n != null) params.n = this.n;
     params.e = this.e;
     if(this.d != null) params.d = this.d;
     if(this.p != null) params.p = this.p;
     if(this.q != null) params.q = this.q;
     if(this.dmp1 != null) params.dmp1 = this.dmp1;
     if(this.dmq1 != null) params.dmq1 = this.dmq1;
     if(this.coeff != null) params.c = this.coeff;

     return params;
   }


//pidCrypt extensions end


}


