# -*- coding: utf-8 -*-
import sys
import re
import base64
import hashlib
import datetime

import requests

# Teststrings
# md5(good luck with this one) = 96687e1c0144e4c24eaac7ef4e633458
# md5(Nerds) = 9ed83210a576dd59d6fd48cb2b31b401

# DOWN
# milw0rm.com
# gdataonline.com
# ice.breaker.free.fr
# gdataonline.com

# SOLD
# hashreverse.com
# us.md5.crysm.net
# nz.md5.crysm.net
# hashchecker.com
# md5.xpzone.de
# rednoize.com
# md5oogle.com
# hashmash.com
# macrosoftware.ro

# FAKE
# md5.rednoize.com
# www.cmd5.org
# md5.rednoize.com
# md5pass.com

# CAPTCHA
# md5decrypter.com
# md5decrypter.co.uk
# md5.web-max.ca

# DONE
# md5decryption.com
# md5.my-addr.com/md5_decrypt-md5_cracker_online/md5_decoder_tool.php
# www.md5crack.com/crackmd5.php
# www.tmto.org/pages/passwordtools/hashcracker/
# https://isc.sans.edu/tools/reversehash.html
# md5.noisette.ch/index.php

# TODO
# hash.phelix.lv/md5/9a8f740244cfb27c4defc256a0182763/nerds.htm
# http://wordd.org/9A8F740244CFB27C4DEFC256A0182763

# MAYBE INTERESTING
# www.freerainbowtables.com/de/tables2/

DEBUG = False

def isc_sans_edu_get_token():
    matcher = re.compile('name="token" value="(.*?)" />')
    r = requests.get('https://isc.sans.edu/tools/reversehash.html')
    m = matcher.search(r.text)
    if m: return m.group(1)
    else: return None

class RevMd5:

    md5_matcher = re.compile('^[a-fA-F\d]{32}$')
    
    databases = [
        {
            'name': 'md5decryption.com', 
            'url': 'http://md5decryption.com', 
            'method': 'post', 
            'fieldname': 'hash', 
            'extrafields': {
                'submit': 'Decrypt It!'
            }, 
            'matcher': re.compile('Decrypted Text: </b>(.*?)</font>'),
        }, {
            'name': 'md5.my-addr.com', 
            'url': 'http://md5.my-addr.com/md5_decrypt-md5_cracker_online/md5_decoder_tool.php', 
            'method': 'post', 
            'fieldname': 'md5', 
            'extrafields': {
                'x': 25,
                'y': 3,
            }, 
            'matcher': re.compile('Hashed string</span>: (.*?)</div>')
        }, {
            'name': 'md5crack.com',
            'url': 'http://www.md5crack.com/home',
            'method': 'post', 
            'fieldname': 'list',
            'extrafields': {
            	'crack': 'Crack Hashes',
            },
            'matcher': re.compile('</strong>: (.*?)</p>'),
        }, {
            'name': 'tmto.org',
            'url': 'http://www.tmto.org/api/latest/',
            'method': 'get', 
            'fieldname': 'hash',
            'extrafields': {
            	'auth': hashlib.sha256('%s%s%s' % (datetime.date.today().year, datetime.date.today().month, datetime.date.today().day)).hexdigest()
            },
            'matcher': re.compile('text="(.*?)" />'),
            'post': base64.b64decode
        }, {
            'name': 'isc.sans.edu',
            'url': 'https://isc.sans.edu/tools/reversehash.html',
            'method': 'post', 
            'fieldname': 'text',
            'extrafields': {
            	'token': isc_sans_edu_get_token
            },
            'matcher': re.compile('= (.*?)[ ]*</p><br />'),
        }, {
            'name': 'md5.noisette.ch',
            'url': 'http://md5.noisette.ch/index.php',
            'method': 'post', 
            'fieldname': 'hash',
            'extrafields': {},
            'matcher': re.compile('String to hash : <input name="text" value="(.*?)"/>'),
        }
    ]
    
    def request(self, method, url, hashname, hash, payload):
        payload[hashname] = hash
        if method == 'post':
            r = requests.post(url, data=payload)
        elif method == 'get':
            r = requests.get(url, params=payload)
        else:
            print 'METHOD NOT IMPLEMENTED'
            exit()
            
        if DEBUG: print r.url
        return r.text
    
    def reverse(self, hash, only_service = None):
        ret = {}
        for database in self.databases:
        
            # filter for testing purposes
            if only_service:
                if database['name'] != only_service:
                    continue
            rev = 'NOT FOUND'
            
            # call callables
            for field in database['extrafields']:
                if hasattr(database['extrafields'][field], '__call__'):
                    database['extrafields'][field] = database['extrafields'][field]()
            
            # make request
            data = self.request(
                database['method'], 
                database['url'], 
                database['fieldname'], 
                database['pre'](hash) if 'pre' in database else hash, 
                database['extrafields']
            )

            # find unhashed string in response
            match = database['matcher'].search(data)
            if DEBUG: print match
            if match:
                rev = match.group(1).strip()
                if 'post' in database:
                    rev = database['post'](rev)
            ret[database['name']] = rev
        return ret

    def is_valid(self, hash):
        return self.md5_matcher.match(hash)

    def stats(self):
        ret = {}
        for database in self.databases:
            ret[database['name']] = 'NOT IMPLEMENTED YET'
        return ret

if __name__ == '__main__':
    if len(sys.argv) >= 2:
        revmd5 = RevMd5()
        for hash in sys.argv[1:]:
            print hash,
            if revmd5.is_valid(hash):
                print revmd5.reverse(hash)
            else:
                print '*INVALID'
    else: print '%s <MD5HASHES>' % sys.argv[0]
