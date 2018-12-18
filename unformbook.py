import sys
import os
import argparse

from Crypto.Hash import SHA

class FormBook():

    def __init__(self, filename):
        import json
        import r2pipe
        from perichheaderparser import PERichHeaderParser, find_pe
        
        self.filename = filename
        
        if find_pe(open(filename, 'rb').read()) is not None:
            p = PERichHeaderParser(filename)
            masm_detected, version = p.detect_MASM()
            if masm_detected:
                print '[+] MASM detected. Version %s. FormBook candidate. Continue...' % version
                
                self.r2 = r2pipe.open(filename)
                self.r2.cmd('e scr.color = 0')
                self.r2.cmd('aaaa')
                
                # Finfing all the malware functions
                functions = self.r2.cmdj('aflj')
                enc_buffers = []
                self.enc_buffers = []
                for sub in functions:
                    self.r2.cmd('s 0x%08x' % sub['offset'])  # Seek to each function offset
                    dasm = json.loads(self.r2.cmd('pdj 1'))  # Dissasemble first function instruction
                    if dasm[0]['bytes'] == 'e800000000':  # Check for call $+5
                        enc_buffers.append(sub['offset'])
                if len(enc_buffers) == 34:
                    print "[+] Number of encbuffers is ok. Continue..."
                    enc_buffers_selection = [
                        enc_buffers[14],
                        enc_buffers[15],
                        enc_buffers[6],
                        enc_buffers[5],
                        enc_buffers[7],
                        enc_buffers[8],
                    ]
                    
                    for e in enc_buffers_selection:
                        # Go to offset
                        self.r2.cmd('s 0x%08x' % json.loads(self.r2.cmd("axtj %s" % '0x{0:08X}'.format(e)))[0]['from'])
                        
                        i = 1
                        while json.loads(self.r2.cmd('pdj -%s' % str(i)))[0]['type'] != 'push':
                            i += 1

                        self.enc_buffers.append({ 
                            'addr': e, 
                            'size': json.loads(self.r2.cmd('pdj -%s' % str(i)))[0]['val']
                        })

                else:
                    print '[!] FormBook encbuffers length is not 34. Script should consider this case so, contact the developer. Exiting...'
                    self.exit = True
            else:
                print '[!] MASM not detected. This is not FormBook or maybe it\'s packed. Exiting...'
                self.exit = True
        else:
            print '[!] File is not a valid PE. Exiting...'
            self.exit = True

    @staticmethod
    def sha1(input_buffer):
        '''
        Custom SHA-1 implementation made by FormBook. Byte swapping the array of five 32-bits integer
        '''
        def sha1_revert(digest):
            import struct
            tuples = struct.unpack("<IIIII", digest)
            output_hash = ""
            for item in tuples:
                output_hash += struct.pack(">I", item)
            return output_hash

        sha1 = SHA.new()
        sha1.update(input_buffer)
        return sha1_revert(sha1.digest())


    @staticmethod
    def hash_function(hash_string):
        from crccheck.crc import Crc32Bzip2
        return Crc32Bzip2.calc(bytearray(hash_string.lower(), encoding='utf-8'))


    @staticmethod
    def string_byte_substraction(input_string, sub):
        return "".join([chr((ord(c) - 1 - sub) & 0xFF) for c in input_string])


    @staticmethod
    def decrypt_strings(fb_decrypt, key, encrypted_strings):
        '''
        Encrypted string decryption
        '''
        offset = 0
        i = 0
        f = open('decrypted_strings.txt', 'w')
        while offset < len(encrypted_strings):
            str_len = ord(encrypted_strings[offset])
            offset += 1
            dec_str = fb_decrypt.decrypt_func2(encrypted_strings[offset:offset+str_len], key)
            dec_str = dec_str[:-1]  # remove '\0' character
            line = '{:d} {:s}'.format(i, dec_str)
            print line
            print line
            offset += str_len
            i += 1
        f.close()

    def decrypt_c2c_uri(self):
        import json
        import r2pipe
        import validators
        sys.path.append(os.path.abspath('external/tildedennis/formbook/'))
        from formbook_decryption import FormBookDecryption

        fb_decrypt = FormBookDecryption()

        encbuf6_addr = '0x{0:08X}'.format(self.enc_buffers[2]['addr'] + 7)
        encbuf7_addr = '0x{0:08X}'.format(self.enc_buffers[5]['addr'] + 7)
        encbuf8_addr = '0x{0:08X}'.format(self.enc_buffers[0]['addr'] + 7)
        encbuf9_addr = '0x{0:08X}'.format(self.enc_buffers[3]['addr'] + 7)
        
        self.r2.cmd('s %s' % encbuf6_addr)
        encbuf6_s0 = self.r2.cmd('p8 %s' % str(self.enc_buffers[2]['size'] * 2)).decode("hex")
        self.r2.cmd('s %s' % encbuf7_addr)
        encbuf7_s0 = self.r2.cmd('p8 %s' % str(self.enc_buffers[5]['size'] * 2)).decode("hex")
        self.r2.cmd('s %s' % encbuf8_addr)
        encbuf8_s0 = self.r2.cmd('p8 %s' % str(self.enc_buffers[0]['size'] * 2)).decode("hex")
        self.r2.cmd('s %s' % encbuf9_addr)
        encbuf9_s0 = self.r2.cmd('p8 %s' % str(self.enc_buffers[3]['size'] * 2)).decode("hex")
        
        rc4_key_two = fb_decrypt.decrypt_func1(encbuf6_s0, self.enc_buffers[2]['size'])
        rc4_key_one = fb_decrypt.decrypt_func1(encbuf7_s0, self.enc_buffers[5]['size'])
        encbuf8_s1 = fb_decrypt.decrypt_func1(encbuf8_s0, self.enc_buffers[0]['size'])
        encbuf9_s1 = fb_decrypt.decrypt_func1(encbuf9_s0, self.enc_buffers[3]['size'])

        rc4_key = FormBook.sha1(encbuf9_s1)
        encbuf8_s2 = fb_decrypt.decrypt_func2(encbuf8_s1, rc4_key)
        
        self.r2.cmd('s 0x%08x' % json.loads(self.r2.cmd("axtj %s" % '0x{0:08X}'.format(self.enc_buffers[0]['addr'])))[0]['from'])

        while json.loads(self.r2.cmd('pdj 1'))[0]['type'] != 'push':
            self.r2.cmd('so 1')
        
        c2_size = json.loads(self.r2.cmd('pdj 1'))[0]['val']
        found = False
        for i, c in enumerate(encbuf8_s2):
            encrypted_c2c_uri = encbuf8_s2[i:i+c2_size]
            encrypted_c2c_uri = fb_decrypt.decrypt_func2(encrypted_c2c_uri, rc4_key_two)
            c2c_uri = fb_decrypt.decrypt_func2(encrypted_c2c_uri, rc4_key_one)
            if validators.url('http://' + '{:s}'.format(c2c_uri).replace('\x00', '')):
                print '[+] C&C URI found: hxxp://{:s}'.format(c2c_uri)
        


def main(argv):
    parser = argparse.ArgumentParser(description='FormBook encbuffers extractor')
    parser.add_argument('file', help='FormBook executable (after unpacking, check asm compiler presence)')
    args = parser.parse_args()
    
    fb = FormBook(args.file)
    
    if not fb.exit:
        fb.decrypt_c2c_uri()
    
    sys.exit()
    
if __name__ == "__main__":
    main(sys.argv)

