#!/usr/bin/env python

#######################################################################################################################
##
## Use Frida to automatically extract injected PE files (injected via RunPE method and MapViewOfSection method)
## 
##
## !!!WARNING: If you use this to extract packed malware run it in a safe VM!!! 
##    There are no protections to stop the malware from infecting the host
##
## !!!DOUBLE WARNING: While this is a useful "first-pass" tool, Frida is userland code 
##    and easily bypassed by decent packers. Use PIN if you want to really boss
##    it up: http://jbremer.org/malware-unpacking-level-pintool/
##
## !!!TRIPLE WARNING: Frida is easily detected if you know what to look for:
##    https://crackinglandia.wordpress.com/2015/11/10/anti-instrumentation-techniques-i-know-youre-there-frida/
##
## !!!FINAL WARNING: use at your own risk! Seriously. 
##
##
#######################################################################################################################

import frida
import sys
import argparse
import os
import time
import json

# import local rebuild module 
import rebuild 


__AUTHOR__ = '@herrcore'



class FridaExtractError(Exception):
   pass

class FridaExtract:
    """
        Extract RunPE injected files
    """
    JS_EXTRACT = "inject_extract.js"

    def __init__(self, cmd, out_file="dump.bin"):
        self.pid = frida.spawn(cmd)
        self.session = frida.attach(self.pid)
        #enable Ducktape runtime
        self.session.disable_jit()
        self.dump = {}
        self.out_file = out_file
        self.raw = False


    def rebuild_pe(self):
        """
            Attempt to reconstruct PE from dumped memory
        """
        reconstructor = rebuild.ParsePE(self.dump)
        #use autobuild to automatically construct PE
        pe_file = reconstructor.auto_build()
        file(self.out_file, 'wb').write(pe_file)

    def dump_raw_sections(self):
        reconstructor = rebuild.ParsePE(self.dump)
        bin_arr = reconstructor.dump_raw_sections()
        count = 0
        for bin_str in bin_arr:
            file("dump"+str(count)+".bin", 'wb').write(bin_str)
            count += 1 

    def dump_raw(self):
        """
            Sort sections by ascending address and dump into file
        """
        reconstructor = rebuild.ParsePE(self.dump)
        blob = reconstructor.dump_raw()
        file(self.out_file, 'wb').write(blob)


    def get_api_addr(self, module_name, api_name):
        """
            Get virtual address for API
        """
        mod_base = 0
        fnt_addr = 0
        flag_found = False
        for x in self.session.enumerate_modules():
            if x.name.upper() == module_name.upper():
                mod_base = x.base_address
                for f in x.enumerate_exports():
                    if f.name.upper() == api_name.upper():
                        flag_found = True
                        fnt_addr = f.relative_address
        if flag_found:
            api_addr = mod_base + fnt_addr
            return api_addr
        else:
            raise FridaExtractError("API not found")
            return -1

    
    def _process_message(self, message, data):
        """
            Frida COMMS
        """
        if message['type'] == 'send':
            stanza = message['payload']
            if stanza['name'] == '+log':
                print stanza['payload'] + "\n"
                try:
                    self.extract.post({ 'type': '+log-ack' })
                except Exception as e:
                    pass

            elif stanza['name'] == '+dump':
                #{"address":<virtual_address>}, data: <bin_string>
                if self.raw:
                    print " ".join([elem.encode("hex")  for elem in data]) + "\n"
                #serialize data and store 
                self.dump[stanza["address"]] = [ord(elem) for elem in data]
                try:
                    self.extract.post({ 'type': '+dump-ack' })
                except Exception as e:
                    pass

            elif stanza['name'] == '+flush':
                print "Flush Message Buffers"
                try:
                    self.extract.post({ 'type': '+flush-ack' })
                except Exception as e:
                    pass

            elif stanza['name'] == '+kill':
                print "Kill Main Process: " + str(stanza['payload']) + "\n"
                frida.kill(self.pid)
                print "Dump Complete!\n\nPress Enter to quit."
                try:
                    self.extract.post({ 'type': '+kill-ack' })
                except Exception as e:
                    pass

            elif stanza['name'] == '+pkill':
                print "Kill Sub-Process: " + str(stanza['payload']) + "\n"
                frida.kill(int(stanza['payload']))
                if self.raw:
                    #self.dump_raw()
                    self.dump_raw_sections()

                else:
                    self.rebuild_pe()
                try:
                    self.extract.post({ 'type': '+pkill-ack' })
                except Exception as e:
                    pass
        else:
            print "==========ERROR=========="
            print message
            print "========================="


    def inject_extract_script(self):
        #TODO: upgade to use frida-compile
        with open(self.JS_EXTRACT) as fp:
            script_js = fp.read()
        self.extract = self.session.create_script(script_js, name="extract.js")
        self.extract.on('message',self._process_message)
        self.extract.load()


    def get_module_ranges(self, modulename, protection):
        """
            Get memory ranges for module that match the supplied protection
        """
        return self.extract.exports.getmoduleranges(modulename, protection)


    def set_protection(self, base, size, protection):
        """
            Set memory protection
        """
        self.extract.exports.setprotection(base, size, protection)


    def set_verbose(self, debug_flag):
        """
            Print trace of all hooked API calls
        """
        self.extract.exports.setverbose(debug_flag)


    def go(self):
        frida.resume(self.pid)



def main():
    parser = argparse.ArgumentParser(description="Extract Injected PE")
    parser.add_argument("infile", help="The file to unpack.")
    parser.add_argument('--args',dest="in_args",default=None,help="Specify arguments for exe as comma seperated list")
    parser.add_argument('--out_file',dest="out_file",default=None,help="Specify the file name to dump the PE. Default: out.bin")
    parser.add_argument('-v','--verbose',dest="verbose",action='store_true',default=False,help="Print hooked API calls.")
    parser.add_argument('--raw',dest="dump_raw",action='store_true',default=False,help="Don't attempt to reconstruct PE, dump raw memory to file.")
    args = parser.parse_args()
    
    infile = args.infile
    filename = os.path.basename(infile)

    cmd = [infile]

    #Frida spawn takes args as a list with [0]=exe
    if args.in_args != None:
        cmd.extend(args.in_args.split(","))

    ### setup ###
    if args.out_file != None:
        frida_driver = FridaExtract(cmd, out_file=args.out_file)
    else:
        frida_driver = FridaExtract(cmd)

    if args.dump_raw:
        frida_driver.raw = True 

    frida_driver.inject_extract_script()

    ### set verbosity ###
    if args.verbose:
        frida_driver.set_verbose(True)

    ### execute! ###
    frida_driver.go()

    ### temporary hack ###
    # keep program open long enough to receive messages 
    raw_input("Started Dump: Press Enter to kill process at any time!\n\n")
    frida.kill(frida_driver.pid)

if __name__ == '__main__':
    main()