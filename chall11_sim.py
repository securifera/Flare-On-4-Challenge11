import struct
import binascii
import sys

class Instr(object):

    def __init__(self, src, dest, br_offset):
        self.src = src
        self.dest = dest
        self.br_offset = br_offset

    def __str__(self):
        ret = "Src: %i\n" % self.src 
        ret +="Dest: %i\n" % self.dest 
        ret +="Next Offset: %i\n" % self.br_offset 
        return ret

def get_next_instr( data, start_off ):

    src = data[start_off]
    dest = data[start_off+1]
    br_off = data[start_off+2]
    return Instr(src, dest, br_off)

def parse_jmps():
    global trace
    tmp_trace = []
    for line in trace:
        if "Branch Taken" in line:
            arr = line.split("#")

            if len(arr) == 2:
                #Split instructions
                first = arr[0]
                first_arr = first.split(":")
                addr = first_arr[0]
                instrs = first_arr[1].strip()
                if instrs == "mem[0x0]{0x0} - mem[0x0]{0x0} = mem[0x0]{0x0}":


                    #Get the branch addr
                    branch = arr[1].split(":")[1].strip()
                    out_str = addr + ":" + " jmp " + branch
                    out_str = "{:70s} {:2s}".format( out_str, "#")
                    tmp_trace.append(out_str)
                    tmp_trace.append("")
                    continue

        
        tmp_trace.append(line)

    trace = tmp_trace


def parse_clears():
    global trace

    tmp_trace = []
    for line in trace:
        arr = line.split("#")

        if len(arr) == 2:
            #Split instructions
            first = arr[0]
            first_arr = first.split(":")
            addr = first_arr[0]
            instrs = first_arr[1].strip()
            instrs = instrs.split(" ")
            if len( instrs ) == 5:

                op1 = instrs[0]
                #print op1
                
                op2 = instrs[2]
                #print op2

                val = instrs[4]
                #print val 

                #raw_input()
                if op1 == op2:

                    val_arr = val.split("{")
                    val = val_arr[0] + " = " + val_arr[1][:-1]
                    out_str = addr + ": " + val
                    out_str = "{:70s} {:2s}".format( out_str, "#")
                    #tmp_trace.append(out_str)
                    continue


        tmp_trace.append(line)

    trace = tmp_trace


def parse_movs():
    global trace

    tmp_trace = []
    i = 0
    while i < len(trace):

        line = trace[i]
        arr = line.split("#")

        if len(arr) == 2:
            #Split instructions
            first = arr[0]
            comment1 = arr[1]
            first_arr = first.split(":")
            addr1 = first_arr[0]
            instrs = first_arr[1].strip()
            instrs = instrs.split(" ")
            if len( instrs ) == 5:

                op1 = instrs[0]
                #print op1
                
                op2 = instrs[2]
                #print op2

                val = instrs[4]
                val_mem = val.split("{")[0]
                #print val_mem 

                #raw_input()
                if op1 == "mem[0x0]{0x0}" and val_mem == "mem[0x0]":

                    #Get next line
                    line2 = trace[i + 1]
                    arr = line2.split("#")

                    #Split instructions
                    first = arr[0]
                    comment2 = arr[1]
                    first_arr = first.split(":")
                    addr = first_arr[0]
                    instrs = first_arr[1].strip()
                    instrs = instrs.split(" ")
                    if len( instrs ) == 5:

                        line2_op1 = instrs[0]
                        line2_op2 = instrs[2]                 
                        line2_val = instrs[4]
                        #print line2_op2

                        op1_val = line2_op1.split("{")[1][:-1]
                        #print op1_val
                        #raw_input()
                        if line2_op2 == val and op1_val == '0x0':

                            #Print the first line
                            out_str = addr1 + ": "
                            out_str = "{:70s} {:2s}".format( out_str, "#")
                            #tmp_trace.append(out_str)

                            #Get the value
                            val2_mem = line2_val.split("{")[0]
                            op2_mem = line2_op2.split("{")[0]
                            val = "*" + val2_mem + " = *" + op2

                            out_str = addr + ": " + val
                            out_str = "{:70s} {:2s}".format( out_str, "#")
                            out_str += comment1 + comment2
                            line = out_str

                            #print line

                            #raw_input()
                            i += 1


        tmp_trace.append(line)
        i += 1

    trace = tmp_trace

def parse_adds():
    global trace

    tmp_trace = []
    i = 0
    while i < len(trace):

        line = trace[i]
        arr = line.split("#")
        print line

        if len(arr) == 2:
            #Split instructions
            first = arr[0]
            comment1 = arr[1]
            first_arr = first.split(":")
            addr1 = first_arr[0]
            instrs = first_arr[1].strip()
            instrs = instrs.split(" ")
            if len( instrs ) == 5:

                op1 = instrs[0]
                #print op1
                
                op2 = instrs[2]
                #print op2

                val = instrs[4]
                val_mem = val.split("{")[0]
                #print val_mem 

                #raw_input()
                if op1 == "mem[0x0]{0x0}" and val_mem == "mem[0x0]":

                    #Get next line
                    line2 = trace[i + 1]
                    arr = line2.split("#")
                    print line2
                    raw_input()

                    #Split instructions
                    first = arr[0]
                    comment2 = arr[1]
                    first_arr = first.split(":")
                    addr = first_arr[0]
                    instrs = first_arr[1].strip()
                    instrs = instrs.split(" ")
                    if len( instrs ) == 5:

                        line2_op1 = instrs[0]
                        line2_op2 = instrs[2]                 
                        line2_val = instrs[4]
                        #print line2_op2

                        op1_val = line2_op1.split("{")[1][:-1]
                        #print op1_val
                        #raw_input()
                        if line2_op2 == val and op1_val != '0x0':

                            out_str = addr1 + ": "
                            out_str = "{:70s} {:2s}".format( out_str, "#")
                            #tmp_trace.append(out_str)

                            val2_mem = line2_val.split("{")[0]
                            op2_mem = line2_op2.split("{")[0]
                            val = line2_op1 + " + " + op2 + " = " + line2_val

                            out_str = addr + ": " + val
                            out_str = "{:70s} {:2s}".format( out_str, "#")
                            out_str += comment1 + comment2
                            line = out_str

                            #print line

                            raw_input()
                            i += 1


        tmp_trace.append(line)
        i += 1

    trace = tmp_trace

def parse_shift_left():
    global trace

    tmp_trace = []
    i = 0
    while i < len(trace):

        line = trace[i]
        arr = line.split("#")

        if len(arr) == 2:
            #Split instructions
            first = arr[0]
            comment1 = arr[1]
            first_arr = first.split(":")
            addr1 = first_arr[0]
            instrs = first_arr[1].strip()
            instrs = instrs.split(" ")
            if len( instrs ) == 5:

                op1 = instrs[0]
                #print op1
                
                op2 = instrs[2]
                #print op2

                val = instrs[4]
                val_mem = val.split("{")[0]
                #print val_mem 

                #raw_input()
                if op1 == "mem[0x0]{0x0}" and val_mem == "mem[0x0]":

                    #Get next line
                    line2 = trace[i + 1]
                    arr = line2.split("#")

                    #Split instructions
                    first = arr[0]
                    comment2 = arr[1]
                    first_arr = first.split(":")
                    addr = first_arr[0]
                    instrs = first_arr[1].strip()
                    instrs = instrs.split(" ")
                    if len( instrs ) == 5:

                        line2_op1 = instrs[0]
                        line2_op2 = instrs[2]                 
                        line2_val = instrs[4]
                        #print line2_op2

                        #print hex(op2_val)
                        #raw_input()
                        if line2_op2 == op2:

                            out_str = addr1 + ": "
                            out_str = "{:70s} {:2s}".format( out_str, "#")
                            #tmp_trace.append(out_str)

                            #Get the second op 
                            op2_val = int(line2_op2.split("{")[1][:-1], 16) *2
                            op2_mem = line2_op2.split("{")[0]
                            op2_mem += "{" + hex(op2_val) + "}"

                            val = op1 + " - " + op2_mem + " = " + line2_val

                            out_str = addr + ": " + val
                            out_str = "{:70s} {:2s}".format( out_str, "#")
                            out_str += comment1 + comment2
                            line = out_str


                            #print line
                            #raw_input()
                            i += 1


        tmp_trace.append(line)
        i += 1

    trace = tmp_trace


def add_comments():
    global trace

    tmp_trace = []
    for line in trace:
        arr = line.split("#")

        if len(arr) == 2:
            #Split instructions
            first = arr[0]
            first_arr = first.split(":")
            addr = first_arr[0]
            if addr == "0x1048":
                out_str = "{:70s}{:2s}".format( first, "#")
                out_str += " Check for newline"
                line = out_str
            elif addr == "0x10bb":
                out_str = "{:70s}{:2s}".format( first, "#")
                out_str += " Store input character"
                line = out_str

        tmp_trace.append(line)




    trace = tmp_trace



global trace


#-Line 5185: 0xdef: mem[0xe99]{0x35e8a} - mem[0xe98]{0x1e7be} = mem[0xe99]{0x176cc} # 
#-Line 8515: 0xdef: mem[0xe99]{0x2df13} - mem[0xe98]{0x1e7be} = mem[0xe99]{0xf755}  # 
#-Line 11845: 0xdef: mem[0xe99]{0x2f58e} - mem[0xe98]{0x1e7be} = mem[0xe99]{0x10dd0} # 
#-Line 15174: 0xdef: mem[0xe99]{0x2c89e} - mem[0xe98]{0x1e7be} = mem[0xe99]{0xe0e0}  # 
#-Line 18500: 0xdef: mem[0xe99]{0x3391b} - mem[0xe98]{0x1e7be} = mem[0xe99]{0x1515d} # 
#-Line 21829: 0xdef: mem[0xe99]{0x2c88d} - mem[0xe98]{0x1e7be} = mem[0xe99]{0xe0cf}  # 
#-Line 25155: 0xdef: mem[0xe99]{0x2f59b} - mem[0xe98]{0x1e7be} = mem[0xe99]{0x10ddd} # 
#-Line 28483: 0xdef: mem[0xe99]{0x36d9c} - mem[0xe98]{0x1e7be} = mem[0xe99]{0x185de} # 
#-Line 31809: 0xdef: mem[0xe99]{0x36616} - mem[0xe98]{0x1e7be} = mem[0xe99]{0x17e58} # 
#-Line 35135: 0xdef: mem[0xe99]{0x340a0} - mem[0xe98]{0x1e7be} = mem[0xe99]{0x158e2} # 
#-Line 38461: 0xdef: mem[0xe99]{0x2d79b} - mem[0xe98]{0x1e7be} = mem[0xe99]{0xefdd}  # 
#-Line 41787: 0xdef: mem[0xe99]{0x2c89e} - mem[0xe98]{0x1e7be} = mem[0xe99]{0xe0e0}  # 
#-Line 45113: 0xdef: mem[0xe99]{0x2df0c} - mem[0xe98]{0x1e7be} = mem[0xe99]{0xf74e}  # 
#-Line 48439: 0xdef: mem[0xe99]{0x36d8d} - mem[0xe98]{0x1e7be} = mem[0xe99]{0x185cf} # 
#-Line 51765: 0xdef: mem[0xe99]{0x2ee0a} - mem[0xe98]{0x1e7be} = mem[0xe99]{0x1064c} # 
# Line 55093: 0xdef: mem[0xe99]{0x331ff} - mem[0xe98]{0x1e7be} = mem[0xe99]{0x14a41} # 
# password = subleq_and_reductio_ad_absurdum@flare-on.com

goal = "0x331ff"

for x in range(10, 127):
    for y in range(10, 127):
        #Read in file
        f = open("vm.dat", "r")
        data = f.read()
        f.close()

        #Convert to int array
        mem_arr = []
        for i in range(0, len(data), 4):
            mem_arr.append( struct.unpack("I", data[i:i+4])[0] )

        #Start address 
        start_off = 0x463 
        cur_off = start_off
        stdout = ""
        password = chr(x) + chr(y) + "\n"
        counter = 0
        instr_count = 0
        trace = []
        while True:

            out_str = "%s: " % hex(cur_off)
            cur_Inst = get_next_instr( mem_arr, cur_off) 
            out_str += "mem[%s]{%s} - mem[%s]{%s} = " % (hex(cur_Inst.dest), 
                hex(mem_arr[cur_Inst.dest]), hex(cur_Inst.src), hex(mem_arr[cur_Inst.src]))

            #print cur_Inst
            mem_arr[cur_Inst.dest] -= mem_arr[cur_Inst.src]
            mem_arr[cur_Inst.dest] &= 0xffffffff

            #Add total
            out_str += "mem[%s]{%s}" % (hex(cur_Inst.dest), hex(mem_arr[cur_Inst.dest]) )


            #Check whether to branch
            val = False
            if cur_Inst.br_offset != 0:
                val = (mem_arr[cur_Inst.dest] ==0 or mem_arr[cur_Inst.dest] > 0x100000000/2)
                #print val

            #Check whether to quit
            out_str = "{:70s} {:2s}".format( out_str, "#")
            if val:
                out_str += " Branch Taken: %s" % hex(cur_Inst.br_offset)
                cur_off = cur_Inst.br_offset
                if cur_off == 0xffffffff:
                    break
            elif cur_Inst.br_offset != 0:
                out_str += " Branch Not Taken"
                cur_off += 3
            else:
                cur_off += 3    

            if mem_arr[4] == 1:      #Output Ready Flag  
                stdout += chr(mem_arr[2])
                mem_arr[4] = 0
                mem_arr[2] = 0
                out_str += " Writing output"


            #Ouput to screen
            #out_str += "\n\nOutput:\n\n"
            #out_str += stdout + "\n\n"
            #sys.stdout.write(out_str)

            #Read a char
            if mem_arr[3] == 1:       #Input Ready Flag  
                input_chr = password[counter]
                mem_arr[1] = ord(input_chr)
                mem_arr[3] = 0
                counter += 1
                out_str += " Reading input"
                #raw_input()

            trace.append(out_str)
            #Add instruction count
            instr_count += 1

        for line in trace:
            arr = line.split("#")

            if len(arr) == 2:
                #Split instructions
                first = arr[0]
                first_arr = first.split(":")
                addr = first_arr[0] 
                if addr == "0xdef":
                    instrs = first_arr[1].strip()
                    instrs = instrs.split(" ")
                    if len( instrs ) == 5:

                        op1 = instrs[0]
                        #print op1
                        
                        op2 = instrs[2]
                        if goal in op2:
                            print line
                            print "Correct Password: " + password
                            raw_input()
                            sys.exit(1)

        print password

print "Instruction count: %i" % instr_count

#for line in trace:
#    print line

#parse_jmps()
#for line in trace:
#    print line

#parse_clears()
#for line in trace:
#    print line

#parse_movs()
#for line in trace:
#    print line

#parse_adds()
#for line in trace:
#    print line

#parse_shift_left()

#add_comments()

#for line in trace:
#    print line
