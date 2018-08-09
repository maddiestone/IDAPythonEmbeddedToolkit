#######################################
# IDAPython Script to Decrypt ARM 32-bit "WEDDINGCAKE" Packed Android Native Librarires
# Author: Maddie Stone (maddiestone@google.com)
# Copyright 2018 Google LLC.
#
# To run the script on the 32-bit ARM Android ELF, JNI_OnLoad must be defined
# and exported from the database. If any of the formatting or display
# of instructions is changed in your version of IDA, change the REGEX expressions
# at the beginning.
#######################################

import struct

decrypt_sub_addr = -1
ARRAY_INSTR = "ADD     R0, PC"
DATABASE_BACKUP = "decrypted_database_bkup.idb"
regex_len = re.compile(r"MOVS? +R[0-9], +#0x[0-9A-Fa-f]{1,8}")
regex_load_len = re.compile("LDR +R[0-9], +\[SP,#0x[0-9]{2}\+var_.*")
arrays_to_dec = {}
saved_lens = {}
just_array_addrs = []

""" Find the address of the decryption subroutine.

"""
def find_decrypt_sub():
    # Get OnLoad addr
    exported_subs = Entries()
    jni_onload_addr = -1
    for e in exported_subs:
        if (e[3] == "JNI_OnLoad"):
            print "**** JNI_OnLoad Addr: 0x%x ****" % e[2]
            jni_onload_addr = e[2]
            break
    if (jni_onload_addr == -1):
        print "CAN'T CONTINUE! CAN'T FIND ONLOAD!"
        return -1
    else:
        curr = NextHead(jni_onload_addr + 0xD0)
        end = GetFunctionAttr(curr, FUNCATTR_END)
        while (curr < end):
            disasm = GetDisasm(curr)
            if (disasm.startswith("BL ")):
                dec_addr = int(disasm.split("_")[-1].strip(), 16)
                if (XrefsTo(dec_addr) > 5):
                    print "DECRYPTION_ADDR: 0x%x" % dec_addr
                    return dec_addr
            curr = NextHead(curr)
        return - 1

""" Arithmetic shift right maintaining sign.
"""
def arith_shift_rt(num, shifts):
    val = num >> shifts
    #print "val: 0x%x" % val
    if (val < 0):
        mask = 0x10000000
        for i in range(1, shifts):
            val |= mask
            mask >> 1
    #print "num >> shifts = val --> 0x%x >> 0x%x = 0x%x" % (num, shifts, val)
    return val

""" Signed Branch if Less than or Equal
"""
def signed_ble(left_reg, right_reg):
    if (left_reg & 0x80000000):
        if (not(right_reg & 0x80000000)):
            return True
    else:
        if (right_reg & 0x80000000):
            return False
    return left_reg <= right_reg

""" Decrypts array of bytes and writes decrypted bytes back to array argument.
"""
def decrypt(array, array_len, array_0To255, array_0x400):
    if (array is None):
        print ("Array is null. -- Exiting")
        return
    if (array_len < 1):
        print ("array len < 1 -- Exiting")
        return
    after_end_of_array_index =  array_len
    reg_4 = ~(0x00000004)
    reg_0 = 4
    reg_2 = 0
    reg_5 = 0
    do_loop = True
    while (do_loop):
        #print "IN LOOP"
        reg_6 = after_end_of_array_index + reg_0
        #print "REG6: 0x%x" % reg_6
        reg_6 = array[reg_6 + reg_4]
        #print "array[reg_6 + reg_4] = array[%d] = %d" % ((after_end_of_array_index + reg_0+ reg_4), reg_6)
        if (reg_6 & 0x80):
            #print "WENT LEFT"
            if (reg_5 > 3):
                #print "reg_5 (%d) > 3 --> EXITING" % reg_5
                return
            reg_6 = reg_6 & 0x7F
            reg_2 = reg_2 & 0xFF
            #print "Before shift -- reg_6: 0x%x reg_2: 0x%x" % (reg_6, reg_2)
            reg_2 = reg_2 << 7
            reg_2 = reg_2 | reg_6
            reg_0 = reg_0 + reg_4 + 4
            #print "reg_2: 0x%x reg_0: 0x%x" % (reg_2, reg_0)
            reg_3 = array_len + reg_0 + reg_4 + 2
            reg_5 += 1
            #print "reg_3: 0x%x reg_5: 0x%x" % (reg_3, reg_5)
            if (reg_3 & 0x80000000 or reg_3 <= 1):
                #print "reg_3 shouldn't be less than 2 --> EXITING"
                return
        else:
            do_loop = False
            reg_5 = 0xF0 & reg_6
            reg_3 = array_len + reg_0 + reg_4
            reg_1 = reg_3 + 1
            #print ("Is reg1 (%d) equal to array_len(%d)") % (reg_1, array_len)
            if (reg_0 == 0 and reg_5 != 0):
                #print "reg_0 == 0 && reg_5 != 0 --> EXITING"
                return
    reg_5 = reg_1
    #print "reg_2: 0x%x reg_6: 0x%x r2<<7: 0x%x" % (reg_2, reg_6, (reg_2 << 7))
    reg_1 = (reg_2 << 7) + reg_6
    byte_FF = 0xFF
    reg_1 = reg_1 & byte_FF
    last_byte = reg_1
    #print ("reg_5 = 0x%x reg_1 = 0x%x reg_3 = 0x%x last_byte = 0x%x") % (reg_5, reg_1, reg_3, last_byte)
    if (reg_5 == 0 or reg_5 & 0x80000000 or last_byte == 0 or signed_ble(reg_3, last_byte)):
        #print "reg_5 < 1 || last_byte == 0 || reg_3 < last_byte -- Exiting"
        #print "reg_5 = 0x%x last_byte = 0x%x reg_3 = 0x%x" % (reg_5, last_byte, reg_3)
        return
    reg_1 = (reg_4 + 4)
    reg_1 = (reg_1 * last_byte)
    reg_1 += array_len
    crazy_num = reg_1 + reg_0 + reg_4
    #print ("(reg_4 + 4) * last_byte = 0x%x, reg_1 = 0x%x, crazy_num = 0x%x" % ((reg_4 + 4) * last_byte, reg_1, crazy_num))
    if (crazy_num < 1):
        #print "crazy_num < 1 --> EXITING"
        return
    new_index = reg_1 + reg_0
    #print "new_index: 0x%x" % new_index
    reg_5 = 0
    while (1):
        byte = array[reg_5]
        reg_0 = byte << 2
        reg_6 = array_0x400[byte]
        reg_0 = 0xFF - reg_6
        #print "byte: 0x%x reg_6: 0x%x reg_0: 0x%x" % (byte, reg_6, reg_0)
        if (not reg_6 & 0x80000000):
            #print "reg_6 > 0 --> Set reg_6 = reg_0"
            reg_6 = reg_0
        reg_0 = reg_5
        reg_1 = reg_0 % last_byte
        reg_0 = new_index + reg_1
        #print ("reg_1: 0x%x reg_0: %x" % (reg_1, reg_0))
        #print ("reg_0 = array[new_index + reg_1 + reg_4], array[0x%x] = 0x%x" % (reg_0 + reg_4, reg_0))
        reg_0 = array[(reg_0 + reg_4) & 0xFF]
        reg_1 = array_0x400[reg_0]
        #print ("reg_1 = array_0x400[reg_0] --> 0x%x = array_0x400[0x%x]" % (reg_1, reg_0))
        reg_2 = reg_1 | reg_6
        #print ("reg_2 = reg_1 | reg_6 --> 0x%x = 0x%x | 0x%x" % (reg_2, reg_1, reg_6))
        index_reg_0 = reg_5
        if (reg_2 & 0x80000000):
            #print ("reg_2 (0x%x) < 0) --> exiting " % (reg_2))
            break
        reg_1 = reg_6 + reg_1 + reg_5
        reg_2 = arith_shift_rt(reg_1, 0x1F)
        reg_2 = reg_2 >> 0x18
        #print "reg_2 = 0x%x" % reg_2
        reg_2 = reg_2 & ~0x000000FF
        #print "After BICS -- reg_2 = 0x%x" % reg_2
        reg_1 -= reg_2
        #print "reg_1 -= reg_2 --> reg_1 = 0x%x" % reg_1
        reg_1 = 0x000000FF - reg_1
        #print ("reg_1 (0x%x)= 0x000000FF - reg_1" % (reg_1))
        reg_1 = array_0To255[reg_1 & 0xFF]
        #print ("0x%x = array_0To255[reg_1 & 0xFF]" % reg_1)
        array[index_reg_0] = reg_1 & 0xFF
        #print "array[0x%x] = 0x%x" % (index_reg_0, reg_1)
        reg_5 += 1
        if (reg_5 >= crazy_num):
            #print ("reg_5 >= crazy_num --> Exit")
            break
    #print "*********** FINISHED DECRYPT ***************"

""" Processes disassembly output using defined regex's to 
    find the address of the encrypted array argument and
    the length of the array. These are saved to the 
    arrays_to_decrypt Map to be passed to the decrypt
    function.
"""
def get_array_and_len(addr, prev_len):
    disasm = GetDisasm(addr)
    #print ("[get_array_and_len] 0x%x: %s" % (addr, disasm))
    pieces = disasm.split(';')
    array_name = pieces[-1].strip()
    #print "ARRAY_NAME: %s" % array_name
    array_name = array_name.split('_')[-1]
    array = int(array_name, 16)
    #print "Array addr: 0x%x" % array
    first_addr = addr
    addr = NextHead(addr)
    steps = 0
    array_length = 0
    while (steps < 3):
        disasm = GetDisasm(addr)
        if (regex_len.match(disasm)):
            #print "MATCHED REGEX_LEN: %s" % disasm
            len_disasm = disasm.split("#")[1]
            print "len_disasm1: %s" % len_disasm
            len_disasm = len_disasm.split(";")[0]
            print "len_disasm: %s" % len_disasm
            array_length = int(len_disasm, 16)
            #print "len: 0x%x" % array_length
            addr = NextHead(addr)
            try_if_len_saved(addr, array_length)
            break
        elif (regex_load_len.match(disasm)):
            pieces = disasm.split("var_")
            var_num = pieces[-1].strip().replace("]", "")
            array_length = saved_lens[var_num]
            if (array_length):
                #print "Looked up length -- saved_lens[%s] = 0x%x" % (pieces[-1].strip(), array_length)
                break
            else:
                steps += 1
                addr = NextHead(addr)
        elif (disasm.startswith("B ")):
            addr = int(disasm.split("loc_")[-1].strip(), 16)
            print "BRANCH: %s -- new_addr: 0x%x" % (disasm, addr)
        else:
            steps += 1
            addr = NextHead(addr)
    if (array_length != 0):
        print "Adding to list: [0x%x, 0x%x]" % (array, array_length)
        just_array_addrs.append(array)
        arrays_to_dec[array] = array_length
    else:
        print "Keeping last length - Adding to list: [0x%x, 0x%x]" % (array, prev_len)
        just_array_addrs.append(array)
        array_length = prev_len
        arrays_to_dec[array] = array_length
        addr = NextHead(first_addr)
        try_if_len_saved(addr, array_length)
    return array_length

""" Checks if the length that should be used for the 
    encrypted array was saved on to the stack.
"""
def try_if_len_saved(addr, length):
    disasm = GetDisasm(addr)
    #print "[try_if_len_saved] 0x%x: %s" % (addr, disasm)
    steps = 0
    while (steps < 4):
        if (disasm.startswith("STR")):
            pieces = disasm.split("var_")
            var_num = pieces[-1].strip().replace("]", "")
            saved_lens[var_num] = length
            break
            print "Added -- saved_lens[%s] = 0x%x" % (pieces[-1].strip(), length)
        else:
            addr = NextHead(addr)
            disasm = GetDisasm(addr)
            steps += 1
        #print "try_if_len_saved: NOPE"

""" Returns the values of the array at argument
    addr for length len.
"""
def get_array_from_addr(addr, len):
    array = [0xFF] * len
    for i in range(0,len):
        array[i] = Byte(addr)
        addr += 1
    return array



#########################################################
# MAIN
#########################################################
exported_subs = Entries()
for e in exported_subs:
    if (e[3] == "JNI_OnLoad"):
        print "**** JNI_OnLoad Addr: 0x%x ****" % e[2]


print "**** INITIALIZE THE TWO ARRAYS ****"
# Create array counting up 0 - 255
num_array = range(0,256)

# Run Stage 1 Loop
v4 = 0x2C09
for i in range (0, 256):
    v6 = (0x41C64E6D * v4 + 0x3039)
    v7 = v6 & 0xFF
    v8 = num_array[v6 & 0xFF]
    #print "---------------------------------------------------"
    #print "v6: 0x%x v7: 0x%x v8: 0x%x" % (v6, v7, v8)
    v9 = (0x41C64E6D * (v6 & 0x7FFFFFFF) + 0x3039)
    #print "v9: 0x%x num_array[v9 & 0xFF]: 0x%x" % (v9, num_array[v9&0xFF])
    #print "Replacing num_array[0x%x]=0x%x" % (v7, num_array[v9&0xFF])
    num_array[v7] = num_array[v9 & 0xFF]
    #print "Setting num_array[v9 & 0xFF] to v8"
    num_array[v9 & 0xFF] = v8
    v4 = v9 & 0x7FFFFFFF
    #print "num_array[0x%x] = 0x%x -- should equal 0x%x" % (v9&0xFF, num_array[v9&0xFF], v8)
#print "Finished"
#print num_array


#print "Running Stage 2"
new_array = [0xFFFFFFFF] * 0x100
for i in range(0,256):
    index = num_array[i]
    new_array[index] = i
    new_array[num_array[i]] = i
#print "DONE!"
#print new_array

print "**** FINDING ARRAYS TO BE DECRYPTED ****"
decryption_sub_addr = find_decrypt_sub()
if (decryption_sub_addr != -1):
    print "**** DECRYPTION SUB AT: 0x%x ****" % decryption_sub_addr

    # GET ALL OF THE DECRYPTION CALLS
    decrypt_calls = XrefsTo(decryption_sub_addr)
    #print decrypt_calls
    callee_addrs = []
    for c in decrypt_calls:
        callee_addrs.append(c.frm)
    min_call = min(callee_addrs)
    max_call = max(callee_addrs)
    print "MIN: 0x%x MAX: 0x%x" % (min_call, max_call)

    curr = min_call - 0x20
    prev_length = 0
    while(curr < max_call):
        disasm = GetDisasm(curr)
        if (disasm.startswith(ARRAY_INSTR)):
            #print "MATCH: 0x%x: %s" % (curr, disasm)
            prev_length = get_array_and_len(curr, prev_length)
        curr = NextHead(curr)

    print "**** SAVING OFF DATABASE TO: %s" % DATABASE_BACKUP
    #save_database(DATABASE_BACKUP)
    print "**** STARTING DECRYPT ****"
    just_array_addrs.sort()
    #print "ARRAYS"
    print just_array_addrs
    size = len(just_array_addrs)
    last_addr = just_array_addrs[size-1]
    print "AREA: 0x%x - 0x%x = 0x%x" % (last_addr + arrays_to_dec[last_addr], just_array_addrs[0],(last_addr + arrays_to_dec[last_addr]) - just_array_addrs[0] )

    decrypted_bytes = 0
    for a in just_array_addrs:
        #print "**************************************************************************************************"
        array_start = a
        array_end = a
        array_len = arrays_to_dec[a]
        array = get_array_from_addr(a, array_len)
        #print array
        decrypt(array, array_len, num_array, new_array)
        #print "0x%x: %s" % (a, ''.join(chr(e) for e in array))
        # Writing array contents to file and IDB
        idb_addr = a
        for b in array:
            if (b & 0xFF == 0x00 and array_end == array_start):
                array_end = a
            #dec_file.write(struct.pack('<B', b & 0xFF))
            PatchByte(a, b & 0xFF)
            a +=1
        #print array
        MakeStr(array_start, array_end)
        decrypted_bytes += array_len
    print "FINISHED! DECRYPTED 0x%x BYTES. " % (decrypted_bytes)
    #dec_file.close()
else:
    print "CAN'T FIND DECRYPTION SUB ADDR! EXITING!"


