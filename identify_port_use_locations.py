##############################################################################################
# Copyright 2017 The Johns Hopkins University Applied Physics Laboratory LLC
# All rights reserved.
# Permission is hereby granted, free of charge, to any person obtaining a copy of this 
# software and associated documentation files (the "Software"), to deal in the Software 
# without restriction, including without limitation the rights to use, copy, modify, 
# merge, publish, distribute, sublicense, and/or sell copies of the Software, and to 
# permit persons to whom the Software is furnished to do so.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, 
# INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR 
# PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE 
# LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, 
# TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE 
# OR OTHER DEALINGS IN THE SOFTWARE.

##############################################################################################
# identify_ port_use_locations.py
# Identifies all code using the CPU's ports and records the address and instruction
# in the identified file.
#
# User-Defined Input: 	
# ** Before use, edit the regex_pinref regular expression to match how the ports are displayed
# in instructions for your architecture.
#
##############################################################################################


################### USER DEFINED VALUES ###################
# PIC18F8722
regex_pinref = re.compile(r" PORT[A-H]")

# 87C52 (8051) - Ports referenced as FSR_80 (P0)...FSR_B0 (P3)
#regex_pinref = re.compile(r" FSR_[8-9A-Ba-b]0.?[0-7]?")

# C515 (8051) - Ports referened as P1 or P1_8
#regex_pinref = re.compile(r" P\d+\_?\d+")

# M32R
#regex_pinref = re.compile(r"
############################################################



start_addr = AskAddr(MinEA(), "Please enter the starting address for the code to be analyzed.")
end_addr = AskAddr(MaxEA(), "Please enter the ending address for the code to be analyzed.")

default_fn = "port_use_locations.txt"
filename = AskFile(1, default_fn, "Please choose the location to save the port use locations file.")

change_func_nm = AskYN(0, "Would you like to append a prefix to the names of funcs using ports?")

curr_addr = start_addr
func_name_out = False
with open(filename, "w") as out_file:
	while curr_addr < end_addr:
		if (isCode(GetFlags(curr_addr))):
			instruct = GetDisasm(curr_addr);
			#print ("0x%08x: " % curr_addr) + instruct
			if regex_pinref.search(instruct):
				out_file.write(("0x%08x: " % curr_addr) + instruct);
				print ("0x%08x: " % curr_addr) + instruct
				if (change_func_nm == 1):
					func_start_addr = GetFunctionAttr(curr_addr, FUNCATTR_START)
					if (func_start_addr != BADADDR):
						curr_name = GetFunctionName(curr_addr)
						if (curr_name != "" and not curr_name.startswith("pin")):
							port_nums = regex_pinref.findall(instruct)
							name = "pin" + port_nums[0] + "Used_" + curr_name
							MakeName(func_start_addr, name)
		curr_addr = NextHead(curr_addr)
			
			