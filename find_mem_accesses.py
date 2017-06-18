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
# find_mem_accesses.py
# 
# Identifies the memory accesses used in the code. When a memory access is identified based
# on the user contributed regular expression, this script completes three different actions
# to help with the static analysis:
# 	1. 	A cross reference is created between the instruction and the memory address. This 
#		will fail if the address doesn't currently exist because the segment was not created.
# 	2. 	The value at the memory address is retrieved and added as a comment to the 
#		referencing instruction.
#	3. 	A dictionary of all of the memory addresses accessed and the referencing instructions'
#		addresses are printed and saved to a file.
# ** NOTE:If you are using a Harvard architecture, ensure you can distinguish between memory
# spaces or comment out the cross-reference and value parts of this script.
#
# Inputs: 	start_addr: 	Start address for segment to define as data
#			end_addr:		End address for segment to define as data
#			file_name:		File to write the accesses to
#
##############################################################################################
import re

################### USER DEFINED VALUES ###################
# Enter a regular expression for the memory access instructions you'd like to identify. 
# Also enter the index of the operand in the instruction so that it can be retrieved via
# the GetOperandValue() function. 
#
# 8051 (movx DPTR, #addr)
regex_mem_instruct = re.compile(r"mov +DPTR, #")
operand_index = 1
############################################################


start_addr = AskAddr(MinEA(), "Please enter the starting address for the code to be analyzed.")
end_addr = AskAddr(MaxEA(), "Please enter the ending address for the code to be analyzed.")

default_fn = "memory_use_locations.txt"
filename = AskFile(1, default_fn, "Please choose the location to save the memory accesses file.")

accesses_dict = {}

if ((start_addr is not None and end_addr is not None) and (start_addr != BADADDR and end_addr != BADADDR) and start_addr < end_addr):
	curr_addr = start_addr
	while (curr_addr < end_addr):
		if (regex_mem_instruct.match(GetDisasm(curr_addr))):
			#mem_addr = regex_mem_addr.match(GetDisasm(curr_addr))
			mem_addr = GetOperandValue(curr_addr, operand_index)
			print "[find_mem_accesses.py] Instruction Address: 0x%x Operand Address: 0x%0x" % (curr_addr, mem_addr)
			# Create Cross-Reference to Address
			result = add_dref(curr_addr, mem_addr, dr_T)
			if (not result):
				print "[find_mem_accesses.py] Could NOT create data cross-references."
			else:
				# Try to Get Value at Memory Address and Record at Reference
				# Defaulting to WORD (2 bytes) can change or add other intelligence here
				value = Word(mem_addr)
				MakeComm(curr_addr, "@[0x%x] = 0x%x" % (mem_addr, value))
				if (mem_addr in accesses_dict):
					accesses_dict[mem_addr].append(curr_addr)
				else:
					accesses_dict[mem_addr] = [curr_addr, ]
		curr_addr = NextHead(curr_addr)
	print "[find_mem_accesses.py] Finished searching range. Writing to file."
	with open(filename, "w") as out_file:
		for key in sorted(accesses_dict.keys()):
			out_file.write("0x%0x: \n" % key)
			for ref in accesses_dict[key]:
				out_file.write("\t0x%0x \n" % ref)
else:
	print "[find_mem_accesses.py] ERROR. Please enter valid addresses." 
									
			