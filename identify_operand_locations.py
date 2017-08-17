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
# identify_operand_locations.py
# Identifies the instructions in the range start_addr to end_addr that reference the 
# input operand (regex_operand). The addresses of all instructions where the operand is 
# found are printed to the IDA output window and saved to a file.
#
# User-Defined Input: 	
# ** Before use, edit the regex_operand regular expression to match how the operand of interest
# is displayed in instructions.
# ** If you do not want to search the entire database, change start_addr and end_addr.
#
##############################################################################################

# UPDATE THIS VALUE FOR THE REFERENCES TO THE OPERAND YOU'RE LOOKING FOR
regex_operand = re.compile(r"\[ebp+arg_4\]")

start_addr = AskAddr(MinEA(), "Please enter the starting address for the code to be analyzed.")
end_addr = AskAddr(MaxEA(), "Please enter the ending address for the code to be analyzed.")

default_fn = "operand_locations.txt"
filename = AskFile(1, default_fn, "Please choose the location to save the operand use locations file.")

curr_addr = start_addr
with open(filename, "w") as out_file:
	while curr_addr < end_addr:
		if (isCode(GetFlags(curr_addr))):
			instruct = GetDisasm(curr_addr);
			if regex_operand.search(instruct):
				out_file.write(("0x%08x: " % curr_addr) + instruct);
				print ("0x%08x: " % curr_addr) + instruct
		curr_addr = NextHead(curr_addr)
			
			