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
# define_code_functions.py
# Attempts to define the bytes in the user-entered address range as code and then as functions
# based on the user-define smart_prolog and smart_epilog regular expressions for that architecture.
#
# Inputs: 	start_addr: 	Start address for segment to define as data
#			end_addr:		End address for segment to define as data
#			data_type:		Type of data to set segment to (dependent on architecture)
#
##############################################################################################
import re
import idaapi

################### USER DEFINED VALUES ###################
# Enter a regular expression for how this architecture usually begins and ends functions.
# If the architecture does not dictate how to start or end a function use r".*" to allow
# for any instruction

processor_name = idaapi.get_inf_structure().procName


if processor_name == '8051':
	# 8051 Architecture Prologue and Epilogue
	smart_prolog = re.compile(r".*")
	smart_epilog = re.compile(r"reti{0,1}")

elif processor_name == 'PIC18Cxx':
	# PIC18 Architecture Prologue and Epilogue
	smart_prolog = re.compile(r".*")
	smart_epilog = re.compile(r"return  0")

elif processor_name == 'm32r':
	# Mitsubishi M32R Architecutre Prologue and Epilogue
	smart_prolog = re.compile(r"push +lr")
	smart_epilog = re.compile(r"jmp +lr.*")

elif processor_name == 'TMS32028':
	# Texas Instruments TMS320C28x
	smart_prolog = re.compile(r".*")
	smart_epilog = re.compile(r"lretr")

elif processor_name == 'AVR':
	# AVR
	smart_prolog = re.compile(r"push +r")
	smart_epilog = re.compile(r"reti{0,1}")

else:
	print "[define_code_functions.py] UNSUPPORTED PROCESSOR. Processor = %s is unsupported. Exiting." % processor_name
	raise NotImplementedError('Unsupported Processor Type.')

print "[define_code_functions.py] Processor = %s -- Reg Expressions Selected. Proceeding." % processor_name
############################################################

start_addr = AskAddr(MinEA(), "Please enter the starting address for the data to be defined.")
end_addr = AskAddr(MaxEA(), "Please enter the ending address for the data to be defined.")

if ((start_addr is not None and end_addr is not None) and (start_addr != BADADDR and end_addr != BADADDR)):
	do_make_unk = AskYN(0, "Do you want to make all of the code block UNKNOWN first?")
	if (do_make_unk == 1):
		curr_addr = start_addr
		while (curr_addr < end_addr):
			MakeUnkn(curr_addr,idc.DOUNK_SIMPLE)
			curr_addr += 1
	if (do_make_unk != -1):
		curr_addr = start_addr
		print "[make_code_functions.py] Running script to define code and functions on 0x%x to 0x%x" % (start_addr, end_addr)
		while (curr_addr < end_addr):
			next_unexplored = FindUnexplored(curr_addr, idaapi.SEARCH_DOWN)
			MakeCode(next_unexplored)		# We don't care whether it succeeds or fails so not storing retval
			curr_addr = next_unexplored

		# Finished attempting to make all unexplored bytes into code
		# Now, attempt to create functions of all code not currently in a function
		print "[make_code_functions.py] Completed attempting to define bytes as code. Now trying to define functions."
		curr_addr = start_addr
		while (curr_addr != BADADDR and curr_addr < end_addr):
			if (isCode(GetFlags(curr_addr)) and GetFunctionAttr(curr_addr, FUNCATTR_START) == BADADDR):
					#print "Function Stuffs 0x%0x" % curr_addr
					if(smart_prolog.match(GetDisasm(curr_addr)) or smart_epilog.match(GetDisasm(PrevHead(curr_addr)))):
						#print "Smart Prolog match"
						if (MakeFunction(curr_addr) != 0):	
							# MakeFunction(curr_addr) was successful so set curr_addr to next addr after the new function
							curr_addr = GetFunctionAttr(curr_addr, FUNCATTR_END)	# Returns first address AFTER the end of the function
							continue
			curr_addr = NextHead(curr_addr)
else:
	print "[make_code_functions.py] Quitting. Entered address values are not valid."
	
		

        
