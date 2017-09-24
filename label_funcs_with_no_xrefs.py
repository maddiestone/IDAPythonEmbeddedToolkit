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
# label_funcs_with_no_xrefs.py
# This script checks each defined function in the address range entered for cross-references. 
# If there are no cross-references to the function, the prefix "noXrefs_" is added to the 
# function's name. It then iterates through all functions in the code range again to identify
# all functions who's only code references are functions that have no cross-references. This
# is to detected functions called only by other functions who have no code references.
# This script helps to detect "dead code" that is never called.
#
# Inputs: 	start_addr: 	Start address for segment to define as data
#			end_addr:		End address for segment to define as data
#           ignore_addrs:   Addresses of functions that should not be considered as "noXref"
#                           For Example, RESET should be listed here
#
##############################################################################################

################### USER DEFINED VALUES ###################
# Function Addresses that should not be considered "No Crossreferences/Dead"
# For example, the reset and interrupt vectors don't have cross-references but should
# not be labeled as such.
ignore_addrs = (0x0, 0x8, 0x18)
###########################################################
			
def addPrefixToFunctionName(prefix, functionAddr):
	name = GetFunctionName(curr_addr)
	if (name and not name.startswith(prefix)):
		name = prefix + name
		print ("[label_funcs_with_no_xrefs.py] Function 0x%x Name: " % curr_addr) + name
		MakeName(curr_addr, name)

start_addr = AskAddr(MinEA(), "Please enter the starting address for the functions to be examined.")
end_addr = AskAddr(MaxEA(), "Please enter the ending address for the functions to be examined.")

if ((start_addr is not None and end_addr is not None) and (start_addr != BADADDR and end_addr != BADADDR) and start_addr < end_addr):
	print "[label_funcs_with_no_xrefs.py] Running on addresses 0x%x to 0x%x" % (start_addr, end_addr)
	
	# If start_addr is in a function, get the starting address of that function. Else, returns -1.
	curr_addr = GetFunctionAttr(start_addr, FUNCATTR_START) # Get the function head for the "start" addr
	if (curr_addr == BADADDR):
		# start_addr is not currently in a function so select the beginning of the next function
		curr_addr = NextFunction(start_addr)
	
	# Using this to continually iterate through all functions until no new functions 
	# having no code reference paths are found. 
	new_noXrefs_found = False
	while (curr_addr != BADADDR and curr_addr < end_addr):
		if (curr_addr not in ignore_addrs and (not GetFunctionName(curr_addr).startswith("noXrefs_"))):
			xrefs = XrefsTo(curr_addr)
			has_valid_xref = False;
			for x in xrefs:
				if (not GetFunctionName(x.frm).startswith("noXrefs_")):	
					# Function has a valid cross-reference and is not "dead code"
					has_valid_xref = True;
					break;
			if (has_valid_xref == False):
				# No valid xrefs were found to this function
				new_noXrefs_found = True
				addPrefixToFunctionName("noXrefs_", curr_addr)
			curr_addr = NextFunction(curr_addr)
			if ((curr_addr == BADADDR or curr_addr >= end_addr) and new_noXrefs_found):
				print "[label_funcs_with_no_xrefs.py] Iterating through range again because new functions with no Xrefs found."
				curr_addr = start_addr
				new_noXrefs_found = False
		curr_addr = NextFunction(curr_addr)	
	print "[label_funcs_with_no_xrefs.py] FINISHED."
else:
	print "[label_funcs_with_no_xrefs.py] QUITTING. Invalid address(es) entered."