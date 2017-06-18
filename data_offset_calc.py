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
# data_offset_calc.py
# Resolves the references to indirect offsets of a variable, register, or memory location
# whose value is known. Changes the display of the operand in the instruction (OpAlt function),
# creates a data cross references (add_dref), and creates a comment of the resolved address
# (MakeComment). User nees to define the following:
# 			offset_var_string: The string representation of the variable, register, or memory
#								location to be replaced by the resolved value
#			offset_var_value:	The value of the variable defined in offset_var_string
#			reg_ex_indirect:	A regular expression of how indirect offset accesses to the variable
#			reg_ex_immediate:	A regular expression of how the immediate offset value is represented
#			new_opnd_display:	A string representation of how the calculated and resolved 
#								value should be displayed as the operand in the instruction
#
# Inputs: 	start_addr: 	Start address for segment to define as data
#			end_addr:		End address for segment to define as data
#
##############################################################################################
import re


################### USER DEFINED VALUES ###################
# String of the variable/register/location used as the indirect variable
offset_var_str = "fp"

# The defined offset_var_str's value			
offset_var_value = 0x808000		

# Regular expression for out offset_var_str is referenced indirectly in the IDA Disassembly
# @(-0x(1-8 hex chars), fp )
reg_ex_indirect = re.compile(r"@\(-?0x[0-9A-Fa-f]{1,8}, "+ offset_var_str +"\)")

# Regular expression for how immediate values are shown in the indirect reference
# For this example, it's 0x1044, but some architectures would show that as 1044h
regex_immediate = re.compile(r"0x[0-9A-Fa-f]{1,8}")

# String expression for how the newly calculated instruction should be displayed within the instruction
new_opnd_display =  '@[0x%x]' 

# OPTIONAL ---- EXAMPLE FOR ADDING OTHER INSTRUCTIONS TO THE PROCESSING
# If you'd like to add other instructions to be processed for resolving indirect offset accesses,
# update the regular expression here and use it as shown in the "else" block below
reg_ex_add3 = re.compile(r"add3    \w\w, fp, #-?0x[0-9A-Fa-f]{1,8}")
#############################################################

start_addr = AskAddr(MinEA(), "Please enter the starting address for the data to be analyzed.")
end_addr = AskAddr(MaxEA(), "Please enter the ending address for the data to be analyzed.")

if ((start_addr is not None and end_addr is not None) and (start_addr != BADADDR and end_addr != BADADDR) and start_addr < end_addr):
	print "[data_offset_calc.py] STARTING. Looking for indirect accesses across 0x%x to 0x%x" % (start_addr, end_addr)
	curr_addr = start_addr;
	while curr_addr < end_addr:
		operand = GetOpnd(curr_addr, 1)							# Operand = 2nd Operand in the Instruction at curr_addr
		if reg_ex_indirect.match(operand):
			print ('[data_offset_calc.py] 0x%x Operand: ' % curr_addr) + operand
			
			# This checks if there are any immediate values also in the 2nd operand with the variable. For example, mov R3, @(0x10, fp)
			offset = re.findall(regex_immediate, operand) 		
			if (offset):
				print "[data_offset_calc.py] 0x%x Offset: 0x%x" % (curr_addr, int(offset[0],16))
		
				# Check if Immediate Operand is Neg or Pos
				if '-' in operand :
					new_opnd = offset_var_value - int(offset[0], 16)
				else:
					new_opnd = offset_var_value + int(offset[0], 16)
				
				print ("[data_offset_calc.py] 0x%x: Offset + " + offset_var_str + " = 0x%0x") % (curr_addr, new_opnd)
				OpAlt(curr_addr, 1, new_opnd_display % new_opnd)	# Changes Display of Instruction
				result = add_dref(curr_addr, new_opnd, dr_T)			# Create Data Ref -- Using dref_T because not checking if read or write	
				print ("[data_offset_calc.py] Creating dref from 0x%x to 0x%x: " % (curr_addr, new_opnd)) + str(result)
			# Using dr_O (O as in Offset, not 0) because we are not check if this a "write" or "read"
			else:													
				print "[data_offset_calc.py] 0x%x: No immediate offset identified." % curr_addr													

	#####################################################################################
	# This block is optional but shows how to add additional regular expressions for other instructions
	# you'd like to match besides the general indirect offset acceses. For M32R we are also matching
	# the add3 instruction that take the form "add3  Reg, fp, 0xNUM"

		else:
			instruct = GetDisasm(curr_addr)
			if reg_ex_add3.match(instruct):
				print ('[data_offset_calc.py] 0x%08x Instruct: ' % curr_addr) + instruct
				immed_opnd = GetOpnd(curr_addr, 2)				# Getting the 3rd Operand Based on the reg_ex_add3 defined above
				offset = re.findall(regex_immediate, immed_opnd);
				if offset:
					if '-' in immed_opnd:
						new_opnd = offset_var_value - int(offset[0], 16)
					else:
						new_opnd = offset_var_value + int(offset[0], 16)
					print '[data_offset_calc.py] 0x%x: Offset + fp = 0x%08x' % (curr_addr, new_opnd)
					MakeComm(curr_addr, '0x%08x' % new_opnd) 		# Add comment with new operand instead of overwriting instruction as done above
					result = add_dref(curr_addr, new_opnd, dr_T) 	# Creates Data XREF from Instruct to Calculated Val
					print ("[data_offset_calc.py] Creating dref from 0x%x to 0x%x: " % (curr_addr, new_opnd)) + str(result)
				else:
					print "[data_offset_calc.py] 0x%x: No immediate offset identified." % curr_addr
	########################################################################################
		prev = curr_addr
		curr_addr = NextHead(curr_addr, 0xFFFFF)
		if (curr_addr == BADADDR):
			print "[data_offset_calc.py] EXITING."
			break 
else:
	print "[data_offset_calc.py] QUITTING. Invalid values entered for starting and ending addresses."
