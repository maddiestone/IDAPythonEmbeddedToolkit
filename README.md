# IDAPython Embedded Toolkit

Copyright 2017 The Johns Hopkins University Applied Physics Laboratory LLC
All rights reserved.
Permission is hereby granted, free of charge, to any person obtaining a copy of this 
software and associated documentation files (the "Software"), to deal in the Software 
without restriction, including without limitation the rights to use, copy, modify, 
merge, publish, distribute, sublicense, and/or sell copies of the Software, and to 
permit persons to whom the Software is furnished to do so.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, 
INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR 
PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE 
LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, 
TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE 
OR OTHER DEALINGS IN THE SOFTWARE.

## Description
IDAPython is a way to script different actions in the IDA Pro disassembler with Python. This
repository of scripts automates many different processes necessary when analyzing the
firmware running on microcontroller and microprocessor CPUs. The scripts are written to be
easily modified to run on a variety of architectures. Read the instructions in the header of each
script to determine what ought to be modified for each architecture.

## How to Run
Install IDAPython per: https://github.com/idapython/src

Once your IDA database is open, go to File > Script file... and select the script to run.

## Scripts in the IDAPython Embedded Toolkit
* **data_offset_calc.py -- Resolve Indirect Offset Memory Accesses**
Resolves the references to indirect offsets of a variable, register, or memory location
whose value is known. Changes the display of the operand in the instruction (OpAlt function),
creates a data cross references (add_dref), and creates a comment of the resolved address
(MakeComment). User nees to define the following:
		offset_var_string: The string representation of the variable, register, or memory
							location to be replaced by the resolved value
		offset_var_value:	The value of the variable defined in offset_var_string
		reg_ex_indirect:	A regular expression of how indirect offset accesses to the variable
		reg_ex_immediate:	A regular expression of how the immediate offset value is represented
		new_opnd_display:	A string representation of how the calculated and resolved 
							value should be displayed as the operand in the instruction

* **define_code_functions.py -- Define Code and Functions**
This script scans an area of the database from the user input "start address" to "end address"
defining the bytes as code and attempting to define functions from that code. The script
is architecture agnostic by having the user define a regular expression for the "function prologue"
and the "function epilogue" for the architecture being analyzed.

* **define_data_as_types.py -- Define a Block as Data**
Defines a segment of addresses as the user-specified data type (byte, word, or double word).
The byte length for each of these types is architecture dependent, but generally:
	1 byte  = Byte
      2 bytes = Word
	4 bytes = Double Word
This script with undefine all bytes in the range first which means if you previously had
code or strings defined in the area, they will be overwritten as data.

* **make_strings.py -- Define a Block as Strings**
This script is used to search for and declare blocks of "Unexplored" bytes as ASCII strings. 
The user inserts the starting and ending address of the areas to be analyzed. The script then
checks if each byte is an ASCII character value and ends with a defined "ending string character."
In this example, the ending string characters are 0xD, 0xA, and 0x00. The script only checks 
"undefined or unexplored" values in the database. For example, if a string is currently 
defined as code, it will not identify this string. This is to protect previously defined values. 

* **label_funcs_with_no_xrefs.py -- Label All Functions without Cross-References/ Valid Code Paths**
This script identifies what could be "dead code". It checks each function for cross-references to 
the function in question. If there are none, it adds the prefix "noXrefs_" to the function name. This
is very efficient for architectures that do not call functions indirectly.

* **identify_port_use_locations.py -- Find All CPU Port Usage**
Identifies all code using the CPU's ports and records the address and instruction
in the identified file. There is the option to annotate each function that accesses a CPU port/pin
with a prefix stating that it's using the specific port/pin.

* **find_mem_acceses.py -- Identify Memory Accesses**
Identifies the memory accesses used in the code. When a memory access is identified based
on the user contributed regular expression, this script completes three different actions
to help with the static analysis:
	1. 	A cross reference is created between the instruction and the memory address. This 
		will fail if the address doesn't currently exist because the segment was not created.
 	2. 	The value at the memory address is retrieved and added as a comment to the 
		referencing instruction.
	3. 	A dictionary of all of the memory addresses accessed and the referencing instructions'
		addresses are printed and saved to a file.
