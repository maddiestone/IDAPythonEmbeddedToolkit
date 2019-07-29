# IDAPython Embedded Toolkit: Android Segment

The tools,scripts, and information in this section help reverse engineer
and analyze Android-related binaries. 

## jni_translate
Android apps can include compiled native code (usually written in C/C++) within a native library. This code uses the Java Native Interface to interact with the Java (or Kotlin) code within the Android app. Learn more at https://maddiestone.github.io/AndroidAppRE/reversing_native_libs.html). Each JNI function within the Android native lib will take the JNIEnv pointer as its first argument. The JNIEnv struct is a table of function pointers that provide useful Java functions to the native code. 

The *jni_translate.py* IDA Python script will comment within the IDA disassembly what function from the JNIEnv struct is being called to help ease analysis. This is necessary because most calls to functions within the JNIEnv are called as indirect offset accesses to JNIEnv*. 

For example, the following disassembly is a call to GetStaticMethodId which is at offset 0x1C4 in the JNIEnv struct.
```
LDR R1, [R0]		#R0 is JNIEnv*
MOVS R0, #0x1C4
LDR R4, [R0, R1]	# R4 = [JNIEnv + 0x1C4] = Ptr to GetStaticMethodId()
BLX R4				# Call GetStaticMethodId
```

This script will add the function name as a comment in the IDA Disassembly. 

## WeddingCake
The WeddingCake anti-analysis library is an Android native code wrapper 
that includes many techniques to frustrate analysis. More information 
about this packer and how to run the tools included here is available
from Maddie Stone's BlackHat USA 2018 talk, "Unpacking the Packed Unpacker".

*WeddingCake_decrypt.py*: This IDAPython script will run on ARM32 ELFs
that have been packed with the WeddingCake Android anti-analysis library.
The script will decrypt all of the encrypted strings in the IDA database
and overwrite the database with the decrypted contents. To run the script,
you must ensure that the JNI_OnLoad function is defined and exported in 
the IDA database. 

*WeddingCake_sysprops.txt*: All of the system properties that WeddingCake
checks for and the values that will cause the application to exit.

Copyright 2018 Google LLC.
Author: maddiestone@google.com (Maddie Stone)

