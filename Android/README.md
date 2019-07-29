# IDAPython Embedded Toolkit: Android Segment

The tools,scripts, and information in this section help reverse engineer
and analyze Android-related binaries. 

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

*jni_translate.py*: An IDA plugin that translates JNIEnv offsets to the actual function signature and makes that information available to an analyst.

Copyright 2018 Google LLC.
Author: maddiestone@google.com (Maddie Stone)

