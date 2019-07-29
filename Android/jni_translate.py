"""JNIEnv-translate recovers the offset used to access a function in JNIEnv and translates that into the corresponding function."""


from __future__ import print_function
import re
from idaapi import ida_funcs
import idc


num = 0
regs_offsets = {}
regs_loads = {}
# a function that accesses and calls a JNI function does at least of 4
# operations 1. push registers to stack, 2. get JNIEnv pointer,
# 3. dereference specific function 4. call function. All these will take at
# least 8 bytes.
min_func_len = 0x8
jnienv = {}
last_inst_not_for_jnie = False
last_inst_not_mtd3 = False


REGEX_PUSH = re.compile(r"PUSH +\{(R[0-9]+,?)+ *(-R[0-9]+,)? *(LR)?\}")
# LDR     R4, [R0]
REGEX_LDR_JNIE = re.compile(r"LDR +R[0-9]+, +\[R[0-9]+\]")
# ADDS    R4, #8|#0x8
REGEX_OPT_ADD = re.compile(r"ADDS +R[0-9]+, +(#[0-9]{1,3}|#0x[0-9A-Fa-f]{1,3})")
# MOVS    R3, #8|#0x8
REGEX_OPT_MOV = re.compile(r"MOVS +R[0-9]+, +(#[0-9]{1,3}|#0x[0-9A-Fa-f]{1,3})")
# MOV     R12, R3
REGEX_MOV = re.compile(r"MOV +R[0-9]+, +R[0-9]+")
# LDR     R4, [R4,#67]
REGEX_LDR_MTD1 = re.compile(r"LDR +R[0-9]+, +\[R[0-9]+, *#[0-9]{1,3}\]")
# LDR     R4, [R4,#0x7C]
REGEX_LDR_MTD4 = re.compile(r"LDR +R[0-9]+, +\[R[0-9]+, *#0x[0-9A-Fa-f]{1,3}\]")
# LDR     R3, [R4,R3]
REGEX_LDR_MTD2 = re.compile(r"LDR +R[0-9]+, +\[R[0-9]+, *R[0-9]+\]")
# LDR     R3, [R4]
REGEX_LDR_MTD3 = re.compile(r"LDR +R[0-9]+, +\[R[0-9]+\]")
# BLX     R4
REGEX_BLX = re.compile(r"BLX +R[0-9]+")
# POP     {R4,PC}
REGEX_POP = re.compile(r"POP +\{(R[0-9]+,?)+ *(-R[0-9]+,)? *(PC)?\}")


def remove_comment_from_disasm(disasm):
  """Remove comment from disassembly.

  Args:
   disasm: (str) disassembly of the current instruction.

  Returns:
   New disassembly after removing comment.
  """
  if ";" in disasm:
    return disasm.split(";")[0]
  return disasm


def match_ldr_jnie(disasm):
  """process instruction that loads function table pointer.

  E.g LDR     R4, [R0].

  Args:
   disasm: (str) disassembly of the current instruction.

  Returns:
   True True or False depending on whether the instruction loads JNIEnv ptr
  """
  global regs_offsets, regs_loads
  # some instructions have comment, remove the comments
  disasm = remove_comment_from_disasm(disasm)
  # get the reg that now holds JNIEnv ptr
  disasm = disasm.split("LDR")[1].split(",")
  loc_jnie = disasm[0].strip()
  loc_source = disasm[1].strip()[1:-1]
  if loc_jnie in regs_loads and regs_loads[loc_jnie]:
    return False
  if loc_source in regs_offsets and regs_offsets[loc_source] != -1:
    return False
  # its currently at offset 0
  regs_offsets[loc_jnie] = 0
  # saying that the current reg holds JNIEnv ptr
  regs_loads[loc_jnie] = True
  return True


def match_opt_adds(disasm):
  """process instruction that adds a literal value to function table pointer.

  Also used for an instruction that moves a literal value to a register.
  E.g ADDS    R4, #8|#0x8 and MOVS    R3, #8|#0x8.

  Args:
   disasm: (str) disassembly of the current instruction.

  Returns:
   True or False based on whether the instruction adds an offset to
   JNIEnv ptr or mov the offset to a register.
  """
  global regs_offsets, regs_loads
  saved_disasm = disasm
  passed_adds = False
  disasm = remove_comment_from_disasm(disasm)
  if REGEX_OPT_ADD.match(disasm):
    passed_adds = True
    disasm = disasm.split("ADDS")[1].split(",")
  else:
    disasm = disasm.split("MOVS")[1].split(",")
  off = disasm[1].strip()[1:]
  mov_add_reg = disasm[0].strip()
  if "0x" in off:
    off = int(off[2:], 16)
  offset = int(off)
  # probably a false positive
  if offset == 0:
    return False
  if REGEX_OPT_MOV.match(saved_disasm):
    regs_loads[mov_add_reg] = False
  regs_offsets[mov_add_reg] = offset
  return passed_adds


def match_mov(disasm):
  """process instruction that copies content of one register to another.

  E.g MOV     R12, R3.

  Args:
   disasm: (str) disassembly of the current instruction.
  """
  global regs_offsets, regs_loads
  disasm = remove_comment_from_disasm(disasm)
  disasm = disasm.split("MOV")[1]
  disasm = disasm.split(",")
  dest_reg = disasm[0].strip()
  source_reg = disasm[1].strip()
  if source_reg in regs_offsets:
    regs_offsets[dest_reg] = regs_offsets[source_reg]
  if source_reg in regs_loads:
    regs_loads[dest_reg] = regs_loads[source_reg]
  else:
    regs_loads[dest_reg] = False


def match_ldr_mtd1_and_4(disasm):
  """Load function pointer.

  process instruction that loads function pointer into a register using
  REGEX_LDR_MTD1 or REGEX_LDR_MTD4. E.g LDR     R4, [R4,#67] and
  LDR     R4, [R4,#0x7C].

  Args:
   disasm: (str) disassembly of the current instruction.

  Returns:
   True or False depending on whether instruction loads the function ptr.
  """
  global regs_offsets, regs_loads
  disasm = remove_comment_from_disasm(disasm)
  disasm = disasm.split("LDR")[1].split(",")
  dest_reg = disasm[0].strip()
  off = disasm[2].strip()
  ind = off.find("]")
  off = off[1:ind]
  if "0x" in off:
    off = int(off[2:], 16)
  if disasm[1].strip()[1:] in regs_offsets:
    regs_offsets[disasm[1].strip()[1:]] += int(off)
  else:
    regs_offsets[disasm[1].strip()[1:]] = int(off)
  regs_offsets[dest_reg] = regs_offsets[disasm[1].strip()[1:]]
  regs_loads[dest_reg] = False
  passed_ldmtd = True
  return passed_ldmtd


def match_ldr_mtd2(disasm):
  """Load function pointer.

  process instruction that loads function pointer into a register using
  REGEX_LDR_MTD2. E.g LDR     R3, [R4,R3].

  Args:
   disasm: (str) disassembly of the current instruction.

  Returns:
   True or False depending on whether instruction loads the function ptr.
  """
  global regs_offsets, regs_loads
  disasm = remove_comment_from_disasm(disasm)
  disasm = disasm.split("LDR")[1].split(",")
  dest_reg = disasm[0].strip()
  set_reg = disasm[2].strip()[:-1]
  if set_reg in regs_offsets:
    regs_offsets[dest_reg] = regs_offsets[set_reg]
  else:
    regs_offsets[dest_reg] = 0
  regs_loads[dest_reg] = False
  passed_ldmtd = True
  return passed_ldmtd


def match_ldr_mtd3(disasm):
  """Load function pointer.

  process instruction that loads function pointer into a register using
  REGEX_LDR_MTD3. E.g LDR     R3, [R4].

  Args:
   disasm: (str) disassembly of the current instruction.

  Returns:
   True or False depending on whether instruction loads the function ptr.
  """
  global regs_offsets, regs_loads, last_inst_not_for_jnie
  passed_ldmtd = False
  disasm = remove_comment_from_disasm(disasm)
  disasm = disasm.split("LDR")[1].split(",")
  dest_reg = disasm[0].strip()
  set_reg = disasm[1].strip()[1:-1]
  if (set_reg in regs_offsets and set_reg in regs_loads and
      regs_loads[set_reg]):
    if set_reg in regs_offsets:
      regs_offsets[dest_reg] = regs_offsets[set_reg]
    else:
      regs_offsets[dest_reg] = 0
    regs_loads[dest_reg] = False
    passed_ldmtd = True
  last_inst_not_for_jnie = False
  return passed_ldmtd


def match_blx(ea, disasm):
  """process instruction that does the indirect call to JNIEnv function.

  E.g BLX     R4.

  Args:
   ea: (int) current address
   disasm: (str) disassembly of the current instruction.

  Returns:
   True or False depending on whether instruction loads the function ptr.
  """
  global regs_offsets, regs_loads, jnienv, num
  disasm = remove_comment_from_disasm(disasm)
  callee = disasm.split("BLX")[1].strip()
  if callee in regs_offsets and str(regs_offsets[callee]) in jnienv:
    idc.MakeComm(ea, str(jnienv[str(regs_offsets[callee])]))
    num += 1
  regs_offsets[callee] = -1
  regs_loads[callee] = False


def others_lds(disasm):
  """process LDR that was first mistaken as ldr_jnie or ldr_mtd3.

  Args:
   disasm: (str) disassembly of the current instruction.
  """
  global last_inst_not_for_jnie, last_inst_not_mtd3
  if "LDR" in disasm:
    loc_jnie = disasm.split("LDR")[1].split(",")[0].strip()
    if loc_jnie in regs_loads:
      regs_loads[loc_jnie] = False
  last_inst_not_for_jnie = False
  last_inst_not_mtd3 = False


def extract_routines():
  """Function extracts refs to JNIEnv."""
  global regs_offsets, regs_loads, num, min_func_len, jnienv
  global last_inst_not_for_jnie, last_inst_not_mtd3
  # get JNI function signatures
  jnienv = create_jnienv_indices()

  # gets all functions defined in the binary
  for i in range(ida_funcs.get_func_qty()):
    func = ida_funcs.getn_func(i)
    start_ea = func.startEA
    end_ea = func.endEA

    # not completely sure if end_ea will always be greater than start_ea
    if end_ea - start_ea < min_func_len:
      continue
    ea = start_ea
    passed_ldjnie = False
    passed_adds = False
    passed_ldmtd = False
    last_inst_not_for_jnie = False
    last_inst_not_mtd3 = False

    # not completely sure if end_ea will always be greater than start_ea
    while ea <= end_ea:
      disasm = idc.GetDisasm(ea)
      # check for instruction that moves JNIEnv ptr to a reg
      if REGEX_LDR_JNIE.match(disasm) and not last_inst_not_for_jnie:
        old_passed_ldjnie = passed_ldjnie
        passed_ldjnie = match_ldr_jnie(disasm)
        if passed_ldjnie:
          ea = idc.NextHead(ea)
        else:
          passed_ldjnie = old_passed_ldjnie
          last_inst_not_for_jnie = True

      # check if a literal value gets added to the reg holding JNIEnv ptr.
      # keep track of that offset
      elif REGEX_OPT_ADD.match(disasm) or REGEX_OPT_MOV.match(disasm):
        passed_adds = match_opt_adds(disasm)
        ea = idc.NextHead(ea)

      # check if the content of a reg gets moved to another reg. Data
      # associated to the source reg is linked to the destination reg
      # in match_mov(disasm)
      elif REGEX_MOV.match(disasm):
        match_mov(disasm)
        ea = idc.NextHead(ea)

      # instns that match this regex may be loading the exact function ptr.
      # This instn adds an additional offset.
      # Get the offset and add it to any prev offset maybe from REGEX_OPT_ADD
      elif ((REGEX_LDR_MTD1.match(disasm) or REGEX_LDR_MTD4.match(disasm))
            and passed_ldjnie):
        passed_ldmtd = match_ldr_mtd1_and_4(disasm)
        ea = idc.NextHead(ea)

      # instns that match this regex may be loading the exact function ptr.
      # Uses another reg to specify offset, usually from REGEX_OPT_MOV
      elif REGEX_LDR_MTD2.match(disasm) and passed_ldjnie:
        passed_ldmtd = match_ldr_mtd2(disasm)
        ea = idc.NextHead(ea)

      # instns that match this regex may be loading the exact function ptr
      elif (REGEX_LDR_MTD3.match(disasm) and passed_ldjnie and passed_adds
            and not last_inst_not_mtd3):
        passed_ldmtd = match_ldr_mtd3(disasm)
        if passed_ldmtd:
          ea = idc.NextHead(ea)
          last_inst_not_for_jnie = False
        else:
          last_inst_not_mtd3 = True

      # this instn calls the JNIEnv func.
      # Get the exact function signature using calculated offset and
      # add signature as comment at this callsite
      elif REGEX_BLX.match(disasm) and passed_ldmtd:
        match_blx(ea, disasm)
        ea = idc.NextHead(ea)
        passed_ldjnie = False
        passed_adds = False
        passed_ldmtd = False

      else:
        others_lds(disasm)
        ea = idc.NextHead(ea)
    regs_offsets.clear()
    regs_loads.clear()

  print("Done.", num, ("callsites have been updated with "
                       "JNIEnv function signatures"))


def create_jnienv_indices():
  """create dictionary of JNIEnv function signatures (offset -> signature)."""
  global jnienv
  jnienv = {
      "16": "jint        (*GetVersion)(JNIEnv *) ;",
      "20": ("jclass      (*DefineClass)(JNIEnv*, const char*,"
             " jobject, const jbyte*, jsize) ;"),
      "24": "jclass      (*FindClass)(JNIEnv*, const char*) ;",
      "28": "jmethodID   (*FromReflectedMethod)(JNIEnv*, jobject) ;",
      "32": "jfieldID    (*FromReflectedField)(JNIEnv*, jobject) ;",
      "36": ("jobject     (*ToReflectedMethod)"
             "(JNIEnv*, jclass, jmethodID, jboolean) ;"),
      "40": "jclass      (*GetSuperclass)(JNIEnv*, jclass) ;",
      "44": "jboolean    (*IsAssignableFrom)(JNIEnv*, jclass, jclass) ;",
      "48": ("jobject     (*ToReflectedField)"
             "(JNIEnv*, jclass, jfieldID, jboolean) ;"),
      "52": "jint        (*Throw)(JNIEnv*, jthrowable) ;",
      "56": "jint        (*ThrowNew)(JNIEnv *, jclass, const char *) ;",
      "60": "jthrowable  (*ExceptionOccurred)(JNIEnv*) ;",
      "64": "void        (*ExceptionDescribe)(JNIEnv*) ;",
      "68": "void        (*ExceptionClear)(JNIEnv*) ;",
      "72": "void        (*FatalError)(JNIEnv*, const char*) ;",
      "76": "jint        (*PushLocalFrame)(JNIEnv*, jint) ;",
      "80": "jobject     (*PopLocalFrame)(JNIEnv*, jobject) ;",
      "84": "jobject     (*NewGlobalRef)(JNIEnv*, jobject) ;",
      "88": "void        (*DeleteGlobalRef)(JNIEnv*, jobject) ;",
      "92": "void        (*DeleteLocalRef)(JNIEnv*, jobject) ;",
      "96": "jboolean    (*IsSameObject)(JNIEnv*, jobject, jobject) ;",
      "100": "jobject     (*NewLocalRef)(JNIEnv*, jobject) ;",
      "104": "jint        (*EnsureLocalCapacity)(JNIEnv*, jint) ;",
      "108": "jobject     (*AllocObject)(JNIEnv*, jclass) ;",
      "112": "jobject     (*NewObject)(JNIEnv*, jclass, jmethodID, ...) ;",
      "116": "jobject     (*NewObjectV)(JNIEnv*, jclass, jmethodID, va_list) ;",
      "120": "jobject     (*NewObjectA)(JNIEnv*, jclass, jmethodID, jvalue*) ;",
      "124": "jclass      (*GetObjectClass)(JNIEnv*, jobject) ;",
      "128": "jboolean    (*IsInstanceOf)(JNIEnv*, jobject, jclass) ;",
      "132": ("jmethodID   (*GetMethodID)"
              "(JNIEnv*, jclass, const char*, const char*) ;"),
      "136": ("jobject     (*CallObjectMethod)"
              "(JNIEnv*, jobject, jmethodID, ...) ;"),
      "140": ("jobject     (*CallObjectMethodV)"
              "(JNIEnv*, jobject, jmethodID, va_list) ;"),
      "144": ("jobject     (*CallObjectMethodA)"
              "(JNIEnv*, jobject, jmethodID, jvalue*) ;"),
      "148": ("jboolean    (*CallBooleanMethod)"
              "(JNIEnv*, jobject, jmethodID, ...) ;"),
      "152": ("jboolean    (*CallBooleanMethodV)"
              "(JNIEnv*, jobject, jmethodID, va_list) ;"),
      "156": ("jboolean    (*CallBooleanMethodA)"
              "(JNIEnv*, jobject, jmethodID, jvalue*) ;"),
      "160": ("jbyte       (*CallByteMethod)"
              "(JNIEnv*, jobject, jmethodID, ...) ;"),
      "164": ("jbyte       (*CallByteMethodV)"
              "(JNIEnv*, jobject, jmethodID, va_list) ;"),
      "168": ("jbyte       (*CallByteMethodA)"
              "(JNIEnv*, jobject, jmethodID, jvalue*) ;"),
      "172": ("jchar       (*CallCharMethod)"
              "(JNIEnv*, jobject, jmethodID, ...) ;"),
      "176": ("jchar       (*CallCharMethodV)"
              "(JNIEnv*, jobject, jmethodID, va_list) ;"),
      "180": ("jchar       (*CallCharMethodA)"
              "(JNIEnv*, jobject, jmethodID, jvalue*) ;"),
      "184": ("jshort      (*CallShortMethod)"
              "(JNIEnv*, jobject, jmethodID, ...) ;"),
      "188": ("jshort      (*CallShortMethodV)"
              "(JNIEnv*, jobject, jmethodID, va_list) ;"),
      "192": ("jshort      (*CallShortMethodA)"
              "(JNIEnv*, jobject, jmethodID, jvalue*) ;"),
      "196": ("jint        (*CallIntMethod)"
              "(JNIEnv*, jobject, jmethodID, ...) ;"),
      "200": ("jint        (*CallIntMethodV)"
              "(JNIEnv*, jobject, jmethodID, va_list) ;"),
      "204": ("jint        (*CallIntMethodA)"
              "(JNIEnv*, jobject, jmethodID, jvalue*) ;"),
      "208": ("jlong       (*CallLongMethod)"
              "(JNIEnv*, jobject, jmethodID, ...) ;"),
      "212": ("jlong       (*CallLongMethodV)"
              "(JNIEnv*, jobject, jmethodID, va_list) ;"),
      "216": ("jlong       (*CallLongMethodA)"
              "(JNIEnv*, jobject, jmethodID, jvalue*) ;"),
      "220": ("jfloat      (*CallFloatMethod)"
              "(JNIEnv*, jobject, jmethodID, ...) ;"),
      "224": ("jfloat      (*CallFloatMethodV)"
              "(JNIEnv*, jobject, jmethodID, va_list) ;"),
      "228": ("jfloat      (*CallFloatMethodA)"
              "(JNIEnv*, jobject, jmethodID, jvalue*) ;"),
      "232": ("jdouble     (*CallDoubleMethod)"
              "(JNIEnv*, jobject, jmethodID, ...) ;"),
      "236": ("jdouble     (*CallDoubleMethodV)"
              "(JNIEnv*, jobject, jmethodID, va_list) ;"),
      "240": ("jdouble     (*CallDoubleMethodA)"
              "(JNIEnv*, jobject, jmethodID, jvalue*) ;"),
      "244": ("void        (*CallVoidMethod)"
              "(JNIEnv*, jobject, jmethodID, ...) ;"),
      "248": ("void        (*CallVoidMethodV)"
              "(JNIEnv*, jobject, jmethodID, va_list) ;"),
      "252": ("void        (*CallVoidMethodA)"
              "(JNIEnv*, jobject, jmethodID, jvalue*) ;"),
      "256": ("jobject     (*CallNonvirtualObjectMethod)"
              "(JNIEnv*, jobject, jclass, jmethodID, ...) ;"),
      "260": ("jobject     (*CallNonvirtualObjectMethodV)"
              "(JNIEnv*, jobject, jclass, jmethodID, va_list) ;"),
      "264": ("jobject     (*CallNonvirtualObjectMethodA)"
              "(JNIEnv*, jobject, jclass, jmethodID, jvalue*) ;"),
      "268": ("jboolean    (*CallNonvirtualBooleanMethod)"
              "(JNIEnv*, jobject, jclass, jmethodID, ...) ;"),
      "272": ("jboolean    (*CallNonvirtualBooleanMethodV)"
              "(JNIEnv*, jobject, jclass, jmethodID, va_list) ;"),
      "276": ("jboolean    (*CallNonvirtualBooleanMethodA)"
              "(JNIEnv*, jobject, jclass, jmethodID, jvalue*) ;"),
      "280": ("jbyte       (*CallNonvirtualByteMethod)"
              "(JNIEnv*, jobject, jclass, jmethodID, ...) ;"),
      "284": ("jbyte       (*CallNonvirtualByteMethodV)"
              "(JNIEnv*, jobject, jclass, jmethodID, va_list) ;"),
      "288": ("jbyte       (*CallNonvirtualByteMethodA)"
              "(JNIEnv*, jobject, jclass, jmethodID, jvalue*) ;"),
      "292": ("jchar       (*CallNonvirtualCharMethod)"
              "(JNIEnv*, jobject, jclass, jmethodID, ...) ;"),
      "296": ("jchar       (*CallNonvirtualCharMethodV)"
              "(JNIEnv*, jobject, jclass, jmethodID, va_list) ;"),
      "300": ("jchar       (*CallNonvirtualCharMethodA)"
              "(JNIEnv*, jobject, jclass, jmethodID, jvalue*) ;"),
      "304": ("jshort      (*CallNonvirtualShortMethod)"
              "(JNIEnv*, jobject, jclass, jmethodID, ...) ;"),
      "308": ("jshort      (*CallNonvirtualShortMethodV)"
              "(JNIEnv*, jobject, jclass, jmethodID, va_list) ;"),
      "312": ("jshort      (*CallNonvirtualShortMethodA)"
              "(JNIEnv*, jobject, jclass, jmethodID, jvalue*) ;"),
      "316": ("jint        (*CallNonvirtualIntMethod)"
              "(JNIEnv*, jobject, jclass, jmethodID, ...) ;"),
      "320": ("jint        (*CallNonvirtualIntMethodV)"
              "(JNIEnv*, jobject, jclass, jmethodID, va_list) ;"),
      "324": ("jint        (*CallNonvirtualIntMethodA)"
              "(JNIEnv*, jobject, jclass, jmethodID, jvalue*) ;"),
      "328": ("jlong       (*CallNonvirtualLongMethod)"
              "(JNIEnv*, jobject, jclass, jmethodID, ...) ;"),
      "332": ("jlong       (*CallNonvirtualLongMethodV)"
              "(JNIEnv*, jobject, jclass, jmethodID, va_list) ;"),
      "336": ("jlong       (*CallNonvirtualLongMethodA)"
              "(JNIEnv*, jobject, jclass, jmethodID, jvalue*) ;"),
      "340": ("jfloat      (*CallNonvirtualFloatMethod)"
              "(JNIEnv*, jobject, jclass, jmethodID, ...) ;"),
      "344": ("jfloat      (*CallNonvirtualFloatMethodV)"
              "(JNIEnv*, jobject, jclass, jmethodID, va_list) ;"),
      "348": ("jfloat      (*CallNonvirtualFloatMethodA)"
              "(JNIEnv*, jobject, jclass, jmethodID, jvalue*) ;"),
      "352": ("jdouble     (*CallNonvirtualDoubleMethod)"
              "(JNIEnv*, jobject, jclass, jmethodID, ...) ;"),
      "356": ("jdouble     (*CallNonvirtualDoubleMethodV)"
              "(JNIEnv*, jobject, jclass, jmethodID, va_list) ;"),
      "360": "context",
      "364": ("void        (*CallNonvirtualVoidMethod)"
              "(JNIEnv*, jobject, jclass, jmethodID, ...) ;"),
      "368": ("void        (*CallNonvirtualVoidMethodV)"
              "(JNIEnv*, jobject, jclass, jmethodID, va_list) ;"),
      "372": ("void        (*CallNonvirtualVoidMethodA)"
              "(JNIEnv*, jobject, jclass, jmethodID, jvalue*) ;"),
      "376": ("jfieldID    (*GetFieldID)"
              "(JNIEnv*, jclass, const char*, const char*) ;"),
      "380": "jobject     (*GetObjectField)(JNIEnv*, jobject, jfieldID) ;",
      "384": "jboolean    (*GetBooleanField)(JNIEnv*, jobject, jfieldID) ;",
      "388": "jbyte       (*GetByteField)(JNIEnv*, jobject, jfieldID) ;",
      "392": "jchar       (*GetCharField)(JNIEnv*, jobject, jfieldID) ;",
      "396": "jshort      (*GetShortField)(JNIEnv*, jobject, jfieldID) ;",
      "400": "jint        (*GetIntField)(JNIEnv*, jobject, jfieldID) ;",
      "404": "jlong       (*GetLongField)(JNIEnv*, jobject, jfieldID) ;",
      "408": "jfloat      (*GetFloatField)(JNIEnv*, jobject, jfieldID) ;",
      "412": "jdouble     (*GetDoubleField)(JNIEnv*, jobject, jfieldID) ;",
      "416": ("void        (*SetObjectField)"
              "(JNIEnv*, jobject, jfieldID, jobject) ;"),
      "420": ("void        (*SetBooleanField)"
              "(JNIEnv*, jobject, jfieldID, jboolean) ;"),
      "424": "void        (*SetByteField)(JNIEnv*, jobject, jfieldID, jbyte) ;",
      "428": "void        (*SetCharField)(JNIEnv*, jobject, jfieldID, jchar) ;",
      "432": ("void        (*SetShortField)"
              "(JNIEnv*, jobject, jfieldID, jshort) ;"),
      "436": "void        (*SetIntField)(JNIEnv*, jobject, jfieldID, jint) ;",
      "440": "void        (*SetLongField)(JNIEnv*, jobject, jfieldID, jlong) ;",
      "444": ("void        (*SetFloatField)"
              "(JNIEnv*, jobject, jfieldID, jfloat) ;"),
      "448": ("void        (*SetDoubleField)"
              "(JNIEnv*, jobject, jfieldID, jdouble) ;"),
      "452": ("jmethodID   (*GetStaticMethodID)"
              "(JNIEnv*, jclass, const char*, const char*) ;"),
      "456": ("jobject     (*CallStaticObjectMethod)"
              "(JNIEnv*, jclass, jmethodID, ...) ;"),
      "460": ("jobject     (*CallStaticObjectMethodV)"
              "(JNIEnv*, jclass, jmethodID, va_list) ;"),
      "464": ("jobject     (*CallStaticObjectMethodA)"
              "(JNIEnv*, jclass, jmethodID, jvalue*) ;"),
      "468": ("jboolean    (*CallStaticBooleanMethod)"
              "(JNIEnv*, jclass, jmethodID, ...) ;"),
      "472": ("jboolean    (*CallStaticBooleanMethodV)"
              "(JNIEnv*, jclass, jmethodID, va_list) ;"),
      "476": ("jboolean    (*CallStaticBooleanMethodA)"
              "(JNIEnv*, jclass, jmethodID, jvalue*) ;"),
      "480": ("jbyte       (*CallStaticByteMethod)"
              "(JNIEnv*, jclass, jmethodID, ...) ;"),
      "484": ("jbyte       (*CallStaticByteMethodV)"
              "(JNIEnv*, jclass, jmethodID, va_list) ;"),
      "488": ("jbyte       (*CallStaticByteMethodA)"
              "(JNIEnv*, jclass, jmethodID, jvalue*) ;"),
      "492": ("jchar       (*CallStaticCharMethod)"
              "(JNIEnv*, jclass, jmethodID, ...) ;"),
      "496": ("jchar       (*CallStaticCharMethodV)"
              "(JNIEnv*, jclass, jmethodID, va_list) ;"),
      "500": ("jchar       (*CallStaticCharMethodA)"
              "(JNIEnv*, jclass, jmethodID, jvalue*) ;"),
      "504": ("jshort      (*CallStaticShortMethod)"
              "(JNIEnv*, jclass, jmethodID, ...) ;"),
      "508": ("jshort      (*CallStaticShortMethodV)"
              "(JNIEnv*, jclass, jmethodID, va_list) ;"),
      "512": ("jshort      (*CallStaticShortMethodA)"
              "(JNIEnv*, jclass, jmethodID, jvalue*) ;"),
      "516": ("jint        (*CallStaticIntMethod)"
              "(JNIEnv*, jclass, jmethodID, ...) ;"),
      "520": ("jint        (*CallStaticIntMethodV)"
              "(JNIEnv*, jclass, jmethodID, va_list) ;"),
      "524": ("jint        (*CallStaticIntMethodA)"
              "(JNIEnv*, jclass, jmethodID, jvalue*) ;"),
      "528": ("jlong       (*CallStaticLongMethod)"
              "(JNIEnv*, jclass, jmethodID, ...) ;"),
      "532": ("jlong       (*CallStaticLongMethodV)"
              "(JNIEnv*, jclass, jmethodID, va_list) ;"),
      "536": ("jlong       (*CallStaticLongMethodA)"
              "(JNIEnv*, jclass, jmethodID, jvalue*) ;"),
      "540": ("jfloat      (*CallStaticFloatMethod)"
              "(JNIEnv*, jclass, jmethodID, ...) ;"),
      "544": ("jfloat      (*CallStaticFloatMethodV)"
              "(JNIEnv*, jclass, jmethodID, va_list) ;"),
      "548": ("jfloat      (*CallStaticFloatMethodA)"
              "(JNIEnv*, jclass, jmethodID, jvalue*) ;"),
      "552": ("jdouble     (*CallStaticDoubleMethod)"
              "(JNIEnv*, jclass, jmethodID, ...) ;"),
      "556": ("jdouble     (*CallStaticDoubleMethodV)"
              "(JNIEnv*, jclass, jmethodID, va_list) ;"),
      "560": ("jdouble     (*CallStaticDoubleMethodA)"
              "(JNIEnv*, jclass, jmethodID, jvalue*) ;"),
      "564": ("void        (*CallStaticVoidMethod)"
              "(JNIEnv*, jclass, jmethodID, ...) ;"),
      "568": ("void        (*CallStaticVoidMethodV)"
              "(JNIEnv*, jclass, jmethodID, va_list) ;"),
      "572": ("void        (*CallStaticVoidMethodA)"
              "(JNIEnv*, jclass, jmethodID, jvalue*) ;"),
      "576": ("jfieldID    (*GetStaticFieldID)"
              "(JNIEnv*, jclass, const char*, const char*) ;"),
      "580": "jobject     (*GetStaticObjectField)(JNIEnv*, jclass, jfieldID) ;",
      "584": ("jboolean    (*GetStaticBooleanField)"
              "(JNIEnv*, jclass, jfieldID) ;"),
      "588": "jbyte       (*GetStaticByteField)(JNIEnv*, jclass, jfieldID) ;",
      "592": "jchar       (*GetStaticCharField)(JNIEnv*, jclass, jfieldID) ;",
      "596": "jshort      (*GetStaticShortField)(JNIEnv*, jclass, jfieldID) ;",
      "600": "jint        (*GetStaticIntField)(JNIEnv*, jclass, jfieldID) ;",
      "604": "jlong       (*GetStaticLongField)(JNIEnv*, jclass, jfieldID) ;",
      "608": "jfloat      (*GetStaticFloatField)(JNIEnv*, jclass, jfieldID) ;",
      "612": "jdouble     (*GetStaticDoubleField)(JNIEnv*, jclass, jfieldID) ;",
      "616": ("void        (*SetStaticObjectField)"
              "(JNIEnv*, jclass, jfieldID, jobject) ;"),
      "620": ("void        (*SetStaticBooleanField)"
              "(JNIEnv*, jclass, jfieldID, jboolean) ;"),
      "624": ("void        (*SetStaticByteField)"
              "(JNIEnv*, jclass, jfieldID, jbyte) ;"),
      "628": ("void        (*SetStaticCharField)"
              "(JNIEnv*, jclass, jfieldID, jchar) ;"),
      "632": ("void        (*SetStaticShortField)"
              "(JNIEnv*, jclass, jfieldID, jshort) ;"),
      "636": ("void        (*SetStaticIntField)"
              "(JNIEnv*, jclass, jfieldID, jint) ;"),
      "640": ("void        (*SetStaticLongField)"
              "(JNIEnv*, jclass, jfieldID, jlong) ;"),
      "644": ("void        (*SetStaticFloatField)"
              "(JNIEnv*, jclass, jfieldID, jfloat) ;"),
      "648": ("void        (*SetStaticDoubleField)"
              "(JNIEnv*, jclass, jfieldID, jdouble) ;"),
      "652": "jstring     (*NewString)(JNIEnv*, const jchar*, jsize) ;",
      "656": "jsize       (*GetStringLength)(JNIEnv*, jstring) ;",
      "660": "const jchar* (*GetStringChars)(JNIEnv*, jstring, jboolean*) ;",
      "664": ("void        (*ReleaseStringChars)"
              "(JNIEnv*, jstring, const jchar*) ;"),
      "668": "jstring     (*NewStringUTF)(JNIEnv*, const char*) ;",
      "672": "jsize       (*GetStringUTFLength)(JNIEnv*, jstring) ;",
      "676": "const char* (*GetStringUTFChars)(JNIEnv*, jstring, jboolean*) ;",
      "680": ("void        (*ReleaseStringUTFChars)"
              "(JNIEnv*, jstring, const char*) ;"),
      "684": "jsize       (*GetArrayLength)(JNIEnv*, jarray) ;",
      "688": ("jobjectArray (*NewObjectArray)"
              "(JNIEnv*, jsize, jclass, jobject) ;"),
      "692": ("jobject     (*GetObjectArrayElement)"
              "(JNIEnv*, jobjectArray, jsize) ;"),
      "696": ("void        (*SetObjectArrayElement)"
              "(JNIEnv*, jobjectArray, jsize, jobject) ;"),
      "700": "jbooleanArray (*NewBooleanArray)(JNIEnv*, jsize) ;",
      "704": "jbyteArray    (*NewByteArray)(JNIEnv*, jsize) ;",
      "708": "jcharArray    (*NewCharArray)(JNIEnv*, jsize) ;",
      "712": "jshortArray   (*NewShortArray)(JNIEnv*, jsize) ;",
      "716": "jintArray     (*NewIntArray)(JNIEnv*, jsize) ;",
      "720": "jlongArray    (*NewLongArray)(JNIEnv*, jsize) ;",
      "724": "jfloatArray   (*NewFloatArray)(JNIEnv*, jsize) ;",
      "728": "jdoubleArray  (*NewDoubleArray)(JNIEnv*, jsize) ;",
      "732": ("jboolean*   (*GetBooleanArrayElements)"
              "(JNIEnv*, jbooleanArray, jboolean*) ;"),
      "736": ("jbyte*      (*GetByteArrayElements)"
              "(JNIEnv*, jbyteArray, jboolean*) ;"),
      "740": ("jchar*      (*GetCharArrayElements)"
              "(JNIEnv*, jcharArray, jboolean*) ;"),
      "744": ("jshort*     (*GetShortArrayElements)"
              "(JNIEnv*, jshortArray, jboolean*) ;"),
      "748": ("jint*       (*GetIntArrayElements)"
              "(JNIEnv*, jintArray, jboolean*) ;"),
      "752": ("jlong*      (*GetLongArrayElements)"
              "(JNIEnv*, jlongArray, jboolean*) ;"),
      "756": ("jfloat*     (*GetFloatArrayElements)"
              "(JNIEnv*, jfloatArray, jboolean*) ;"),
      "760": ("jdouble*    (*GetDoubleArrayElements)"
              "(JNIEnv*, jdoubleArray, jboolean*) ;"),
      "764": ("void        (*ReleaseBooleanArrayElements)"
              "(JNIEnv*, jbooleanArray, jboolean*, jint) ;"),
      "768": ("void        (*ReleaseByteArrayElements)"
              "(JNIEnv*, jbyteArray, jbyte*, jint) ;"),
      "772": ("void        (*ReleaseCharArrayElements)"
              "(JNIEnv*, jcharArray, jchar*, jint) ;"),
      "776": ("void        (*ReleaseShortArrayElements)"
              "(JNIEnv*, jshortArray, jshort*, jint) ;"),
      "780": ("void        (*ReleaseIntArrayElements)"
              "(JNIEnv*, jintArray, jint*, jint) ;"),
      "784": ("void        (*ReleaseLongArrayElements)"
              "(JNIEnv*, jlongArray, jlong*, jint) ;"),
      "788": ("void        (*ReleaseFloatArrayElements)"
              "(JNIEnv*, jfloatArray, jfloat*, jint) ;"),
      "792": ("void        (*ReleaseDoubleArrayElements)"
              "(JNIEnv*, jdoubleArray, jdouble*, jint) ;"),
      "796": ("void        (*GetBooleanArrayRegion)"
              "(JNIEnv*, jbooleanArray, jsize, jsize, jboolean*) ;"),
      "800": ("void        (*GetByteArrayRegion)"
              "(JNIEnv*, jbyteArray, jsize, jsize, jbyte*) ;"),
      "804": ("void        (*GetCharArrayRegion)"
              "(JNIEnv*, jcharArray, jsize, jsize, jchar*) ;"),
      "808": ("void        (*GetShortArrayRegion)"
              "(JNIEnv*, jshortArray, jsize, jsize, jshort*) ;"),
      "812": ("void        (*GetIntArrayRegion)"
              "(JNIEnv*, jintArray, jsize, jsize, jint*) ;"),
      "816": ("void        (*GetLongArrayRegion)"
              "(JNIEnv*, jlongArray, jsize, jsize, jlong*) ;"),
      "820": ("void        (*GetFloatArrayRegion)"
              "(JNIEnv*, jfloatArray, jsize, jsize, jfloat*) ;"),
      "824": ("void        (*GetDoubleArrayRegion)"
              "(JNIEnv*, jdoubleArray, jsize, jsize, jdouble*) ;"),
      "828": ("void        (*SetBooleanArrayRegion)"
              "(JNIEnv*, jbooleanArray, jsize, jsize, const jboolean*) ;"),
      "832": ("void        (*SetByteArrayRegion)"
              "(JNIEnv*, jbyteArray, jsize, jsize, const jbyte*) ;"),
      "836": ("void        (*SetCharArrayRegion)"
              "(JNIEnv*, jcharArray, jsize, jsize, const jchar*) ;"),
      "840": ("void        (*SetShortArrayRegion)"
              "(JNIEnv*, jshortArray, jsize, jsize, const jshort*) ;"),
      "844": ("void        (*SetIntArrayRegion)"
              "(JNIEnv*, jintArray, jsize, jsize, const jint*) ;"),
      "848": ("void        (*SetLongArrayRegion)"
              "(JNIEnv*, jlongArray, jsize, jsize, const jlong*) ;"),
      "852": ("void        (*SetFloatArrayRegion)"
              "(JNIEnv*, jfloatArray, jsize, jsize, const jfloat*) ;"),
      "856": ("void        (*SetDoubleArrayRegion)"
              "(JNIEnv*, jdoubleArray, jsize, jsize, const jdouble*) ;"),
      "860": ("jint        (*RegisterNatives)"
              "(JNIEnv*, jclass, const JNINativeMethod*, jint) ;"),
      "864": "jint        (*UnregisterNatives)"
             "(JNIEnv*, jclass) ;",
      "868": "jint        (*MonitorEnter)(JNIEnv*, jobject) ;",
      "872": "jint        (*MonitorExit)(JNIEnv*, jobject) ;",
      "876": "jint        (*GetJavaVM)(JNIEnv*, JavaVM**) ;",
      "880": ("void        (*GetStringRegion)"
              "(JNIEnv*, jstring, jsize, jsize, jchar*) ;"),
      "884": ("void        (*GetStringUTFRegion)"
              "(JNIEnv*, jstring, jsize, jsize, char*) ;"),
      "888": ("void*       (*GetPrimitiveArrayCritical)"
              "(JNIEnv*, jarray, jboolean*) ;"),
      "892": ("void        (*ReleasePrimitiveArrayCritical)"
              "(JNIEnv*, jarray, void*, jint) ;"),
      "896": ("const jchar* (*GetStringCritical)"
              "(JNIEnv*, jstring, jboolean*) ;"),
      "900": ("void        (*ReleaseStringCritical)"
              "(JNIEnv*, jstring, const jchar*) ;"),
      "904": "jweak       (*NewWeakGlobalRef)(JNIEnv*, jobject) ;",
      "908": "void        (*DeleteWeakGlobalRef)(JNIEnv*, jweak) ;",
      "912": "jboolean    (*ExceptionCheck)(JNIEnv*) ;",
      "916": "jobject     (*NewDirectByteBuffer)(JNIEnv*, void*, jlong) ;",
      "920": "void*       (*GetDirectBufferAddress)(JNIEnv*, jobject) ;",
      "924": "jlong       (*GetDirectBufferCapacity)(JNIEnv*, jobject) ;",
      "928": "jobjectRefType (*GetObjectRefType)(JNIEnv*, jobject) ;"}
  return jnienv


def run_test():
  """TEST to be sure that regex works fine."""
  print("*"*20)
  test_regex_push()
  test_regex_ldr_jnie()
  test_regex_opt_add()
  test_regex_opt_mov()
  test_regex_mov()
  test_regex_ldr_mtd1()
  test_regex_ldr_mtd14()
  test_regex_ldr_mtd2()
  test_regex_ldr_mtd3()
  test_regex_blx()
  test_regex_pop()


def test_regex_push():
  """TEST REGEX_PUSH."""
  print(REGEX_PUSH.match("PUSH    {R4, LR}"), "Should pass push")
  print(REGEX_PUSH.match("PUSH    {R3-R5,LR}"), "Should pass push")
  print(REGEX_PUSH.match("POP    {R14,LR}"), "Should Fail")


def test_regex_ldr_jnie():
  """TEST REGEX_LDR_JNIE."""
  print(REGEX_LDR_JNIE.match("LDR     R4, [R0]"), "Should pass jni")


def test_regex_opt_add():
  """TEST regex_REGEX_OPT_ADD."""
  print(REGEX_OPT_ADD.match("ADDS    R4, #0xFC"), "Should pass adds")


def test_regex_opt_mov():
  """TEST regex_REGEX_OPT_MOV."""
  print(REGEX_OPT_MOV.match("MOVS    R3, #0x17C"), "Should pass movs")


def test_regex_mov():
  """TEST regex_REGEX_MOV."""
  print(REGEX_MOV.match("MOV     R12, R3"), "Should pass mov")


def test_regex_ldr_mtd1():
  """TEST REGEX_LDR_MTD1."""
  print(REGEX_LDR_MTD1.match("LDR     R4, [R4,#45]"), "Should pass mtd1")


def test_regex_ldr_mtd14():
  """TEST REGEX_LDR_MTD4."""
  print(REGEX_LDR_MTD4.match("LDR     R4, [R4,#0x7C]"), "Should pass mtd4")


def test_regex_ldr_mtd2():
  """TEST REGEX_LDR_MTD2."""
  print(REGEX_LDR_MTD2.match("LDR     R3, [R4,R3]"), "Should pass mtd2")


def test_regex_ldr_mtd3():
  """TEST REGEX_LDR_MTD3."""
  print(REGEX_LDR_MTD3.match("LDR     R3, [R4]"), "Should pass mtd3")


def test_regex_blx():
  """TEST REGEX_BLX."""
  print(REGEX_BLX.match("BLX     R4"), "Should pass blx")


def test_regex_pop():
  """TEST REGEX_POP."""
  print(REGEX_POP.match("POP     {R4,PC}"), "Should pass pop")


def main():
  """main function."""
  extract_routines()

if __name__ == "__main__":
  main()
