#Generates a SourceMod-ready signature.
#@author nosoop
#@category _NEW_
#@keybinding 
#@menupath 
#@toolbar 

from __future__ import print_function

import collections
import ghidra.program.model.lang.OperandType as OperandType
import ghidra.program.model.lang.Register as Register

BytePattern = collections.namedtuple('BytePattern', ['is_wildcard', 'byte'])

def __bytepattern_ida_str(self):
	return '{:02X}'.format(self.byte) if not self.is_wildcard else '?'

def __bytepattern_sig_str(self):
	return r'\x{:02X}'.format(self.byte) if not self.is_wildcard else r'\x2A'

BytePattern.ida_str = __bytepattern_ida_str
BytePattern.sig_str = __bytepattern_sig_str

def findUniqueSig(bs, start):
	"""
	Returns a tuple (is_unique, first_start_address) indicating whether a signature is unique.
	"""
	next_start_address = None
	result = findBytes(start, bs, 2)
	if len(result):
		next_start_address = result[0]
	return len(result) == 1, next_start_address

def dumpOperandInfo(ins, op):
	t = hex(ins.getOperandType(op))
	print('  ' + str(ins.getPrototype().getOperandValueMask(op)) + ' ' + str(t))
	
	# TODO if register
	for opobj in ins.getOpObjects(op):
		print('  - ' + str(opobj))

def shouldMaskOperand(ins, opIndex):
	"""
	Returns True if the given instruction operand mask should be masked in the signature.
	"""
	optype = ins.getOperandType(opIndex)
	# if any(reg.getName() == "EBP" for reg in filter(lambda op: isinstance(op, Register), ins.getOpObjects(opIndex))):
		# return False
	return optype & OperandType.DYNAMIC or optype & OperandType.ADDRESS

def getMaskedInstruction(ins):
	"""
	Returns a generator that outputs either a byte to match or None if the byte should be masked.
	"""
	# print(ins)
	
	# resulting mask should match the instruction length
	mask = [0] * ins.length
	
	proto = ins.getPrototype()
	# iterate over operands and mask bytes
	for op in range(proto.getNumOperands()):
		# dumpOperandInfo(ins, op)
		
		# TODO deal with partial byte masks
		if shouldMaskOperand(ins, op):
			mask = [ m | v & 0xFF for m, v in zip(mask, proto.getOperandValueMask(op).getBytes()) ]
	# print('  ' + str(mask))
	
	# TODO improve this logic
	for m, b in zip(mask, ins.getBytes()):
		if m == 0xFF:
			yield BytePattern(is_wildcard = True, byte = None)
		else:
			yield BytePattern(byte = b & 0xFF, is_wildcard = False)

if __name__ == "__main__":
	fm = currentProgram.getFunctionManager()
	fn = fm.getFunctionContaining(currentAddress)
	if not fn:
		raise Exception("Not in a function")

	cm = currentProgram.getCodeManager()

	start_at = askChoice("makesig", "Make sig at:", [ "start of function", "current instruction" ], "start of function")
	if start_at == "start of function":
		ins = cm.getInstructionAt(fn.getEntryPoint())
	elif start_at == "current instruction":
		ins = cm.getInstructionContaining(currentAddress)
	
	if not ins:
		raise Exception("Could not find entry point to function")

	pattern = "" # contains pattern string (supports regular expressions)
	byte_pattern = [] # contains BytePattern instances
	
	found = False
	
	# store the address of the first match, if any
	# this provides a small speedup in certain cases by not searching the whole space
	# TODO take advantage of the address list by testing for matches instead of scanning
	start_address = None
	while not found and fm.getFunctionContaining(ins.getAddress()) == fn:
		for entry in getMaskedInstruction(ins):
			byte_pattern.append(entry)
			if entry.is_wildcard:
				pattern += '.'
			else:
				pattern += r'\x{:02x}'.format(entry.byte)
		
		is_unique, start_address = findUniqueSig(pattern, start_address)
		if is_unique:
			found = True
			break
		ins = ins.getNext()
	
	if not found:
		print(*(b.ida_str() for b in byte_pattern))
		raise Exception("Could not find unique signature")
	else:
		print("Signature for", fn.getName())
		print(*(b.ida_str() for b in byte_pattern))
		print("".join(b.sig_str() for b in byte_pattern))
