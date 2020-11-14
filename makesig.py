#Generates a SourceMod-ready signature.
#@author nosoop
#@category _NEW_
#@keybinding 
#@menupath 
#@toolbar 

from __future__ import print_function

import ghidra.program.model.lang.OperandType as OperandType
import ghidra.program.model.lang.Register as Register

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
			yield None
		else:
			yield b & 0xFF

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
	byte_pattern = [] # contains integers 0x00 to 0xFF, or None if the byte was masked
	
	found = False
	
	# store the address of the first match, if any
	# this provides a small speedup in certain cases by not searching the whole space
	# TODO take advantage of the address list by testing for matches instead of scanning
	start_address = None
	while not found and fm.getFunctionContaining(ins.getAddress()) == fn:
		for entry in getMaskedInstruction(ins):
			if entry is None:
				pattern += '.'
				byte_pattern.append(None)
			else:
				pattern += r'\x{:02x}'.format(entry)
				byte_pattern.append(entry)
		
		is_unique, start_address = findUniqueSig(pattern, start_address)
		if is_unique:
			found = True
			break
		ins = ins.getNext()
	
	if not found:
		print(" ".join('{:02X}'.format(b) if b is not None else '?' for b in byte_pattern))
		raise Exception("Could not find unique signature")
	else:
		print("Signature for", fn.getName())
		print(*('{:02X}'.format(b) if b is not None else '?' for b in byte_pattern))
		print("".join(r'\x{:02X}'.format(b) if b is not None else r'\x2A' for b in byte_pattern))
