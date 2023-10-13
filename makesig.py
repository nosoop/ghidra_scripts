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
import ghidra.program.model.address.AddressSet as AddressSet

MAKE_SIG_AT = collections.OrderedDict([
	('fn', 'start of function'),
	('cursor', 'instruction at cursor')
])

BytePattern = collections.namedtuple('BytePattern', ['is_wildcard', 'byte'])

def __bytepattern_ida_str(self):
	# return an IDA-style binary search string
	return '{:02X}'.format(self.byte) if not self.is_wildcard else '?'

def __bytepattern_sig_str(self):
	# return a SourceMod-style byte signature
	return r'\x{:02X}'.format(self.byte) if not self.is_wildcard else r'\x2A'

BytePattern.ida_str = __bytepattern_ida_str
BytePattern.sig_str = __bytepattern_sig_str

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
	return optype & (OperandType.ADDRESS or OperandType.DATA) or optype & (OperandType.ADDRESS or OperandType.SCALAR)

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
	
	for m, b in zip(mask, ins.getBytes()):
		if m == 0xFF:
			# we only check for fully masked bytes at the moment
			yield BytePattern(is_wildcard = True, byte = None)
		else:
			yield BytePattern(byte = b & 0xFF, is_wildcard = False)

# removes trailing wilds from the sig
def cleanupWilds(byte_pattern):
	for byte in reversed(byte_pattern):
		if byte.is_wildcard is False:
			break
		del byte_pattern[-1]

def process(start_at = MAKE_SIG_AT['fn'], min_length = 1):
	fm = currentProgram.getFunctionManager()
	fn = fm.getFunctionContaining(currentAddress)
	cm = currentProgram.getCodeManager()

	if start_at == MAKE_SIG_AT['fn']:
		ins = cm.getInstructionAt(fn.getEntryPoint())
	elif start_at == MAKE_SIG_AT['cursor']:
		try:
			# Ghidra 10.4 introduces an additional parameter 'usePrototypeLength'
			# it will throw on older versions, so fall back to the previous version
			ins = cm.getInstructionContaining(currentAddress, False)
		except TypeError:
			ins = cm.getInstructionContaining(currentAddress)
	
	if not ins:
		raise Exception("Could not find entry point to function")

	pattern = "" # contains pattern string (supports regular expressions)
	byte_pattern = [] # contains BytePattern instances
	
	# keep track of our matches
	matches = []
	match_limit = 128
	
	while fm.getFunctionContaining(ins.getAddress()) == fn:
		for entry in getMaskedInstruction(ins):
			byte_pattern.append(entry)
			if entry.is_wildcard:
				pattern += '.'
			else:
				pattern += r'\x{:02x}'.format(entry.byte)
		
		expected_next = ins.getAddress().add(ins.length)
		ins = ins.getNext()
		
		if ins.getAddress() != expected_next:
			# add wildcards until we get to the next instruction
			for _ in range(ins.getAddress().subtract(expected_next)):
				byte_pattern.append(BytePattern(is_wildcard = True, byte = None))
				pattern += '.'
		
		if len(byte_pattern) < min_length:
			continue
		
		if 0 < len(matches) < match_limit:
			# we have all the remaining matches, start only searching those addresses
			match_set = AddressSet()
			for addr in matches:
				match_set.add(addr, addr.add(len(byte_pattern)))
			matches = findBytes(match_set, pattern, match_limit, 1)
		else:
			# the matches are sorted in ascending order, so the first match will be the start
			matches = findBytes(matches[0] if len(matches) else None, pattern, match_limit)
		
		if len(matches) < 2:
			break
	
	if not len(matches) == 1:
		print(*(b.ida_str() for b in byte_pattern))
		print('Signature matched', len(matches), 'locations:', *(matches))
		printerr("Could not find unique signature")
	else:
		cleanupWilds(byte_pattern)
		print("Signature for", fn.getName())
		print(*(b.ida_str() for b in byte_pattern))
		print("".join(b.sig_str() for b in byte_pattern))

if __name__ == "__main__":
	fm = currentProgram.getFunctionManager()
	fn = fm.getFunctionContaining(currentAddress)
	if not fn:
		printerr("Not in a function")
	else:
		start_at = askChoice("makesig", "Make sig at:", MAKE_SIG_AT.values(), MAKE_SIG_AT['fn'])
		
		# we currently don't expose min_length
		# TODO: rework askChoice to use a custom panel with all options
		process(start_at, min_length = 1)
