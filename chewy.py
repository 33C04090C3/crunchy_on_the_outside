###############################################################################
# CHEWY - examine obfuscated x86 code and distinguish real control flow       #
#                                                                             #
# This script allows a single sequence of obfuscated code to be analysed.     #
# No actual deobfuscation is performed - yet.                                 #
###############################################################################
import random

# globals
count = 1

# make a simple random prefix for names used in this specific chunk of code
prefix = ""
prefix += chr( random.randint(0x61, 0x7B) )
prefix += chr( random.randint(0x61, 0x7B) )
prefix += chr( random.randint(0x61, 0x7B) )

def rename_target(ea):
    global count
    namestr = "%s%u" % (prefix, count)
    set_name( ea, namestr, SN_NOCHECK | SN_NOWARN )
    count = count + 1

def handle_call(insn, ea):
    if( insn.ops[0].addr == ea + 5 ):
        print( "CALL-TO-POP" )
        return ea + insn.size
    elif( get_wide_byte( insn.ops[0].addr ) == 0xC3 ):
        print( "CALL-TO-RET" )
        return ea + insn.size
    else:
        return 0

def handle_mov(insn, ea):
    if( insn.ops[0].type == o_reg and insn.ops[1].type == o_reg ): # ignore register-to-register MOVs
        return ea+insn.size
    else:
        return 0

def do_nothing(insn, ea):
    return ea + insn.size


def do_not_follow_jump(insn, ea):
    set_color( ea, CIC_ITEM, 0x0000FF )
    return ea + insn.size

def follow_jump(insn, ea):
    set_color( ea, CIC_ITEM, 0x00FF00 )
    del_items( insn.ops[0].addr, DELIT_SIMPLE )
    create_insn( insn.ops[0].addr )
    rename_target( insn.ops[0].addr )
    return insn.ops[0].addr

def setup_opaque_pred(insn, ea):
    # both must be registers and equal to each other
    if( ( insn.ops[0].type == o_reg ) and ( insn.ops[1].type == o_reg ) and ( insn.ops[0].reg == insn.ops[1].reg ) ):
        return ea + insn.size
    else:
        print( "%u, %u, %u, %u" % ( insn.ops[0].type, insn.ops[1].type, insn.ops[0].reg, insn.ops[1].reg ) )
        return 0

instruction_dispatcher = {
    'pusha' : do_nothing,
    'popa'  : do_nothing,
    'push'  : do_nothing,
    'pop'   : do_nothing,
    'jmp'   : follow_jump,
    'jp'    : follow_jump,
    'jz'    : follow_jump,
    'jns'   : follow_jump,
    'jno'   : follow_jump,
    'jnz'   : do_not_follow_jump,
    'jo'    : do_not_follow_jump,
    'jb'    : do_not_follow_jump,
    'jnp'   : do_not_follow_jump,
    'xor'   : setup_opaque_pred,
    'xchg'  : do_nothing,
    'bswap' : do_nothing,
    'not'   : do_nothing,
    'pushf' : do_nothing,
    'popf'  : do_nothing,
    'call'  : handle_call,
    'mov'   : handle_mov,
}

# start at the current screen position
current_address = get_screen_ea()
decoding = True

print( "=====START=====" )
# keep decoding until we either reach an unsupported instruction
# or get an error
while( decoding == True ):

    # special escape for B8 EB 07 B9 EB 0F 90 obfuscation sequence
    # wherein the EB 0F is actually a previous jump
    if( get_wide_dword( current_address ) == 0xB907EBB8 and get_wide_word( current_address + 5 ) == 0x900F ):
        print( "0x%08X - [MOV TRICK]" % current_address )
        current_address = current_address + 7
        continue

    # special escape for E8 09 00 00 00 E8 E8 trick
    # first E8 calls a function which patches a NOP into the first of the double E8
    if( get_wide_dword( current_address ) == 0x09E8 and get_wide_word( current_address + 5 ) == 0xE8E8 ):
        print( "0x%08X - [CALL TRICK]" % current_address )
        current_address = current_address + 6
        continue
        #real_call = ida_ua.insn_t()
        #if( ida_ua.decode_insn( real_call, current_address + 6 ) ):
         #   current_address = real_call.ops[0].addr
         #   print( "Real target: %08X" % current_address )
        #else:
        #    print( "Decoding error at %08X" % current_address + 6 )
        #    break


    current_instruction = ida_ua.insn_t()
    if ida_ua.decode_insn( current_instruction, current_address ):
        current_mnem = current_instruction.get_canon_mnem()
        print( "0x%08X - %s" % ( current_address, current_mnem ) )
        if( current_mnem in instruction_dispatcher ):
            retval = instruction_dispatcher[current_instruction.get_canon_mnem()](current_instruction, current_address)
            if( retval == 0 ):
                break
            current_address = retval
        else:
            break

print( "=====STOP======" )
