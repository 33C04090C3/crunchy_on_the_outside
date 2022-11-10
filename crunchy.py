###############################################################################
# CRUNCHY - penetrate the hard outer shell of obfuscation                     #
#                                                                             #
# To get this to work you will probably need to change the arguments to       #
# run_process() and also the base_address global.                             #
###############################################################################
import re

# change as appropriate
base_address  = 0x599000


rol_cl_regex    = re.compile( 'rol     byte ptr \[eax\], cl' )
rol_const_regex = re.compile( 'rol     byte ptr \[eax\], ([0-9A-F]+)h?' )

ror_cl_regex    = re.compile( 'ror     byte ptr \[eax\], cl' )
ror_const_regex = re.compile( 'ror     byte ptr \[eax\], ([0-9A-F]+)h?' )

#xor_cl_regex    = re.compile( 'xor     byte ptr \[eax\], cl' )
xor_cl_regex    = re.compile( 'xor     \[eax\], cl' )
xor_const_regex = re.compile( 'xor     byte ptr \[eax\], ([0-9A-F]+)h?' )

add_cl_regex    = re.compile( 'add     \[eax\], cl' )
add_const_regex = re.compile( 'add     byte ptr \[eax\], ([0-9A-F]+)h?' )

sub_cl_regex    = re.compile( 'sub     \[eax\], cl' )
sub_const_regex = re.compile( 'sub     byte ptr \[eax\], ([0-9A-F]+)h?' )

inc_regex       = re.compile( 'inc     byte ptr \[eax\]' )
dec_regex       = re.compile( 'dec     byte ptr \[eax\]' )

op_regex        = re.compile( '\[eax\]' )


# convert an obfuscation instruction into an operation command we can use later in deobfuscate_region()
def match_obf_line(line):
    if( op_regex.search(line) == None ):
        #print( "Line %s doesn't seem to be an op" % line )
        return None
    elif( rol_cl_regex.match(line) ):
        return ( "ROL_SIZE", 0 )
    elif( ror_cl_regex.match(line) ):
        return ( "ROR_SIZE", 0 )
    elif( xor_cl_regex.match(line) ):
        return ( "XOR_SIZE", 0 )
    elif( add_cl_regex.match(line) ):
        return ( "ADD_SIZE", 0 )
    elif( sub_cl_regex.match(line) ):
        return ( "SUB_SIZE", 0 )
    elif( inc_regex.match(line) ):
        return ( "INC", 0 )
    elif( dec_regex.match(line) ):
        return ( "DEC", 0 )
    elif( rol_const_regex.match(line) ):
        return ( "ROL_CONST", rol_const_regex.match(line).group(1) )
    elif( ror_const_regex.match(line) ):
        return ( "ROR_CONST", ror_const_regex.match(line).group(1) )
    elif( xor_const_regex.match(line) ):
        return ( "XOR_CONST", xor_const_regex.match(line).group(1) )
    elif( add_const_regex.match(line) ):
        return ( "ADD_CONST", xor_const_regex.match(line).group(1) )
    elif( sub_const_regex.match(line) ):
        return ( "SUB_CONST", xor_const_regex.match(line).group(1) )
    else:
        print( "Don't parse %s" % line )
        return ( "UNRECOGNISED", 0 )


# primitive helpers for deobfuscate_region()
def rotate_left( val, amt ):
    temp = val & 0xFF
    amt &= 7
    temp = ( ( temp << amt ) & 0xFF | ( temp >> ( 8 - amt ) ) & 0xFF )
    return temp


def rotate_right( val, amt ):
    temp = val & 0xFF
    amt &= 7
    temp = ( ( temp >> amt ) & 0xFF | ( temp << ( 8 - amt ) ) & 0xFF )
    return temp

def add_byte( input, operand ):
    temp = input + operand
    temp = temp & 0xFF
    return temp

def sub_byte( input, operand ):
    temp = input - operand
    temp = temp & 0xFF
    return temp

def xor_byte( input, operand ):
    temp = input ^ operand
    temp &= 0xFF
    return temp

def inc_byte( input ):
    temp = input + 1
    temp &= 0xFF
    return temp

def dec_byte( input ):
    temp = input - 1
    temp &= 0xFF
    return temp

def deobfuscate_region( addr, size, ops ):
    index = 0

    while( index < size ):
        temp = get_wide_byte(addr+index)
        for op in ops:
            if( op[0] == "INC" ):
                temp = inc_byte(temp)
            elif( op[0] == "DEC" ):
                temp = dec_byte(temp)
            elif( op[0] == "ROL_SIZE" ):
                temp = rotate_left( temp, ( ( size - index ) & 0xFF ) )
            elif( op[0] == "ROR_SIZE" ):
                temp = rotate_right( temp, ( ( size - index ) & 0xFF ) )
            elif( op[0] == "XOR_SIZE" ):
                temp = xor_byte( temp, ( ( size - index ) & 0xFF ) )
            elif( op[0] == "ADD_SIZE" ):
                temp = add_byte( temp, ( ( size - index ) & 0xFF ) )
            elif( op[0] == "SUB_SIZE" ):
                temp = sub_byte( temp, ( ( size - index ) & 0xFF ) )
            elif( op[0] == "ROL_CONST" ):
                temp = rotate_left( temp, int( op[1], 16 ) )
            elif( op[0] == "ROR_CONST" ):
                temp = rotate_right( temp, int( op[1], 16 ) )
            elif( op[0] == "XOR_CONST" ):
                temp = xor_byte( temp, int( op[1], 16 ) )
            elif( op[0] == "ADD_CONST" ):
                temp = add_byte( temp, int( op[1], 16 ) )
            elif( op[0] == "SUB_CONST" ):
                temp = sub_byte( temp, int( op[1], 16 ) )
            else:
                print( "Unrecognised op at addr %08X" % addr )
                return None
        patch_byte( addr+index, temp )

        index += 1
    return 1

# find the "mov eax, rva_of_obf_data"
def process_get_next_address(addr):
    if( get_wide_byte(addr) == 0xB8 and get_wide_byte(addr+5) == 0xC3 ):
        return get_wide_dword(addr+1)
    else:
        return 0

# find the "mov ecx, size_of_obf_data"
def process_get_next_size(addr):
    if( get_wide_byte(addr) == 0xB9 and get_wide_byte(addr+5) == 0xC3 ):
        return get_wide_dword(addr+1)
    else:
        return 0


# find the parameter block
# D8 00 00 00
# Address of get obf data rva in eax fn
# Address of add base on fn
# Address of get size in ecx
def find_parameters(begin,end):
    next_address = 0
    next_size    = 0
    while( end > begin ):
        if( get_wide_dword(end) == 0xD8 ):
            #print( "Got D8 at %08X" % end )
            next_address = process_get_next_address( base_address+get_wide_dword(end+4) )
            next_size    = process_get_next_size( base_address+get_wide_dword(end+12) )
            if( next_address > 0 and next_size > 0 ):
                return (next_address, next_size, end)
            else:
                return (0, 0, 0)
        else:
            end = end - 1
    return( 0, 0, 0 )

# Some way in, the obfuscator sneakily resorts to putting the values inline instead of in a parameter block,
# immediately before the deobfuscation loop.
# Thus you have something like this:
#.adata:005A0F02 B8 8E 3B 00 00                          mov     eax, 3B8Eh
#.adata:005A0F07 03 C5                                   add     eax, ebp
#.adata:005A0F09 B9 74 43 00 00                          mov     ecx, 4374h
#.adata:005A0F0E
#.adata:005A0F0E                         loc_5A0F0E:                             ; CODE XREF: .adata:005A0F15↓j
#.adata:005A0F0E 80 30 67                                xor     byte ptr [eax], 67h
#.adata:005A0F11 40                                      inc     eax
#.adata:005A0F12 49                                      dec     ecx
#.adata:005A0F13 85 C9                                   test    ecx, ecx
#.adata:005A0F15 75 F7                                   jnz     short loc_5A0F0E
def find_alternative_parameters(begin, end):

    while( end > begin ):
        if( get_wide_byte(end) == 0xB8 \
        and get_wide_word( end+3 ) == 0x0000 \
        and get_wide_word( end+5 ) == 0xC503 \
        and get_wide_byte( end+7 ) == 0xB9 \
        and get_wide_word( end+10 ) == 0x0000 ):

                rva = get_wide_dword( end+1 )
                size = get_wide_dword( end+8 )
                return( rva, size )
        else:
            end = end - 1

    return( 0, 0 )


# find a deobfuscation loop of the form...
#.adata:005A2576                         dl1:                                    ; CODE XREF: .adata:005A257E↓j
#.adata:005A2576 D2 08                                   ror     byte ptr [eax], cl
#.adata:005A2578 FE 00                                   inc     byte ptr [eax]
#.adata:005A257A 40                                      inc     eax
#.adata:005A257B 49                                      dec     ecx
#.adata:005A257C 85 C9                                   test    ecx, ecx
#.adata:005A257E 75 F6                                   jnz     short dl1

def find_deobf_loop(begin,end):
    while( end > begin ):
        if( get_wide_dword(end) == 0xC9854940 and get_wide_byte(end+4) == 0x75 and get_wide_byte(end+5) > 0x80 ):
            jump_back = get_wide_byte(end+5)
            jump_back = ( ( jump_back ^ 0xFF ) + 1 ) & 0xFF
            loop_start = ( end + 6 ) - jump_back
            return( loop_start, end+6 )
        else:
            end = end - 1
    return( 0, 0 )


# run through each line of disassembly, looking for deobfuscation operations
def get_deobf_ops(begin, end):
    q = begin
    ops = []
    op_count = 0
    # we have to delete any existing items (i.e. arrays) that IDA may have created
    # otherwise create_insn() will fail
    del_items( begin, DELIT_SIMPLE, ( end - begin ) )
    while( q < end ):
        len = create_insn(q)
        if( len == 0 ):
            print( "get_deobf_ops(%08X, %08X) - error creating instruction at %08X" % ( begin, end, q ) )
            return None

        line = generate_disasm_line( q, GENDSM_FORCE_CODE )
        m = match_obf_line( line ) # returns None if line isn't an obfuscation op
        if( m != None ):
            ops.append( m )
            op_count += 1
        q = q + len
    #print( "%u ops found" % op_count )
    return ops

# pretty-print operations to a string for output
def get_string_of_ops( ops ):
    result = ""
    for i in ops:
        result += "(%s, %s) " % (i[0], i[1])
    return result

# run the entire deobfuscation process
def run_process( initial_address, initial_size ):
    stage_count     = 1
    current_address = initial_address
    current_size    = initial_size

    # loop deobfuscating until there's an error or we're finished
    while( True ):
        # undefine anything in the region (otherwise IDA won't let us find parameters properly)
        del_items( current_address, DELIT_SIMPLE, current_size )


        # find obfuscation table parameters, whichever way they are obtained by the program
        ( obf_addr, obf_size, param_addr ) = find_parameters( current_address, current_address + current_size )
        if( obf_addr == 0 or obf_size == 0 or param_addr == 0 ):
            ( rva, size ) = find_alternative_parameters( current_address, ( current_address + current_size ) - 12 )
            if( rva == 0 and size == 0 ):
                print( "Error finding Stage %u parameters" % stage_count )
                break
            else:
                obf_addr = rva
                obf_size = size
                obf_end  = rva + base_address + size
                param_addr = 0
        else:
            obf_end = obf_addr + base_address + obf_size

        # find deobfuscation loop
        if( param_addr == 0 ):
            ( loop_start, loop_end ) = find_deobf_loop( obf_end, current_address + current_size )
        else:
            ( loop_start, loop_end ) = find_deobf_loop( obf_addr+base_address+obf_size, param_addr )
        if( loop_start == 0 or loop_end == 0 ):
            print( "Error finding Stage %u deobfuscation loop" % stage_count )
            break

        # retrieve the operations used in the loop
        ops = get_deobf_ops( loop_start, loop_end )
        if( ops == None ):
            print( "Error finding Stage %u deobfuscation operations" % stage_count )
            break

        # print some parameters
        print( "Stage %u Start: %08X End: %08X ObfStart: %08X ObfSize: %08X LoopStart: %08X LoopEnd: %08X Ops: [%s]" \
        % ( stage_count, current_address, current_address+current_size, obf_addr+base_address, obf_size, loop_start, loop_end, get_string_of_ops(ops) ) )

        #if( stage_count > 40 ):
        #    break
        #break
        # finally, perform the obfuscation
        if( stage_count > 40 ):
            if( deobfuscate_region( obf_addr+base_address, obf_size, ops ) == None ):
                print( "Error deobfuscating Stage %u" % stage_count )
                break

        # label the stage parts
        stage_name = "stage_%u" % stage_count
        loop_name  = "stage_%u_deobfuscation_loop" % stage_count
        block_name = "stage_%u_parameter_block" % stage_count
        set_name( current_address, stage_name, SN_NOCHECK | SN_NOWARN )
        set_name( loop_start, loop_name, SN_NOCHECK | SN_NOWARN )
        #set_name( param_addr, block_name, SN_NOCHECK | SN_NOWARN )

        # repeat for next region
        stage_count = stage_count + 1
        current_address = obf_addr + base_address
        current_size    = obf_size

# The 'main' - change values as appropriate
run_process( 0x59AB4E, 0x7960 )




