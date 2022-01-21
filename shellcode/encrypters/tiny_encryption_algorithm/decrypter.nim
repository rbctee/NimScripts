import streams
import bitops
import parseopt
import os

#
#    The function 'encode' was written to encode 4 bytes of data into a uint32
#        integer, as is needed by the function 'encrypt'
#
proc encode(shellcode_buffer: array[4, byte]): uint32 =

    var
        r: uint32
        rotation_offset: int
        byte_value: uint32

    #
    #    I think it's better to explain this function with an example.
    #    Let's suppose we have 4 bytes: [0x10, 0x20, 0x30, 0x40]
    #    This function places these bytes inside a 32-bit variable, like this:
    #        - 0x40302010
    #
    #    As you can see, the first value is the Least Significant Byte, while
    #        the last one is the most significant value.
    #
    #    To perform this operations, I'm using the function 'rotateLeftBits' to
    #        rotate the bits by 8/16/24 positions to the left.
    #
    #    In the case of the previous 4 bytes, it would end up like this:
    #        1. 0x00000010
    #        2. 0x00002000
    #        3. 0x00300000
    #        4. 0x40000000
    #
    #    Summing these numbers together, we obtain 0x40302010 (or 1076895760)
    #
    for i in countup(0, 3):

        byte_value = shellcode_buffer[i]

        #
        #    Index:
        #        0 -> rotation_offset = 0
        #        1 -> rotation_offset = 8 (shift by 8 bits to the left)
        #        2 -> rotation_offset = 16 (shift by 16 bits to the left)
        #        3 -> rotation_offset = 24 (shift by 24 bits to the left)
        #
        rotation_offset = 8 * i

        var rotatedByte = rotateLeftBits(cast[uint32](byte_value), rotation_offset)
        r += rotatedByte

    return r

#
#    The function 'encode_key' is very similar to the previous one, but returns
#        an array of 4 uint32 integers, hence 128 bits.
#
proc encode_key(key: string): array[4, uint32] =

    var
        # Convert the encryption key to a sequence of bytes
        key_bytes: seq[byte] = cast[seq[byte]](key)
        
        #
        #    'k' is the array containing the 4 uint32 integers returned by the
        #        function
        #
        k: array[4, uint32]
        key_index: int
        rotation_offset: int

    for byte_index, byte_value in key_bytes:
        
        #
        #    I'm using 'key_index' to determine which group of 4 bytes I need to
        #        convert into a uint32 integer.
        #
        #    Based on the index:
        #        - 0-3   -> calculate k[0]
        #        - 4-7   -> calculate k[1]
        #        - 8-11  -> calculate k[2]
        #        - 12-15 -> calculate k[3]
        #
        key_index = byte_index div 4
        rotation_offset = (byte_index mod 4) * 8
        k[key_index] += rotateLeftBits(cast[uint32](byte_value), rotation_offset)

    return k

#
#   References for the Decryption function:
#       - https://it.wikipedia.org/wiki/Tiny_Encryption_Algorithm
#       - https://link.springer.com/content/pdf/10.1007/3-540-60590-8_29.pdf
#
#   As per the reference, the function accepts the following arguments:
#       - 'v': an array made up of 2 uint32 integers
#           it contains 8 bytes of encrypted data to decrypt
#       - 'k': an array made up of 4 uint32 integers, hence a 128-bits key
#           it's the decryption key
#
#   As for how to encode data and key to uint32 integers, it's up to you
#   In fact, in the original whitepaper I didn't find anything about
#       this matter
#
proc decrypt(v: array[2, uint32], k: array[4, uint32]): array[2, uint32] =

    let
        #
        #    According to the whitepaper:
        #
        #    > A different multiple of delta is used in each round so that no
        #    > bit of the multiple will not change frequently. We suspect the
        #    > algorithm is not very sensitive to the value of delta and we
        #    > merely need to avoid a bad value.
        #    > It will be noted that delta turns out to be odd with truncation
        #    >  or nearest rounding, so no extra precautions are needed to
        #    > ensure that all the digits of sum change.
        #
        delta: uint32 = cast[uint32](0x9e3779b9)

        k0: uint32 = k[0]
        k1: uint32 = k[1]
        k2: uint32 = k[2]
        k3: uint32 = k[3]

    var
        v0: uint32 = v[0]
        v1: uint32 = v[1]
        sum: uint32 = cast[uint32](0xc6ef3720)

    for i in countup(0, 31):

        v1 -= ((v0 shl 4) + k2) xor (v0 + sum) xor ((v0 shr 5) + k3)
        v0 -= ((v1 shl 4) + k0) xor (v1 + sum) xor ((v1 shr 5) + k1)
        sum -= delta

    return [v0, v1]

#
#    The function 'decode' decodes a uint32 integer, converting it into 4 bytes.
#    For example:
#    ```nim
#    var x: uint32 = 0x40302010
#    echo decode(x)
#    ```
#
#    The code above would return this:
#        [16, 32, 48, 64]
#
#    Converting them into hex:
#        [0x10, 0x20, 0x30, 0x40]
#
proc decode(encrypted_chunk: uint32): array[4, byte] =

    var decrypted_bytes: array[4, byte] = cast[array[4, byte]](encrypted_chunk)
    return decrypted_bytes


#
#    The function 'decrypt_shellcode' retrieves 8 bytes from the sequence of
#        encrypted bytes, thus decrypting each pair of 4 bytes.
#    
#    Look at the for loop for more information.
#
proc decrypt_shellcode(encrypted_shellcode: seq[byte], key: string): seq[byte] =

    let
        # number of 4-bytes chunks stored inside encrypted_shellcode
        num_chunks: int = (len(encrypted_shellcode) div 4)

        # array of 4 uint32 integers representing the encryption key
        encoded_key: array[4, uint32] = encode_key(key)

    var
        decrypted_shellcode: seq[byte]
        chunk_pair: array[2, uint32]
        encrypted_chunks_bytes: array[4, byte]

    #
    #    Operations perfomed by the for loop:
    #        1. take a pair of 4 bytes from the input sequence
    #        2. convert them into a pair of uint32 integers
    #        3. pass them to the decryption function
    #        4. convert the pair of decrypted uint32 integer into bytes
    #        5. append the decrypted bytes to the return sequence
    #
    for i in countup(0, num_chunks - 1):

        #
        #    For each 4 bytes of the encrypted shellcode, we have to encode them
        #        into an uint32 function, as the function 'decrypt' is based on
        #        this data type
        #
        for j in countup(0, 3):
            encrypted_chunks_bytes[j] = encrypted_shellcode[i * 4 + j]

        chunk_pair[i mod 2] = encode(encrypted_chunks_bytes)

        #
        #    If the index is odd, then it means there are two values inside the
        #        array 'chunk_pair'.
        #    At this point, we can pass the array to the decrypt function in
        #        order to decrypt the values.
        #
        if i mod 2 == 1:
            var decrypted_chunks: array[2, uint32] = decrypt(chunk_pair, encoded_key)

            #
            #    For each uint32 returned by the 'decrypt' function, we need to
            #        convert them into bytes and append them to
            #        the sequence 'decrypted_shellcode'
            #
            for decrypted_chunk in decrypted_chunks:

                
                var decrypted_chunk_bytes: array[4, byte] = decode(decrypted_chunk)
                # echo "[+] Decrypted chunk: ", decrypted_chunk
                # echo "[+] Decrypted bytes: ", decrypted_chunk_bytes

                #
                #    Append 4 decrypted bytes at a time to the sequence
                #
                decrypted_shellcode.add(decrypted_chunk_bytes)

    # Remove padding from the shellcode
    while decrypted_shellcode[^1] == 0:
        discard decrypted_shellcode.pop()

    # Return the sequence of decrypted bytes
    return decrypted_shellcode

#
#    Show usage of the program
#
proc writeHelp() =
    echo "[+] Usage:\n\t", paramStr(0), " --input=encrypted.bin --key='0123456789abcdef' [--output=decrypted.bin] [--execute]"

proc main(): void =

    var input_file: string = ""
    var output_file: string = ""
    var enc_key: string = ""
    var execute_shellcode: bool = false

    for kind, key, value in getOpt():
        case kind
        of cmdArgument:
            discard

        of cmdLongOption, cmdShortOption:
            case key
            of "input", "i":
                input_file = value

            of "output", "o":
                output_file = value

            of "key", "k":
                enc_key = value

            of "e", "execute":
                execute_shellcode = true

            else:
                echo key
                echo value
 
        of cmdEnd:
            discard

    if input_file == "" or enc_key == "":
        writeHelp()
        system.quit(1)

    echo "[+] Input shellcode: ", input_file
    echo "[+] Using encryption key: ", enc_key
    if output_file != "":
        echo "[+] Output file: ", output_file

    #
    #    After reading the input file containing the shellcode,
    #        e.g. shellcode.bin or a command-line argument, we have to copy each
    #        byte into a data structure, in this case a sequence, i.e. a dynamic
    #        array of a specific data type
    #
    var fs = newFileStream(input_file, fmRead)
    var encrypted_shellcode: seq[byte]

    while not fs.atEnd:
        let b: byte = cast[byte](fs.readChar())
        encrypted_shellcode.add(b)

    # Decrypt the shellcode based on the input secret key
    var decrypted_shellcode_bytes = decrypt_shellcode(encrypted_shellcode, enc_key)
    echo "[+] Decrypted bytes: ", decrypted_shellcode_bytes

    # Write the decrypted shellcode to the output file, if set
    if output_file != "":
        echo "[+] Writing decrypted shellcode to file: ", output_file
        writeFile(output_file, decrypted_shellcode_bytes) 

    if execute_shellcode:
        var shellcode_empty_array: array[1024, byte]
        for index, byte_value in decrypted_shellcode_bytes:
            shellcode_empty_array[index] = byte_value
        
        let shellcode_pointer = cast[ByteAddress](shellcode_empty_array.addr)    
        
        # create function based on shellcode
        var run_shellcode : (proc() {.cdecl, gcsafe.}) = cast[(proc() {.cdecl, gcsafe.})](shellcode_pointer)

        # in my case the function echo is based on fwrite, so you set a breakpoint on:
        #   gef> b *fwrite
        echo "[+] Running shellcode"
        run_shellcode()


#
#    Run the main function only if the program is run by itself, not imported
#    It's like the following code from Python:
#    ```py
#    if __name__ == "__main__":
#        main()
#    ```
#
if isMainModule:
    main()
