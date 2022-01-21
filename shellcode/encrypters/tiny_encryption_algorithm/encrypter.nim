import streams
import bitops
import parseopt
import os

#
#    References for the Encryption function:
#        - https://it.wikipedia.org/wiki/Tiny_Encryption_Algorithm
#        - https://link.springer.com/content/pdf/10.1007/3-540-60590-8_29.pdf
#
#    As per the reference, the function accepts the following arguments:
#        - 'v': an array made up of 2 unsigned 32-bit integers (hence uint32)
#            it contains 8 bytes of data to encrypt
#        - 'k': an array made up of 4 uint32 integers, hence a 128-bits key
#            it's the encryption key
#
#    As for how to encode data and key to uint32 integers, it's up to you
#    In fact, in the original whitepaper I didn't find anything about
#        this matter
#
proc encrypt(v: array[2, uint32], k: array[4, uint32]): array[2, uint32] =

    #
    #    Variables used by the encryption function.
    #    Follows the difference between the 'let' and 'var' statements:
    #        - 'let': After the initialization their value cannot change
    #        - 'var': After the initialization their value CAN be changed
    #
    #    Moreover, by default the value of an integer is 0, so it doesn't need
    #    to be inizialed to 0
    #
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
        sum: uint32


    #
    #    The algorithm uses 32 cycles (64 rounds) to encrypt data 
    #
    for i in countup(0, 31):

        sum += delta
        v0 += ((v1 shl 4) + k0) xor (v1 + sum) xor ((v1 shr 5) + k1)
        v1 += ((v0 shl 4) + k2) xor (v0 + sum) xor ((v0 shr 5) + k3)

    #
    #    Data is returned as an array of 2 uint32 integers, which represent 8
    #        bytes of encrypted data
    #
    return [v0, v1]

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
#    Given a key (a string of 16 characters, so 128 bits) and a sequence of
#        of bytes, it tries to encrypt them using the Tiny Encryption Algorithm
#
proc encrypt_shellcode(shellcode: seq[byte], key: string): seq[uint32] =

    var v: array[2, uint32]
    var k: array[4, uint32] = encode_key(key)

    # I use a copy of the shellcode in order not to modify the original one,
    #   later used for the Assert statement
    var local_shellcode: seq[byte] = shellcode

    echo "[+] Key: ", key
    echo "[+] Encoded key: ", k
    echo "[+] Shellcode without padding: ", local_shellcode
    echo "\tLength: ", local_shellcode.len

    #
    #    Given TEA is a block cipher (e.g. AES CBC mode), it needs use padding
    #        in the case of an input sequence of bytes not divisible by 8
    #

    let shellcode_padding = 8 - (local_shellcode.len mod 8)
    for x in countup(0, shellcode_padding - 1):
  
        #
        #    In this case I'm adding NULL bytes at the end of the original
        #        shellcode, before encrypting it
        #
        local_shellcode.add(0x0)

    echo "[+] Shellcode with padding: ", local_shellcode
    echo "\tLength: ", local_shellcode.len

    var byte_index: int
    var encrypted_shellcode: seq[uint32]

    #
    #    For each 8 bytes of shellcode, the loop does the following:
    #        1. take the first 4 bytes and convert them to an uint32 integer
    #        2. take the next 4 bytes and convert them to an uint32 integer
    #        3. encrypt the 8 bytes of shellcode using the 'encrypt' function
    #        4. append the encrypted bytes to 'encrypted_shellcode' (array of
    #            encrypted bytes)
    #
    for x in local_shellcode:

        var b = local_shellcode[byte_index..(byte_index + 3)]
        var byte_array: array[4, byte]
        for i in countup(0, 3):
            byte_array[i] = b[i]

        # echo "[+] Bytes: ", b
        # echo "[+] Array of bytes: ", byte_array
        v[0] = encode(byte_array)

        b = local_shellcode[(byte_index+4)..(byte_index + 7)]
        for i in countup(0, 3):
            byte_array[i] = b[i]

        v[1] = encode(byte_array)

        v = encrypt(v, k)

        # echo "[+] Encrypted v0: ", v[0]
        # echo "[+] Encrypted v1: ", v[1]

        encrypted_shellcode.add(v[0])
        encrypted_shellcode.add(v[1])

        #
        #    A word about for loops in Nim: the index is read-only, so you can't
        #        perform operations on it.
        #    To get the index:
        #    
        #    ```nim
        #    for index, value in local_shellcode:
        #        ...
        #    ```
        #
        #    It seems every array or sequence has a built-in index, although
        #        read-only, so you cannot do 'index += 8'
        #
        #    Because of this I'm using an external variable: 'byte_index'
        #
        byte_index += 8
        
        # If the next index is out of bonds, then break out of the for loop
        if byte_index >= local_shellcode.len:
            break

    return encrypted_shellcode


#
#    Show usage of the program
#
proc writeHelp() =
    echo "[+] Usage:\n\t", paramStr(0), " --input=shellcode.bin --output=encrypted.bin --key='0123456789abcdef'"
    echo "[+] The encryption key's size must be 16 characters

proc main(): void =


    var input_file: string = ""
    var output_file: string = ""
    var enc_key: string = ""

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

            else:
                echo key
                echo value
 
        of cmdEnd:
            discard

    if input_file == "" or output_file == "" or enc_key == "":
        writeHelp()
        system.quit(1)

    echo "[+] Input shellcode: ", input_file
    echo "[+] Output file: ", output_file
    echo "[+] Using encryption key: ", enc_key
    #
    #    After reading the input file containing the shellcode,
    #        e.g. shellcode.bin or a command-line argument, we have to copy each
    #        byte into a data structure, in this case a sequence, i.e. a dynamic
    #        array of a specific data type
    #
    var fs = newFileStream(input_file, fmRead)

    var shellcode: seq[byte]
    while not fs.atEnd:
        let b: byte = cast[byte](fs.readChar())
        shellcode.add(b)


    #
    #    Once we filled the dynamic array with the bytes of our shellcode, it's
    #        time to encrypt these bytes
    #
    var encrypted_shellcode: seq[uint32] = encrypt_shellcode(shellcode, enc_key)

    # echo "[+] Encrypted shellcode chunks: ", encrypted_shellcode
    # echo "[+] Number of 4-bytes chunks: ", len(encrypted_shellcode)

    #
    #    Now that the shellcode is encrypted with TEA and our encryption key, we
    #        got to convert the data structure returned by the decryption
    #        function a dynamic array of bytes, so we can save them to file
    #
    var encrypted_shellcode_bytes: seq[byte]
    for encrypted_chunk in encrypted_shellcode:

        #
        #    In this case, the decode function takes one uint32 integer and
        #        converts it into 4 bytes, which are added to the dynamic array
        #        (encrypted_shellcode_bytes)
        #
        var encrypted_chunk_bytes: array[4, byte] = decode(encrypted_chunk)

        for b in encrypted_chunk_bytes:
            encrypted_shellcode_bytes.add(b)

    echo "[+] Saving encrypted shellcode to file: ", output_file
    writeFile(output_file, encrypted_shellcode_bytes)


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
