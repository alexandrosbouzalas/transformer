# -*- coding: utf-8 -*-

# Author: Alexandros Bouzalas
# Date: 18.07.2021
# github: 

import re
import sys
import binascii
import argparse
import base64
import time
from pathlib import Path

# Determine the version of python
pversion = re.match(r"([23]\.[0-9]\.[0-9]+)", sys.version, flags=0)


if pversion.group().split(".")[0] == "3":

    if __name__ == "__main__":
    
        parser = argparse.ArgumentParser(description="Easy to use format transformation tool. Example: python3 hextool.py E A B value")
        
        # Positional arguments 
        parser.add_argument("fromformat", 
            help="Original format: (A)ascii (B)inary (D)ecimal (H)exadecimal (B64)ase64", )
        parser.add_argument("toformat", 
            help="Desired format: (A)ascii (B)inary (D)ecimal (H)exadecimal (B64)ase64", )
        parser.add_argument("value", 
            help="String to perform the desired action on", type=str)

        parser.add_argument("-f", "--file", metavar="file", dest="file", help="Write results to a file: --file /path/to/file")
        args = parser.parse_args()

    
        # Argument validation 
        if args.fromformat not in ["A", "B", "D", "H"]:
            print("\nError: " + args.fromformat + " is not a valid argument:\n")
            parser.print_help()
            sys.exit(1)
        else:
            fromformat = args.fromformat
    
        if args.toformat not in ["A", "B", "D", "H"]:
            print("\nError: " + args.toformat + " is not a valid argument:\n")
            parser.print_help()
            sys.exit(1)
        else: 
            toformat = args.toformat
    
        string = args.value


                            # Ascii to _ functions
#-------------------------------------------------------------------------------#

        def ascii_to_binary(value, encoding="utf-8"):

            if len(value) > 0:

                try:

                    binary = []
                    value = re.findall(r".{1}", value)

                    for i in value:

                        i = i.encode(encoding)
                        i = bin(int(binascii.hexlify(i), 16))


                        if len(i) == 8:
                            binary.append('00' + i.split('b')[-1])

                        elif len(i) == 9:
                            binary.append('0' + i.split('b')[-1])
                        else:
                            binary.append(i.split('b')[-1])

                    
                    binary = "".join(binary)
        
                    binary = re.findall(r".{8}", binary)
                    binary = " ".join(binary)

                except:
                    print("\nError: Conversion error. Please check your input.\n")
                    sys.exit(1)


                return binary

            else:
                print("\nError: Value can't be empty.\n")
                sys.exit(1)



        def ascii_to_decimal(value, encoding="utf-8"):

            if len(value) > 0:

                try:

                    decimal = []
                    value = re.findall(r".{1}", value)

                    for i in value:

                        i = i.encode(encoding)
                        i = bin(int(binascii.hexlify(i), 16))

                        
                        if len(i) == 8:
                            decimal.append('00' + i.split('b')[-1])

                        elif len(i) == 9:
                            decimal.append('0' + i.split('b')[-1])
                        else:
                            decimal.append(i.split('b')[-1])

                    
                    decimal = "".join(decimal)
        
                    decimal = re.findall(r".{8}", decimal)
        
                    for i in decimal[:]:
                        decimal.remove(i)
        
                        decimal.append(str(int(i, 2)))
                
                
                    decimal = " ".join(decimal)

                except:
                    print("\nError: Conversion error. Please check your input.\n")
                    sys.exit(1)


                return decimal
            else:
                print("\nError: Value can't be empty.\n")
                sys.exit(1)



        def ascii_to_hex(value, encoding="utf-8"):

            if len(value) > 0:
                try:
                    value = value.encode(encoding)
                    hexadecimal = binascii.hexlify(value)
                    hexadecimal = hexadecimal.decode()
        
                    hexadecimal = re.findall(r".{2}", hexadecimal)
                    hexadecimal = " ".join(hexadecimal).upper()
                except:
                    print("\nError: Conversion error. Please check your input.\n")
                    sys.exit(1)
                return hexadecimal
            else:
                print("\nError: Value can't be empty.\n")
                sys.exit(1)



                            # Binary to _ functions
#-------------------------------------------------------------------------------#



        def binary_to_ascii(value, encoding="utf-8"):

            if len(value) > 0:

                if bool(re.search(r"([a-zA-Z2-9\?;@#$%\-=\\\"\'\(\_\)`\+!&\^*~\{\}\[\]<>:§±])+", value)) == True:
                    print("\nError: Invalid characters found. Binary digits only.\n")
                    sys.exit(1)

                if "".join(set(value)) == " ":
                    print("\nWarning: Standalone whitespace(s) is invalid.\n")
                    sys.exit(1)
                else:
                    value = value.replace(" ", "")
    
    
                if len(value) % 8 != 0:
                    print("\nError: Invalid length detected (Whitespaces are not counted).\n") 
                    sys.exit(1)
        
                else:
                    try:
                        if value == "00100000":
                            ascii_ = "Whitespace"
                        elif value == "00010100":
                            ascii_ = "Newline"
                        else:
                            value = int(value, 2)
                            ascii_ = binascii.unhexlify("%x" % value)
                            ascii_ = ascii_.decode(encoding)
                    except:
                        print("\nError: Error: Binary values smaller that 00010100 (20), can't be converted to ascii.\n")
                        sys.exit(1)

                return ascii_
            else:
                print("\nError: Value can't be empty.\n")
                sys.exit(1)


        def binary_to_decimal(value):

            if len(value) > 0:

                if bool(re.search(r"([a-zA-Z2-9\?;@#$%\-=\\\"\'\(\_\)`\+!&\^*~\{\}\[\]<>:§±])+", value)) == True:
                    print("\nError: Invalid characters found. Binary digits only.\n")
                    sys.exit(1)
    
                if "".join(set(value)) == " ":
                    print("\nWarning: Standalone whitespace(s) is invalid.\n")
                    sys.exit(1)
                else:
                    value = value.replace(" ", "")
    
                if len(value) % 8 != 0:
                    print("\nError: Invalid length detected (Whitespaces are not counted).\n") 
                    sys.exit()
                
                try:
                    decimal = re.findall(r".{8}", value)
        
                    for i in decimal[:]:
                        decimal.remove(i)
        
                        decimal.append(str(int(i, 2)))
                
                
                    decimal = " ".join(decimal)
                except:
                    print("\nError: Conversion error. Please check your input.\n")
                    sys.exit(1)
                return decimal

            else:
                print("\nError: Value can't be empty.\n")
                sys.exit(1)


        def binary_to_hex(value):

            if len(value) > 0:

                if bool(re.search(r"([a-zA-Z2-9\?;@#$%\-=\\\"\'\(\_\)`\+!&\^*~\{\}\[\]<>:§±])+", value)) == True:
                    print("\nError: Invalid characters found. Binary digits only.\n")
                    sys.exit(1)
    
                if "".join(set(value)) == " ":
                    print("\nWarning: Standalone whitespace(s) is invalid.\n")
                    sys.exit(1)
                else:
                    value = value.replace(" ", "")
    
                if len(value) % 8 != 0:
                    print("\nError: Invalid length detected (Whitespaces are not counted).\n") 
                    sys.exit()
    
                try:
                    hexadecimal = "%0*X" % ((len(value) + 3) // 4, int(value, 2))
        
                    hexadecimal = re.findall(r".{2}", hexadecimal)
                    hexadecimal = " ".join(hexadecimal)
                except:
                    print("\nError: Conversion error. Please check your input.\n")
                    sys.exit(1)
                return hexadecimal

            else:
                print("\nError: Value can't be empty.\n")
                sys.exit(1)



                            # Decimal to _ functions
#-------------------------------------------------------------------------------#




        def decimal_to_ascii(value):

            if len(value) > 0:


                if bool(re.search(r"([a-zA-Z\?;@#$%\-=\\\"\'\(\_\)`\+!&\^*~\{\}\[\]<>:§±])+", value)) == True:
                    print("\nError: Invalid characters found. Digits only.\n")
                    sys.exit(1)

                if "".join(set(value)) == " ":
                    print("\nWarning: Standalone whitespace(s) is invalid.\n")
                    sys.exit(1)

                if len(value) < 2:
                    print("\nWarning: Invalid length.\n")
                    sys.exit(1)

                
                if len(value) > 3:
    
                    if bool(re.search(r"\ +", value)) == False or value.count(" ") < int(len(value) / 4):
                        print("\nError: No or too little whitespaces found.")
                        print("\nPlease use whitespsce between the decimal bytes. Example: encode.py D A '104 101 108 108 111'\n")
                        sys.exit(1)
                
    
                value = value.split(" ")
    
                ascii_ = []
    
                for i in value:
    
                    # Display error message if the is more than a single whitespace between bytes
                    try:
                        # Regex above filter negative numbers
                        if int(i) > 255:
                            print("\nError: Decimal values can't be smaller than 0 or bigger than 255.\n")
                            sys.exit(1)
                    except:
                        print("\nError: Conversion error. Check for double whitespaces.\n")
                        sys.exit(1)      
    
                    try:
                        if ''.join(set(i)) == '0':
                            ascii_ = 'Null'
                        else:
                            ascii_.append(chr(int(i)))

                    except:
                        print("\nError: Conversion error. Please check your input.\n")
                        sys.exit(1)
            
                if ascii_ != 'Null':
                    ascii_ = "".join(ascii_)
    
    
                return ascii_

            else:
                print("\nError: Value can't be empty.\n")
                sys.exit(1)


        def decimal_to_binary(value):

            if len(value) > 0:

                if bool(re.search(r"([a-zA-Z\?;@#$%\-=\\\"\'\(\_\)`\+!&\^*~\{\}\[\]<>:§±])+", value)) == True:
                    print("\nError: Invalid characters found. Digits and letter only.\n")
                    sys.exit(1)

                if "".join(set(value)) == " ":
                    print("\nWarning: Standalone whitespace(s) is invalid.\n")
                    sys.exit(1)

                if len(value) < 2:
                    print("\nWarning: Invalid length. Use a 0 prefix with single digits.\n")
                    sys.exit(1)

                if len(value) > 3:
    
                    if bool(re.search(r"\ +", value)) == False or value.count(" ") < int(len(value) / 4):
                        print("\nError: No or too little whitespaces found.")
                        print("\nPlease use whitespce between the decimal bytes. Example: encode.py D A '104 101 108 108 111'\n")
                        sys.exit(1)
                
    
                value = value.split(" ")
    
                binary = []

                for i in value: 
                    if str(i) == " ":
                        value.remove(i)
    
                for i in value:
                    
                    # Regex above filters negative numbers

                    try:
                        if int(i) > 255:
                            sys.exit(1)

                        if len(bin(int(i))) == 3:
                            binary.append('0000000' + (bin(int(i))).split('b')[-1])
                        elif len(bin(int(i))) == 4:
                            binary.append('000000' + (bin(int(i))).split('b')[-1])    
                        elif len(bin(int(i))) == 5:
                            binary.append('00000' + (bin(int(i))).split('b')[-1])
                        elif len(bin(int(i))) == 6:
                            binary.append('0000' + (bin(int(i))).split('b')[-1])
                        elif len(bin(int(i))) == 7:
                            binary.append('000' + (bin(int(i))).split('b')[-1])
                        elif len(bin(int(i))) == 8:
                            binary.append('00' + (bin(int(i))).split('b')[-1])
                        elif len(bin(int(i))) == 9:
                            binary.append('0' + (bin(int(i))).split('b')[-1])   
                        else:
                            binary.append((bin(int(i))).split('b')[-1])

                    except:
                        print("\nError: Decimal values can't be smaller than 0 or bigger than 255.\n")
                        sys.exit(1)
                
                binary = " ".join(binary)

                return binary
            else:
                print("\nError: Value can't be empty.\n")
                sys.exit(1)



        def decimal_to_hex(value):

            if len(value) > 0:

                if bool(re.search(r"([a-zA-Z\?;@#$%\-=\\\"\'\(\_\)`\+!&\^*~\{\}\[\]<>:§±])+", value)) == True:
                    print("\nError: Invalid characters found. Digits and letter only.\n")
                    sys.exit(1)

                if "".join(set(value)) == " ":
                    print("\nWarning: Standalone whitespace(s) is invalid.\n")
                    sys.exit(1)

                if len(value) < 2:
                    print("\nWarning: Invalid length. Use a 0 prefix with single digits.\n")
                    sys.exit(1)

                if len(value) > 3:
    
                    if bool(re.search(r"\ +", value)) == False or value.count(" ") < int(len(value) / 4):
                        print("\nError: No or too little whitespaces found.")
                        print("\nPlease use whitespaces between the decimal bytes. Example: encode.py D A '104 101 108 108 111'\n")
                        sys.exit(1)
                
    
                value = value.split(" ")
                
                hexadecimal = []

                try:

                    for i in value: 
                        if str(i) == " ":
                            value.remove(i)
        
                    for i in value:
        
                        # Display error message if the is more than a single whitespace between bytes
                        try:
                            # Regex above filters negative numbers
                            if int(i) > 255:
                                sys.exit(1)
                        except:
                            print("\nError: Decimal values can't be smaller than 0 or bigger than 255.\n")
                            sys.exit(1)
        
                        try:
    
                            hexadecimal.append((hex(int(i)).split('x')[-1]).upper())
    
                        except:
                            print("\nError: Conversion error. Please check your input.\n")
                            sys.exit(1)
    
                    for i in hexadecimal:
                        if len(str(i)) == 1:
                           hexadecimal[hexadecimal.index(str(i))] = '0' + i
                    
                    hexadecimal = " ".join(hexadecimal)
                except:
                    print("\nError: Conversion error.\n")
                    sys.exit(1)

                return hexadecimal

            else:
                print("\nError: Value can't be empty.\n")
                sys.exit(1)



                            # Hexadecimal to _ functions
#-------------------------------------------------------------------------------#



        def hex_to_ascii(value):
            if len(value) > 0:

                if bool(re.search(r"([g-wy-zG-WY-Z\?;@#$%\-=\\\"\'\(\_\)`\+!&\^*~\{\}\[\]<>:§±])+", value)) == True:
                    print("\nError: Invalid characters found. Digits 0-9 and letters A-F only.\n")
                    sys.exit(1)
    
                if bool(re.search(r"^0x", value)):
                    value = value.replace("0x", "")

                if "".join(set(value)) == " ":
                    print("\nWarning: Standalone whitespace(s) is invalid.\n")
                    sys.exit(1)
                else:
                    value = value.replace(" ", "")
    
    
                if len(value) % 2 != 0:
                    print("\nError: Invalid amount of characters.")
                    sys.exit(1)
    
                value = re.findall(r".{2}", value)
                ascii_ = []
    
                if "".join(value) == "0A":
                    ascii_.append("Newline") 
                elif "".join(value) == "20":
                    ascii_.append("Whitespace")  
                else:

                    for i in value: 
                        if bool(re.search(r"[01][0-9]", i)) == True:
                            print("\nError: The hex value " + i + " can't be converted to ascii. Printable characters must be bigger than 19.\n")
                            sys.exit(1)
                        else:
                            try:
                                ascii_.append(chr(int(i, 16)))
                            except:
                                print("\nError: Conversion error. Please check your input.\n")
                                sys.exit(1)

                ascii_ = "".join(ascii_)
    
                return ascii_
            else:
                print("\nError: Value can't be empty.\n")
                sys.exit(1)



        def hex_to_binary(value):

            if len(value) > 0:

                print (value)
                if bool(re.search(r"([g-wy-zG-WY-Z\?;@#$%\-=\\\"\'\(\_\)`\+!&\^*~\{\}\[\]<>:§±])+", value)) == True:
                    print("\nError: Invalid characters found. Digits 0-9 and letters A-F only.\n")
                    sys.exit(1)   
    
                if bool(re.search(r"^0x", value)):
                    value = value.replace("0x", "")
    
                if "".join(set(value)) == " ":
                    print("Warning: Standalone whitespace(s) is invalid.\n")
                    sys.exit(1)
                else:
                    value = value.replace(" ", "")   
    
    
                if len(value) % 2 != 0:
                    print("\nError: Invalid amount of characters. Use a 0 prefix for single digits")
                    sys.exit(1)
    
                value = re.findall(r".{2}", value)
            
                binary = []
    
                try:
                    for i in value:
                        binary.append(bin(int(i, 16)))
                except:
                    print("\nError: Conversion error. Please check your input.\n")
                    sys.exit(1)
    
                tempvalue = []
    
                for i in binary:
                    
                    try:

                        if len(i) == 3:
                            tempvalue.append('0000000' + (bin(int(i, 2)).split('b')[-1]))
                        elif len(i) == 4:
                            tempvalue.append('000000' + (bin(int(i, 2)).split('b')[-1]))
                        elif len(i) == 5:
                            tempvalue.append('00000' + (bin(int(i, 2)).split('b')[-1]))
                        elif len(i) == 6:
                            tempvalue.append('0000' + (bin(int(i, 2)).split('b')[-1]))   
                        elif len(i) == 7:
                            tempvalue.append('000' + (bin(int(i, 2)).split('b')[-1]))
                        elif len(i) == 8:
                            tempvalue.append('00' + (bin(int(i, 2)).split('b')[-1]))
                        elif len(i) == 9:
                            tempvalue.append('0' + (bin(int(i, 2)).split('b')[-1]))
                        else:
                            tempvalue.append((bin(int(i, 2)).split('b')[-1]))

                    except:
                        print("\nError: Conversion error. Please check your input.\n")
                        sys.exit(1)
    
                binary = ' '.join(tempvalue)
    
                return binary

            else:
                print("\nError: Value can't be empty.\n")
                sys.exit(1)



        def hex_to_decimal(value):

            if len(value) > 0:

                if bool(re.search(r"([g-wy-zG-WY-Z\?;@#$%\-\\\(\_\)`\+!&\^*~\{\}\[\]<>:§±])+", value)) == True:
                    print("\nError: Invalid characters found. Digits 0-9 and letters A-F only.\n")
                    sys.exit(1)

    
                if bool(re.search(r"^0x", value)):
                    value = value.replace("0x", "")
    
                if "".join(set(value)) == " ":
                    print("Warning: Standalone whitespace(s) is invalid.\n")
                    sys.exit(1)
                else:
                    value = value.replace(" ", "")
    
                if len(value) % 2 != 0:
                    print("\nError: Invalid amount of characters. Use a 0 prefix for single digits.")
                    sys.exit(1)
    
                value = re.findall(r".{2}", value)
            
                decimal = []
    
                try:
                    for i in value:

                        if len(str(int(i, 16))) == 1:
                            decimal.append('00' + str(int(i, 16)))
                        else:
                            decimal.append(str(int(i, 16)))
                except:
                    print("\nError: Conversion error. Please check your input.\n")
                    sys.exit(1)
    
                decimal = " ".join(decimal)
    
    
                return decimal

            else:
                print("\nError: Value can't be empty.\n")
                sys.exit(1)

                            # Write to file function
#-------------------------------------------------------------------------------#


        def write_to_file(value, string):

            file = args.file

            if args.file != None:
                
                file = Path(file)

                if file.is_file():
                    
                    try:
                        with open(file, mode='a', encoding='utf-8') as filename:
                            current_time = time.strftime(r"%d.%m.%Y %H:%M:%S", time.localtime())

                            filename.write("Results from " + str(current_time) + "\n")
                            filename.write("\n" + "# Original:" + "\n")
                            filename.write("\n" + string + "\n")
                            filename.write("\n" + "# Transformed:" + "\n")
                            filename.write("\n" + value + "\n\n\n")

                    except:
                        print("\nError: There was an error opening the file.")
                    finally:
                        filename.close()                  

                else:

                    print("\nWarning: The file does not exist.\n")

                    filematch = re.search(r"[a-zA-Z0-9\_\.\ ]+\.[a-z]+$", str(file))

                    create = input("Do you want to create the file (y/n): ")

                    while create != "y" and create != "n":
                        print("\nError: " + create + " is not a valid option. Try again.\n")
                        create = input("Do you want to create the file " + filematch.group() + " (y/n): ")

                    if create == "y":
                        try:
                            with open(file, mode='a', encoding='utf-8') as filename:
                                current_time = time.strftime(r"%d.%m.%Y %H:%M:%S", time.localtime())

                                filename.write("Results from " + str(current_time) + "\n")
                                filename.write(("\n" + "# Original:" + "\n"))
                                filename.write("\n" + string + "\n")
                                filename.write(("\n" + "# Transformed:" + "\n"))
                                filename.write("\n" + value + "\n\n\n")
                        except:
                            print("\nError: There was an error opening the file. Check your path or the directory permissions.")
                        finally:
                            filename.close()





                        # Function calls
#-------------------------------------------------------------------------------#


        if fromformat == "A":

            if toformat == "B":
                encodedstring = ascii_to_binary(string)
                write_to_file(encodedstring, string)

            if toformat == "D":
                encodedstring = ascii_to_decimal(string)
                write_to_file(encodedstring, string)

            if toformat == "H":
                encodedstring = ascii_to_hex(string)
                write_to_file(encodedstring, string)

            if toformat == "A":
                print("\nAscii to ascii not possible.\n")
                sys.exit(1)

        if fromformat == "B":

            if toformat == "A":
                encodedstring = binary_to_ascii(string)
                write_to_file(encodedstring, string)

            if toformat == "D":
                encodedstring = binary_to_decimal(string)
                write_to_file(encodedstring, string)

            if toformat == "H":
                encodedstring = binary_to_hex(string)
                write_to_file(encodedstring, string)

            if toformat == "B":
                print("\nBinary to binary not possible.\n")
                sys.exit(1)


        if fromformat == "D":

            if toformat == "A":
                encodedstring = decimal_to_ascii(string)
                write_to_file(encodedstring, string)

            if toformat == "B":
                encodedstring = decimal_to_binary(string)
                write_to_file(encodedstring, string)

            if toformat == "H":
                encodedstring = decimal_to_hex(string)
                write_to_file(encodedstring, string)

            if toformat == "D":
                print("\nDecimal to decimal not possible.\n")
                sys.exit(1)

        if fromformat == "H":

            if toformat == "A":
                encodedstring = hex_to_ascii(string)
                write_to_file(encodedstring, string)

            if toformat == "B":
                encodedstring = hex_to_binary(string)
                write_to_file(encodedstring, string)

            if toformat == "D":
                encodedstring = hex_to_decimal(string)
                write_to_file(encodedstring, string)

            if toformat == "H":
                print("\nHex to hex not possible.\n")
                sys.exit(1)

        print("\nHere you go: " + encodedstring + "\n")
else:
    print("\nYou are using Python " + pversion.group() + ". Please use Python3 for proper functionality.\n")
