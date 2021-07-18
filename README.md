# transformer

Transform between formats like Ascii, Hexadecimal, Decimal, Binary and Base64 with ease over the command line; no online tool required.

Cheatsheet:

A = Ascii
B = Binary 
D = Decimal
H = Hexadecimal
B64 = Base64
-f/--file = Inlude a file to write the results to


Usage:

python3 transformer.py fromformat toformat value


Examples:

python3 transformer.py A B 'hello'

python3 transformer.py D A '110 233 80'	

python3 transformer.py H B '68 65 6C 6C 6F'

python3 transformer.py B H '01101000 01100101 01101100 01101100 01101111' --file /path/to/file


