# Zulfur - V1.1
Zulfur is a powerful obfuscator that makes code heavier and less readable
# How it works
## Stage 1
Renames variable names
## Stage 2
It first obfuscates all the numbers in the code, turning them into 5+3+2+8+.., then creates a class with an overriden truediv magic method, along with an init that accepts a function, that allows you to.. classname(print)/["Hello,","world"]. It loads into the class lots of return_id methods that construct the strings of the code, after base64 and LZMA and xor with a random constant, it obfuscates every node in the body of the code in a way that you require to run the code and you can't just replace exec with print (V1.0 had this error), it creates a lambda function that checks if the hash of the repr of the given encoded code after being added to the t variable matches z, just a simple checksum, then executes it.
## Stage 3 -- Compaction
Although the name claims to reduce code size, it does the opposite most of the time , it applies the most common way of obfuscation in python, which is marshal of compile, 4 times after different obfuscations, which make the code absurdly hard to recover, if not impossible
# Bugs
The class `Stringo` has a bug where it sometimes decides to crash after ast.unparse. It's not common and the cause is unknown. <br/>
similarly with BLD, the class sometimes may break, but is a lot less common <br/>
ZLib data can break when node contents of module.body are too large, causing a crash
# Name references
## BLD
Weak string obfuscator.
## Namer
Name obfuscator
## Stringo
Strong string obfuscator
## Number
Number obfuscator, Would consider it weak
## befso
BackEndForStringObfuscator
## stbj
StringToByteJoiner
## l2add
List to add
