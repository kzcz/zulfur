# Zulfur
Zulfur is a powerful obfuscator that makes code heavier and less readable
# How it works
## Stage 1
Renames variable names
## Stage 2
It first obfuscates all the numbers in the code, turning them into 1+1+1+1.., then creates a class with an overriden truediv magic method, along with an init that accepts a function, that allows you to.. classname(print)/["Hello,","world"]. It loads into the class lots of return_id methods that construct the strings of the code, after base64 and LZMA, it obfuscates every node in the body of the code and returns it back
## Stage 3 -- Compaction
Although the name claims to reduce code size, it does the opposite most of the time , it applies the most common way of obfuscation in python, which is marshal of compile, 4 times after different obfuscations, which make the code absurdly hard to recover, if not impossible
# Bugs
The class `Stringo` has a bug where it sometimes decides to crash after ast.unparse. It's not common and the cause is unknown.
similarly with BLD, the class sometimes may break, but is a lot less common
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
