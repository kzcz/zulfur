# Zulfur - V1.5
Zulfur is a powerful obfuscator that makes code heavier and less readable.
# Obfuscators
## BLD
Turns strings into `bytes(.....)`, optionally decoding it for str
## FTO
It turns functions into an equivalent object, by creating a new code object and creating a function from that code object.
## ftf
Turns for loops into while loops.
## HBF
Hides built-in function names, like print or exec, not much but leaves room for string obfuscators to do more work.
## IF2E
Converts If nodes into Try nodes, trying to run `1/(not condition)`, if it fails, the condition is true, if it doesn't, it was false.
## Namer
It changes names for variables.
## Number
Turns numbers into sum of smaller numbers.
## Stringo
It splits strings to smaller parts, putting every part in a random position of a list, like `[...,part,...]`, then taking index of where the part is, and adding the parts back together.
## tna
Adds noise to the code.
## TSOL
It encodes the String into a kind of hexadecimal, then mixes the values around, most of the values fall into CJK codes, so it gets the nickname of Chinese translator
# Info
## Why use zulfur?
1. Most python obfuscators are just a for i in range(...): comprees and compile code again and again, yes I'm talking to you Py-fuscate,Those that aren't, like PyArmor, are easy to hook up to a .so or a dll to get the code back, and if you happen to know any obfuscator that does real work, it probably relies on people just not knowing basic reverse engineering.
2. Zulfurs code is easy to modify, as all it's functionality is block based, you have classes and functions for every obfuscation step, so, if you need to use something specific, you can just import the feature from Zulfur with `from zfobf import Foo,...`.
3. It's free and there's actual work put into it, instead of a project that was updated last time 75 years B.C.
## Compatible operating systems
Linux is guaranteed to work. Windows and Mac were never tested, but there isn't any feature that is on linux not present on Mac or Windows.
## Contact
You can DM me in Discord `@puc3` if you have any issues or would like to suggest a new feature.