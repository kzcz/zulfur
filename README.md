# Zulfur Obfuscator Suite V2.1

Zulfur is a powerful Python code obfuscator that makes code harder to read and reverse engineer.

## Features

- String obfuscation
- Variable and function name randomization 
- Control flow obfuscation
- Dead code injection
- Builtin function hiding
- Code compression

## Obfuscation Techniques

### AST Transformers

Zulfur uses several subclasses of `ast.NodeTransformer` to manipulate the Abstract Syntax Tree (AST) of the Python code:

#### BLD (Bytes List Decode)
- Converts string and bytes literals into obfuscated forms
- Transforms strings into UTF-8 encoded byte lists that are later decoded
- Wraps byte literals in a custom decoding function call

#### Stringo
- Splits string literals into smaller parts
- Places each part in a random position within a list
- Reconstructs the original string by adding these parts back together

#### Namer
- Renames variables, functions, classes, and imported names
- Uses a consistent mapping to ensure renamed identifiers are used consistently throughout the code
- Avoids renaming built-in names

#### TSOL
- Encodes string and bytes literals using a custom hexadecimal-like encoding
- Translates the encoded strings to fall mostly within CJK (Chinese, Japanese, Korean) Unicode ranges
- Wraps the encoded strings in a custom decoding function call

#### IF2E (If to Except)
- Converts `if` statements into equivalent `try`/`except` blocks
- Uses a division by zero trick to execute the original `if` condition

#### HBF (Hide Builtin Functions)
- Replaces direct references to built-in functions with calls to obfuscated wrapper functions
- Makes it harder to identify which built-in functions are being used

#### AG2O (AugAssign to Assign)
- Converts augmented assignment operations (like `+=`, `-=`, etc.) into regular assignments with binary operations
- Simplifies the AST structure while maintaining equivalent functionality

### Additional Techniques

- **Dead Code Injection**: Adds random noise statements throughout code
- **Code Compression**: Compresses and encodes obfuscated code

## Zulfur Merger

zfmrg.py is a tool that merges many files into a single one, compressing the files, it does not obfuscate by itself, but can be used for a thin layer of indirection, and help distribute your programs as a unit. Note that it checks for the right packages to be installed, but it wont install them by itself.

# Underworld

underworld.py is a tool that splits your code into individual statements, encrypts them with a simple algorithm, and puts them back together. Each statement has an individual checksum to detect tampering. It does not obfuscate by itself, but can be used alongside the main obfuscator for extra protection. Note that it will stop execution if any checksum fails, which might happen on multiprocessing environments.

## Usage

### Command Line

```
python zfobf.py <input_file> [output_file]
```
If using Android, MacOs, or Unix-like OS, you can:
```
./zfobf.py <input_file> [output_file]
```

### Interactive Mode

Run without arguments for interactive prompts:

```
python zfobf.py
python zfmrg.py
```
And similarly with the last method, under the same conditions, you can:
```
./zfobf.py
./zfmrg.py
```

## Configuration Options

- Quiet mode
- Builtin name hiding 
- Code compression
- Code wrapping

## Advantages

- Highly customizable obfuscation
- Modular design for easy extension
- Free and open source
- Active development
## Contributing

I welcome contributions to Zulfur. For effective collaboration, please follow these guidelines:

### Reporting Issues

- **Operating System**: Your OS (e.g., Linux, Windows).
- **Python Version**: Your Python version (e.g., Python 3.8).
- **Zulfur Version**: Version of Zulfur used.

**For Bugs/User Crashes:**

- **Issue Description**: What is Zulfur incorrectly patching? Describe clearly in English or Spanish.
- **Pre-Zulfur Functionality**: Did it work before Zulfur?
- **Maybe it is your fault**: Sometimes, bugs or bad practices in your code might generate obfuscated code that misses a variable, or that doesn't work as intended, since I am not a magician, the best I can do is recommend you to, before submitting an issue, run a linter on your own code to check its consistency, I use pyright.

**For Zulfur Crashes:**

- **Crash Location**: Which line or section crashed?
- **Usage Context**: Was Zulfur imported or run directly?
- **Modifications**: If modified, what are the sources of these changes?

### Pull Requests

1. **Fork and Clone**: Fork Zulfur and clone it.
2. **Branch**: Create a new branch for your changes.
3. **Commit**: Use clear commit messages.
4. **Test**: Verify your changes.
5. **Pull Request**: Push and submit a pull request with a description.
6. **Review**: Address feedback from reviewers.

### Contact

For issues or help, contact @puc3 on Discord.

## Compatibility 

Tested on Linux. Should work on Windows and macOS.

## License

### For Users

This project is licensed under the GNU General Public License v3.0 (GPLv3). This means that you are free to use, modify, and distribute the software as long as you adhere to the terms of the license. Specifically:

- **Freedom to Use**: You can use the software for any purpose.
- **Freedom to Modify**: You can modify the software and distribute your modifications under the same license.
- **Copyleft**: Any derivative work you distribute must be licensed under the GPLv3 as well. This ensures that the freedoms granted by the license are preserved in derivative works.

### For Hackers

If you're diving into the code or looking to understand or extend the functionality, here’s what the GPLv3 means for you:

- **Transparency**: You have access to the source code, allowing you to study and understand how it works.
- **Contribution**: You can contribute back improvements or fixes to the project, which will also be licensed under GPLv3.
- **Redistribution**: If you share the modified version of the software, you must also share the source code and keep it under the GPLv3 license.

### Changelog
- **1.7**: Added partial support for the syntax of 3.13 and later.
- **2.0 alpha**: Changed location of some stuff, and merged a background project.
- **2.1 alpha**: Moved more stuff, and added a new obfuscator as its own individual file, since it is still missing features.
