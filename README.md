# Zulfur Obfuscator V1.6

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

#### FTO (Function To Object)
- Converts function definitions and lambdas into equivalent function objects
- Uses `eval` to create new code objects and functions from them
- Handles both synchronous and asynchronous functions

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

#### Number
- Breaks down larger integer literals into sums of smaller numbers
- Makes it harder to immediately recognize numeric values in the code

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

## Usage

### Command Line

```
python zfobf.py <input_file> [output_file]
```

### Interactive Mode

Run without arguments for interactive prompts:

```
python zfobf.py
```

## Configuration Options

- Quiet mode
- Version dependent code
- Builtin name hiding 
- Code compression
- Code wrapping

## Advantages

- Highly customizable obfuscation
- Modular design for easy extension
- Free and open source
- Active development

## Compatibility 

Tested on Linux. Should work on Windows and macOS.

## Contact

For issues or feature requests, contact @puc3 on Discord.
