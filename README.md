# xxstrings
## What is xxstrings?
xxstrings is a tool for extracting strings from the memory of a process.
xxstrings is a modification and improvement of the famous strings2 by Geoff McDonald. All rights reserved.

## How does xxstrings work and what improvements does it bring?
xxstrings reads all virtual memory addresses of the granted process, extracting the ascii or unicode strings from the buffer.
This new version of the old and outdated strings2 uses memory paging by default to completely speed up the string extraction process being up to 50% faster than the old strings2.
In addition, from the program flags, it allows enabling or disabling memory paging and it also allows activating a new Eco mode.

### What does the Eco Mode?
In which the new Eco mode?
The new Eco mode enables or disables memory paging depending on the Private Usage of the process.
This in order to speed up the extraction of strings for processes with a greater amount of memory used. (Eco Mode activates paging when private usage exceeds 500MB).

### Cons of paging:
Paging can cause you to lose some strings as it is limiting the region size.
Although do not worry, most likely you will not have problems, in the case of having them you can deactivate it from the flags

## Flags
```
 -p pid
        Defines the Process ID from which the strings will be extracted.
 -eco
        Activate Eco Mode. This will only use paging in processes with a job size greater than 500 MB.
 -notpage
        Disables the paging that is enabled by default.
 -raw
        Only prints the regular ascii/unicode strings.
 -a
        Prints only ascii strings.
 -u
        Prints only unicode strings.
 -l [numchars]
        Minimum number of characters that is
        a valid string. Default is 4.
```
## Contact
You can contact me via Discord on my DM: ZaikoARG#1187

Or on my official tools discord server: https://discord.gg/9jMqbyvMZS
