#! /usr/bin/bash
# https://stackoverflow.com/questions/9408103/shell-script-how-to-read-a-text-file-that-does-not-end-with-a-newline-on-window

FileName='./ala/kazam.txt'
while [ 1 ] ; do    
    read -r line
    if [ -z $line ] ; then
        break
    fi
    fileNamesListStr="$fileNamesListStr $line"
    done < $FileName
echo "$fileNamesListStr"