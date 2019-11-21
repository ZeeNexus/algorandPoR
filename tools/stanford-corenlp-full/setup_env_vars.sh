#!/usr/bin/env bash
#
# Set up your classpath
# exports env var classpath for each JAR file

MY_PATH=$CLASSPATH


for file in `find . -name "*.jar"`
do 
   # export CLASSPATH="$CLASSPATH:`realpath $file`"; 
   SCRIPT=`realpath $file`
   # MY_FILE = $(realpath $file 2>&1)
   # MY_FILE = `realpath $file`
   MY_PATH+=":$SCRIPT"
   export CLASSPATH="$CLASSPATH:`realpath $file`"
   
  # realpath $file;
done
echo $MY_PATH
echo "________________________"

export CLASSPATH="$MY_PATH"; 

echo "classpath: $CLASSPATH"


