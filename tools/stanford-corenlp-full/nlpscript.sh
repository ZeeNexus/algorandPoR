#!/usr/bin/env bash
#
# Runs Stanford CoreNLP in sentimental analysis
# Simple uses for xml and plain text output to files are:
#    ./nlpscript.sh -file filename
#    ./nlpscript.sh -file filename -outputFormat text 
#
# You can also start a simple shell where you can enter sentences to be processed:
#    ./nlpscript.sh
# ./nlpscript.sh -file input.txt -outputFormat json
# ./nlpscript.sh -file input.txt -outputFormat json -outputDirectory /tmp
# -parse.model edu/stanford/nlp/models/srparser/englishSR.ser.gz

OS=`uname`
# Some machines (older OS X, BSD, Windows environments) don't support readlink -e
if hash readlink 2>/dev/null; then
  scriptdir=`dirname $0`
else
  scriptpath=$(readlink -e "$0") || scriptpath=$0
  scriptdir=$(dirname "$scriptpath")
fi

echo java -mx2g -cp \"$scriptdir/*\" edu.stanford.nlp.pipeline.StanfordCoreNLP -annotators tokenize,ssplit,pos,parse,sentiment $*
java -mx2g -cp "$scriptdir/*" edu.stanford.nlp.pipeline.StanfordCoreNLP -annotators tokenize,ssplit,pos,parse,sentiment $*

