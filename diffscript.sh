#!/bin/bash

if [ $# -ne 2 ]
then
	echo "Usage: $0 <folder 1> <folder 2>"
	exit
fi

cd $1
LIST1=*
cd $2
LIST2=*

for l1 in $LIST1
do
	#Find if $l1 exists in $LIST2
	FOUND=0
	for l2 in $LIST2
	do
		if [ $l1 = $l2 ]
		then
			FOUND=1
			break
		fi
	done

	#If $l1 existed in $LIST2
	if [ $FOUND -eq 1 ]
	then
		RESULT=`diff $l1 $l2`
		if [ -n $RESULT ]
		then
			echo "$l1 / $l2 is unmodified"
		else
			echo "$l1 / $l2 is modified"
		fi
	fi
done
