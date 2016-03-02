#!/bin/bash

if [ $# != 3 ]
then
	echo "Usage: $0 bin thread_num loop_time"
	exit 1
fi

bin=$1
thread_num=$2
loop_time=$3

for ((i=0;i<$loop_time;i++))
do
	for ((j=0;j<$thread_num;j++))
	do
		$bin &
	done

	wait
done
