trap "trap - SIGTERM && kill -- -$$" SIGINT SIGTERM SIGHUP EXIT

for i in `seq 0 4`
do
	np=$[10**i]
	for j in `seq 0 9`
	do
		./create_object $np
		sleep 2
	done
done