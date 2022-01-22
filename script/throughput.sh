trap "trap - SIGTERM && kill -- -$$" SIGINT SIGTERM SIGHUP EXIT

mkdir -p results

for i in `seq 0 4`
do
  ./store &
	sleep 5

	np=$[2**i]
	for j in `seq $np`
	do
		./mp_benchmark $j > results/lightning-$np-$j.txt &
	done

	sleep 20
	pkill mp_benchmark
	pkill store
	sleep 5
done
