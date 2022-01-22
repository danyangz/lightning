trap "trap - SIGTERM && kill -- -$$" SIGINT SIGTERM SIGHUP EXIT

mkdir -p results

for waiter in 0 1 2 4 8 16 32 64
do
  for index in `seq 0 9`
  do
    ./store &
    sleep 2
    for j in `seq 0 $[$waiter-1]`
    do
      ./subscribe &
    done
    sleep 10
    ./create_latency >results/waittest-$waiter-$index.txt

    sleep 2
    pkill store
    sleep 2
  done
done