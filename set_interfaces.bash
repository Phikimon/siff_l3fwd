DEV=enp0s10
ID=00:0a.0

ip link set dev $DEV down
./dpdk-devbind.py  --status
modprobe vfio_pci
modprobe vfio enable_unsafe_noiommu_mode=1
echo 1 > /sys/module/vfio/parameters/enable_unsafe_noiommu_mode
./dpdk-devbind.py  -b=vfio-pci $ID
./dpdk-devbind.py  --status

#SETUP
# echo 128 | sudo tee /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages
# ./l3fwd -a 00:09.0 -a 00:0a.0 -l 0-2 -- --lookup=lpm -p 0x3 --config "(0,0,1),(1,0,2)"
