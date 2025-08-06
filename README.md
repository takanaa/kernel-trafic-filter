# kernel-trafic-filter  
1. Run `make` in work directory to build module
2. `make clean` to clear directory  
3. Insert module into kernel with:  
``` bash  
sudo insmod icmp_block.ko  
```  
3. Remove from kernel with:  
``` bash  
sudo rmmod icmp_bloc  
```  
4. Also you can see logs with:
``` bash
dmesg | grep "ICMP"  
dmesg | tail -n 20  
```  
