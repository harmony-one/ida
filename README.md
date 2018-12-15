This is a standalone repository for ida developement purpose. It will be merged into harmony repository after fully develop and tested.
It depends on go-raptorq repo. 


### 12/06/2018 update
IDA Gossip Protocol finished. The go-raptorq binding to libraptorq has issue. Currently use a fake libraptorq version, which doesn't work well as libraptorq
1. to generate config files:
./generate_configs.sh
2. to start listening on broadcast for node_id between 0 to node_id:
./startserver_ida.sh node_id
3. to broadcast a message from node_id
./send_ida.sh <node_id> <message_file>


### 12/11/2018
add unicast mode support
