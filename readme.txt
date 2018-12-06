This is a standalone repository for ida developement purpose. It will be merged into harmony repository after fully develop and tested.
It depends on go-raptorq repo. 


12/06/2018 update
IDA Gossip Protocol finished. The go-raptorq binding to libraptorq has issue. Currently use a fake libraptorq version, which doesn't work well as libraptorq
1. to generate config files:
./generate_configs.sh
2. to start listening on broadcast:
./startserver.sh <node_id>
3. to broadcast a message
./startserver.sh <node_id> <message_file>
