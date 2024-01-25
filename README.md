# Blockchain

To run the code just go to dir containing files and type ```python main.py```. it will take around 5-6 sec to synchronnize and you can also see on command line it says chain ready...

In this code we are sending GOSSIP message to a well-known peer to join the network. After joining the network it keep re-GOSSIPing to 3 known peers every 50 sec to keep us in their peer list for future updates. it has been implemented in function called ```send_gossip_message() ```(line 40).

And this code also implements the feature which cleans up the peer that has not send GOSSIP message after 60 sec. this feature has been implemented in a function called ```handle_gossip()``` in which I have commented it where its being implemented.

After joining network and all now we consensus (line 385 ```do_consensus()```) to get the longest and valide chain on our peer/machine. To achive this we are sending STAT message to all of our known peer (```send_stats_message()```) and after getting reply we find the longest chain (ties break on majority) which we implement in ```find_longest_chain()```. Fter getting the list of peers containg the longest chain we send them GET_BLOCK message and we build our own chain. Due to some wronge formates in GET_BLOCK replay message i have to verify each block before adding to my chain which makes this little slow (```get_chain()```). But after builing the whole chain we verify the whole chain once again (```validate_chain()```).

At the last I also created a function called ```add_new_block()```which handles ANNOUNCE. This function added new block to our chain after verifying its a valide block.