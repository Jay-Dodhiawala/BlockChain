# importing dependencies
import json
import socket
import uuid
import traceback
import random
import time
import string
from itertools import groupby
import hashlib

# variables
MY_HOST = str(socket.gethostbyname(socket.gethostname()))
MY_PORT = 8341
GOSSIP_HOST = "130.179.28.113" #"goose.cs.umanitoba.ca 116"
GOSSIP_PORT = 8999
PEER_TIMEOUT = 60
known_peers = list()        # list of peers i know
known_gossip_id = list()    # list of seen gossip messages
# my_chain = {}

# adding well know peer to known peer
known_peers.append((GOSSIP_HOST, GOSSIP_PORT, time.time()))

def send_message(host, port, message, addr=None):
    # create a udp socket for communication
    udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    # convert message to json
    json_message = json.dumps(message)
    if addr == None:
        udp_sock.sendto(json_message.encode('utf-8'), (host, port))
    else:
        udp_sock.sendto(json_message.encode('utf-8'), addr)
    udp_sock.close()

#---------------------------------Gossip-----------------------------------------------
# function to annouce to network
def send_gossip_message():
    # creating new gossip ids every time................ should it do that?
    gossip_id = str(uuid.uuid4())

    # gossip message
    gossip_message = {
    "type": "GOSSIP",
    "host": MY_HOST,
    "port": MY_PORT,
    "id": gossip_id,
    "name": "void"
    }

    # adding this gossip id to my known id list
    known_gossip_id.append(gossip_id)

    # send message to 3 random peers
    # announcing to all the known peer
    if len(known_peers) >= 3:
        print("sending gossip to 3 random peers")
        # choose any random 3 peer that i know
        random_peers = random.sample(known_peers, 3)
        
        # forward gossip to them
        for peer in random_peers:
            peer_host = peer[0]
            peer_port = peer[1]
            send_message(peer_host, peer_port, gossip_message)
    else:
        for peer in known_peers:
            peer_host = peer[0]
            peer_port = peer[1]
            send_message(peer_host, peer_port, gossip_message)

# handle gossip
def handle_gossip(message):
    # check for same gossip message
    gossip_id = message["id"]
    if gossip_id in known_gossip_id:
        return
    else:
        known_gossip_id.append(gossip_id)

    #-------------------------------------------------
    # send reply to originator
    # process gossip message
    origin_host = message["host"]
    origin_port = message["port"]
    # reply to originator
    gossip_reply = {
        "type": "GOSSIP_REPLY",
        "host": MY_HOST,
        "port": MY_PORT,
        "name": "void"
    }

    # adding peers to our list
    if (origin_host, origin_port) not in known_peers:
        known_peers.append((origin_host, origin_port, time.time()))

    # sending reply back to originator
    send_message(origin_host, origin_port, gossip_reply)

    #---------------------------------------------------
    # update peer list
    current_time = time.time()
    for peer in known_peers:
        peer_last_update_time = peer[2]
        if current_time - peer_last_update_time > PEER_TIMEOUT:
            del peer

    #---------------------------------------------------
    # announce it to 3 peers
    if len(known_peers) >= 3:
        # choose any random 3 peer that i know
        random_peers = random.sample(known_peers, 3)
        
        # forward gossip to them
        for peer in random_peers:
            peer_host = peer[0]
            peer_port = peer[1]
            send_message(peer_host, peer_port, message)
    else:
        for peer in known_peers:
            peer_host = peer[0]
            peer_port = peer[1]
            send_message(peer_host, peer_port, message)


# handle gossip reply
def handle_gossip_reply(gossip_message):
    # process gossip message
    origin_host = gossip_message["host"]
    origin_port = gossip_message["port"]

    # adding peers to our list
    if (origin_host, origin_port) not in known_peers:
        known_peers.append((origin_host, origin_port, time.time()))

#-------------------------------STATS--------------------------------------------------------
# sends stats message to all peer
def send_stats_message(peer_list):
    
    p_list = list()
    for peer in peer_list:
        p = (peer[0], peer[1])
        if p not in p_list:
            p_list.append(p)
    # uniques peer list
    # uni_peer_list = set(p_list)
    # store stats list
    peer_stats_list = list() # (host, port, height, hash)

    # create a udp socket for communication
    stats_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    stats_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    stats_sock.settimeout(1)

    # status message
    stats_message = {"type":"STATS"}

    # convert message to json
    json_message = json.dumps(stats_message)
      
    # send status message to all known peers
    for peer in p_list:
        try:
            peer_host = peer[0]
            peer_port = peer[1]
            stats_sock.sendto(json_message.encode('utf-8'), (peer_host, peer_port))

            # recving the response
            res, _ = stats_sock.recvfrom(1024)
            res = json.loads(res.decode('utf-8'))
            # handle stats reply data
            # if res["type"] == "STATS_REPLY":
            if res["type"] == "STATS_REPLY" and res["height"] != None and res["height"] != "None" and res["height"] != 'null' and res["hash"] != None and res["hash"] != "None" and res["hash"] != 'null':
                peer_stats = (peer_host, peer_port, int(res["height"]), res["hash"])
                # add to list if not avalable
                if peer_stats not in peer_stats_list:
                    peer_stats_list.append(peer_stats)
        except socket.timeout:
            # Handle timeout - skip this peer
            print(f"Timeout while requesting stats from {peer[0]}:{peer[1]}. Removing from peer list.")
            p_list.remove(peer)
            continue
        except Exception as e:
            print("Problem in send_stats_request()")
            print(e)
            print(res, peer_host, peer_port)
            traceback.print_exc()

    stats_sock.close()
    return peer_stats_list # (host, port, height, hash)

# function to reply stat request sent to us
def get_stats_message():
    # messenge to send
    top_data = my_chain[-1]
    height = len(my_chain)
    hashh = top_data['hash']
    stat_message = {
                    "type": "STATS_REPLY",
                    "height": height,
                    "hash": hashh 
                    }

    # convert message to json
    json_message = json.dumps(stat_message)
    return json_message

def find_longest_chain(stats_list):
    # Sort the data by height in descending order and tie breaks on majority
    sorted_data = sorted(stats_list, key=lambda x: (x[2], x[3]), reverse=True)

    # Group the sorted data by height and hash
    grouped_data = {}
    for key, group in groupby(sorted_data, key=lambda x: (x[2], x[3])):
        grouped_data[key] = list(group)
    return grouped_data

#------------------------------------------Build Chian----------------------------------
def send_get_block_request(host, port, atHeight):
    # create a udp socket for communication
    get_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    get_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    get_sock.settimeout(1)

    # get block message
    get_block_request = {
                        "type": "GET_BLOCK",
                        "height": atHeight
                        }
    
    # convert message to json
    json_message = json.dumps(get_block_request)

    try:
        # print(f"sending block request to {host, port}, with height = {atHeight}")
        get_sock.sendto(json_message.encode('utf-8'), (host, port))
         # recving the response
        res, _ = get_sock.recvfrom(1024)
        res = res.decode('utf-8')
        res_json = json.loads(res)
        # handle stats reply data
        # if res_json["type"] == "GET_BLOCK_REPLY":
        return res_json
        # else:
        #     return None
        
    except TimeoutError:
        print(f"timeout by {host, port}")

    except Exception as e:
        print(e)
        print(res)
        traceback.print_exc()
        return None

def get_block_reply_message(index):
    if index >= len(my_chain):
        data = {   'type': 'GET_BLOCK_REPLY',
                    'hash': None,
                    'height': None,
                    'messages': None,
                    'minedBy': None,
                    'nonce': None,
                    'timestamp': None,
                }
    else:
        data = my_chain[index]
    json_message = json.dumps(data)
    return json_message

def get_chain(peer_list):

    # peer list with hostname and port only
    if peer_list == None:
        print("Peer list is empty so doing gossip again")
        return None

    chain_height = peer_list[0][2]
    my_list = list()
    height = 0
    # for height in range(chain_height):
    print("Building Chain...")
    while height < chain_height:
        try:
            curr_peer = random.choice(peer_list)
            # curr_peer = peer_list[height % len(peer_list)]
            curr_peer_host = curr_peer[0]
            curr_peer_port = curr_peer[1]

            block_response = send_get_block_request(curr_peer_host, curr_peer_port, height)

            is_valide = True
            if block_response != None:
                # validate the block befor adding it my chain
                if height > 0 and height < len(my_list):
                    # print(height-1)
                    prev_element = my_list[height-1]
                    curr_element = block_response
                    is_valide = validate_block(curr_element, prev_element)

            if block_response != None and block_response['height'] != None and is_valide:
                my_list.append(block_response)
            else:
                peer_list.remove(curr_peer)
                if height > 1:
                    height -= 1
                else:
                    height = 0
            # increment by 1 every loop
            height += 1
        except Exception as e:
            # print(e)
            # print(peer_list)
            # traceback.print_exc()
            return None
    print(f"Chain is ready with height {len(my_list)}")
    return my_list

#--------------------------------------Verification---------------------------------------
def validate_block(block, prev_block):
    DIFFICULTY = 8
    hashBase = hashlib.sha256()
    # get the most recent hash
    lastHash = prev_block["hash"]

    # add it to this hash
    hashBase.update(lastHash.encode())            

    # add the miner
    if block['minedBy'] is not None:
        hashBase.update(block['minedBy'].encode())
    else:
        # Handle the case when timestamp is None
        # You might want to use a default timestamp or skip this update
        print("Warning: minedby is None. Skipping update.")

    # add the messages in order
    if block['messages'] is not None:
        for m in block['messages']:                
            hashBase.update(m.encode())
    else:
        # Handle the case when timestamp is None
        # You might want to use a default timestamp or skip this update
        print("Warning: Messages is None. Skipping update.")

    # the time (different because this is a number, not a string)
    # hashBase.update(block['timestamp'].to_bytes(8, 'big'))   
    if block['timestamp'] is not None and block['timestamp'] != "null":
        hashBase.update(int(block['timestamp']).to_bytes(8, 'big'))
    else:
        # Handle the case when timestamp is None
        # You might want to use a default timestamp or skip this update
        print("Warning: Timestamp is None. Skipping update.")


    # add the nonce
    hashBase.update(block['nonce'].encode())   

    # get the pretty hexadecimal
    hash = hashBase.hexdigest()                   

    # is it difficult enough? Do I have enough zeros?
    if hash[-1 * DIFFICULTY:] != '0' * DIFFICULTY:
        print("Block was not difficult enough: {}".format(hash))

    # print(f"block hash is {block['hash']}\ncalculated hash is {hash}")
    if block["hash"] == hash and hash[-1 * DIFFICULTY:] == '0' * DIFFICULTY:
        return True
    else:
        return False
    
def validate_chain(my_chain):
    for i in range(1,len(my_chain)):
        prev_block = my_chain[i-1]
        curr_block = my_chain[i]
        is_validate = validate_block(curr_block, prev_block)
        if is_validate == False:
            print(f"chain did not validate at index {i}")
            break
    return is_validate

def do_consensus():
    peer_stats = send_stats_message(known_peers)
    longest_chains = find_longest_chain(peer_stats)

    sorted_chains = dict(sorted(longest_chains.items(), key=lambda item: (item[0], len(item[1])), reverse=True))
    
    for key in sorted_chains:
        if len(my_chain) != 0:
            if my_chain[-1]["hash"] == key[1]:
                print("Chain is up to date...")
                return my_chain
        print(f"working on {key} and had {len(longest_chains[key])} peers")
        if len(longest_chains[key]) > 0:
            chain = get_chain(longest_chains[key])
            if chain != None:
                is_valide = validate_chain(chain)
                print(f"the chain is {is_valide}")
                if is_valide:
                    return chain
        else:
            print("peer list was empty")
            break
    return None

def add_new_block(block):
    # lets verify the block before adding it
    curr_top_block = my_chain[-1]
    is_valide = validate_block(block, curr_top_block)
    if is_valide:
        my_chain.append(block)
    else:
        print("block is not valide")

# generate random nonce
def generate_nonce(length=7):
    characters = string.ascii_letters + string.digits + string.punctuation
    nonce = ''.join(random.choice(characters) for _ in range(length))
    return nonce

def mine_block():
    try:
        print('mining...', len(my_chain))
        top_block = my_chain[-1]
        DIFFICULTY = 8
        timestamp = int(time.time())
        nonce = int(top_block["nonce"])

        while True and len(my_chain) > 0:
            print(f"nonce is {str(nonce)}")
            newBlock = {
                "height": len(my_chain),
                "messages": ["One_Piece", "Naruto", "SAO"],
                "minedBy": "void",
                "nonce": str(nonce),
                "timestamp": timestamp
            }

            # create has for this block
            hashBase = hashlib.sha256()
            # get the most recent hash
            lastHash = top_block["hash"]

            # add it to this hash
            hashBase.update(lastHash.encode())            

            # add the miner
            hashBase.update(newBlock['minedBy'].encode())

            # add the messages in order
            for m in newBlock['messages']:                
                hashBase.update(m.encode())

            # the time (different because this is a number, not a string)
            hashBase.update(newBlock['timestamp'].to_bytes(8, 'big'))   

            # add the nonce
            hashBase.update(newBlock['nonce'].encode())   

            # get the pretty hexadecimal
            hash = hashBase.hexdigest()                   

            # is it difficult enough? Do I have enough zeros?
            if hash[-1 * DIFFICULTY:] != '0' * DIFFICULTY:
                # print("Block was not difficult enough: {}".format(hash))
                pass
            else:
                print("got the block\n", newBlock)
                newBlock["hash"] = hash
                my_chain.append(newBlock)
                newBlock["type"] = "ANNOUNCE"
                #sending announce message to all known peers
                print("sending announce to all peers")
                for peer in known_peers:
                    send_message(peer[0], peer[1], newBlock)
                # return newBlock
            
            nonce = generate_nonce(8)
    except Exception:
        return None
    
    
def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((MY_HOST, MY_PORT))
    print(f"listening on {MY_HOST, MY_PORT}")

    global my_chain
    my_chain = {}

    with sock as s:
        try:
            print("Doing gossip...")
            send_gossip_message()
            gossip_time = time.time()
            # do_consensus()

            while True:
                curr_time = time.time()
                time_passed = curr_time - gossip_time
                # re-ping every 50 seconds
                if time_passed > 50:
                    print("re-pinging the gossip...")
                    # send gossip message again
                    send_gossip_message()
                    # reset timer
                    gossip_time = curr_time
                
                # doing consensus after 2 seconds of gossip
                # means if we do gossip evry 50 sec we will do consensus every 50 sec too
                if time_passed > 2 and time_passed < 3:
                    print("Doing consensus...")
                    chain = do_consensus()
                    if chain != None:
                        my_chain = chain

                data, addr = s.recvfrom(1024)
                try:
                    message = json.loads(data.decode('utf-8'))
                except json.JSONDecodeError:
                    print("Error decoding JSON. Skipping...")
                    traceback.print_exc()
                    continue

                if type(message) == dict:
                    if message["type"] == "GOSSIP":
                        handle_gossip(message)
                    elif message["type"] == "GOSSIP_REPLY":
                        handle_gossip_reply(message)
                    elif message["type"] == "CONSENSUS":
                        my_chain = do_consensus()
                    elif message["type"] == "STATS":
                        if len(my_chain) > 0:
                            my_stats_message = get_stats_message()
                            s.sendto(my_stats_message.encode('utf-8'), addr)
                    elif message["type"] == "STATS_REPLY":
                        pass # this is handled in send_stats_message()
                    elif message["type"] == "GET_BLOCK":
                        height = message["height"]
                        block = get_block_reply_message(int(height))
                        s.sendto(block.encode('utf-8'), addr)
                    elif message["type"] == "GET_BLOCK_REPLY":
                        pass
                    elif message["type"] == "ANNOUNCE":
                        print("Annonce...")
                        add_new_block(message)
                    else: 
                        pass
        except Exception as e:
            print(e)
            print(message)
            traceback.print_exc()
        finally:
            # closing the socket
            s.close()

import threading 

def start_mining_after_delay(delay):
    time.sleep(delay)
    print("delay over...")
    mining_thread = threading.Thread(target=mine_block)
    mining_thread.start()

main_thread = threading.Thread(target=main)
main_thread.start()
# main()
start_mining_after_delay(15)

