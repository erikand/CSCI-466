import Network
import argparse
from time import sleep
import hashlib

## Jared: I modified the packet class to include the ack_nack flags. 
class Packet:
    ## the number of bytes used to store packet length
    seq_num_S_length = 10
    length_S_length = 10
    ack_nack_S_length = 2
    ## length of md5 checksum in hex
    checksum_length = 32 
    
        
    def __init__(self, seq_num, ack_nack, msg_S):
        self.seq_num = seq_num
        self.ack_nack = ack_nack
        self.msg_S = msg_S
        
    @classmethod
    def from_byte_S(self, byte_S):
        if Packet.corrupt(byte_S):
            raise RuntimeError('Cannot initialize Packet: byte_S is corrupt')
        #extract the fields
        seq_num = int(byte_S[Packet.length_S_length : Packet.length_S_length+Packet.seq_num_S_length])
        ack_nack = byte_S[Packet.length_S_length+Packet.seq_num_S_length : Packet.length_S_length+Packet.seq_num_S_length+Packet.ack_nack_S_length]
        msg_S = byte_S[Packet.length_S_length+Packet.seq_num_S_length+Packet.checksum_length :]
        return self(seq_num, ack_nack, msg_S)
    
        
    def get_byte_S(self):
        #convert sequence number of a byte field of seq_num_S_length bytes
        seq_num_S = str(self.seq_num).zfill(self.seq_num_S_length)
        #convert ack/nack to a byte field of ack_nack_S_length bytes
        ack_nack_S = str(self.ack_nack_S_length + len(seq_num_S)).zfill(self.ack_nack_S_length)
        #convert length to a byte field of length_S_length bytes
        length_S = str(self.length_S_length + len(ack_nack_S) + len(seq_num_S) + self.checksum_length + len(self.msg_S)).zfill(self.length_S_length)
        #compute the checksum
        checksum = hashlib.md5((length_S+seq_num_S+ack_nack_S+self.msg_S).encode('utf-8'))
        checksum_S = checksum.hexdigest()
        #compile into a string
        return length_S + seq_num_S + ack_nack_S + checksum_S + self.msg_S
   
    @staticmethod
    def corrupt(byte_S):
        #extract the fields
        length_S = byte_S[0:Packet.length_S_length]
        ack_nack_S = byte_S[Packet.length_S_length : Packet.length_S_length + Packet.ack_nack_S_length]
        seq_num_S = byte_S[Packet.length_S_length + Packet.ack_nack_S_length : Packet.length_S_length + Packet.ack_nack_S_length + Packet.seq_num_S_length]
        checksum_S = byte_S[Packet.length_S_length + Packet.ack_nack_S_length + Packet.seq_num_S_length : Packet.length_S_length + Packet.ack_nack_S_length + Packet.seq_num_S_length + Packet.checksum_length]
        msg_S = byte_S[Packet.length_S_length + Packet.ack_nack_S_length + Packet.seq_num_S_length + Packet.checksum_length :]
        
        #compute the checksum locally
        checksum = hashlib.md5(str(length_S+seq_num_S+ack_nack_S+msg_S).encode('utf-8'))
        computed_checksum_S = checksum.hexdigest()
        #and check if the same
        return checksum_S != computed_checksum_S
    
##Jared: I basically just copied in the RDT 1.0 code for 2.1` and 3.0 to start with
class RDT:
    ## latest sequence number used in a packet
    seq_num = 1
    ## buffer of bytes read from network
    byte_buffer = '' 

    def __init__(self, role_S, server_S, port):
        self.network = Network.NetworkLayer(role_S, server_S, port)
    
    def disconnect(self):
        self.network.disconnect()
        
    def rdt_1_0_send(self, msg_S):
        p = Packet(self.seq_num, self.ack_nack, msg_S)
        #does not handle ack/nack
        self.seq_num += 1
        self.network.udt_send(p.get_byte_S())
        
    def rdt_1_0_receive(self):
        ret_S = None
        byte_S = self.network.udt_receive()
        self.byte_buffer += byte_S
        #keep extracting packets - if reordered, could get more than one
        while True:
            #check if we have received enough bytes
            if(len(self.byte_buffer) < Packet.length_S_length):
                return ret_S #not enough bytes to read packet length
            #extract length of packet
            length = int(self.byte_buffer[:Packet.length_S_length])
            if len(self.byte_buffer) < length:
                return ret_S #not enough bytes to read the whole packet
            #create packet from buffer content and add to return string
            p = Packet.from_byte_S(self.byte_buffer[0:length])
            ret_S = p.msg_S if (ret_S is None) else ret_S + p.msg_S
            #remove the packet bytes from the buffer
            self.byte_buffer = self.byte_buffer[length:]
            #if this was the last packet, will return on the next iteration
            
    #Here is a quick reference table for ack_nack flags
    #00 is a data packet
    #10 is an ack
    #11 is a nack
    def rdt_2_1_send(self, msg_S):
        #send data
        p = Packet(self.seq_num, self.ack_nack, msg_S)
        #handle ack/nack
        if(p.ack_nack == "00"):
            #normal message
            self.seq_num += 1
            self.network.udt_send(p.get_byte_S())
        elif(p.ack_nack == "10"):
            #ack message
            self.network.udt_send(p.get_byte_S())
        elif(p.ack_nack == "11"):
            #nack message
            self.network.udt_send(p.get_byte_S())
            
    #Jared: All I have done so far is add a try except catch block for handling
    #any corrupt packets  
    def rdt_2_1_receive(self):
        ret_S = None
        byte_S = self.network.udt_receive()
        self.byte_buffer += byte_S
        #keep extracting packets - if reordered, could get more than one
        while True:
            #check if we have received enough bytes
            if(len(self.byte_buffer) < Packet.length_S_length):
                return ret_S #not enough bytes to read packet length
            #extract length of packet
            length = int(self.byte_buffer[:Packet.length_S_length])
            if len(self.byte_buffer) < length:
                return ret_S #not enough bytes to read the whole packet
            #create packet from buffer content and add to return string
            try:
                p = Packet.from_byte_S(self.byte_buffer[0:length])
                ret_S = p.msg_S if (ret_S is None) else ret_S + p.msg_S
                #remove the packet bytes from the buffer
                self.byte_buffer = self.byte_buffer[length:]
                #if this was the last packet, will return on the next iteration
            except RunTimeError:
                #this occurs when a corrupt packet is recvd.
                #send nack... this needs work
                p.ack_nack = "11"
                
    #Jared: Not started yet on any of the 3.0, just copied in from 2.1  
    def rdt_3_0_send(self, msg_S):
        #send data
        p = Packet(self.seq_num, self.ack_nack, msg_S)
        #handle ack/nack
        if(p.ack_nack == "00"):
            #normal message
            self.seq_num += 1
            self.network.udt_send(p.get_byte_S())
        elif(p.ack_nack == "10"):
            #ack message
            self.network.udt_send(p.get_byte_S())
        elif(p.ack_nack == "11"):
            #nack message
            self.network.udt_send(p.get_byte_S())
            
    def rdt_3_0_receive(self):
        ret_S = None
        byte_S = self.network.udt_receive()
        self.byte_buffer += byte_S
        #keep extracting packets - if reordered, could get more than one
        while True:
            #check if we have received enough bytes
            if(len(self.byte_buffer) < Packet.length_S_length):
                return ret_S #not enough bytes to read packet length
            #extract length of packet
            length = int(self.byte_buffer[:Packet.length_S_length])
            if len(self.byte_buffer) < length:
                return ret_S #not enough bytes to read the whole packet
            #create packet from buffer content and add to return string
            try:
                p = Packet.from_byte_S(self.byte_buffer[0:length])
                ret_S = p.msg_S if (ret_S is None) else ret_S + p.msg_S
                #remove the packet bytes from the buffer
                self.byte_buffer = self.byte_buffer[length:]
                #if this was the last packet, will return on the next iteration
            except RunTimeError:
                #this occurs when a corrupt packet is recvd.
                #send nack... this needs work
                p.ack_nack = "11"

if __name__ == '__main__':
    parser =  argparse.ArgumentParser(description='RDT implementation.')
    parser.add_argument('role', help='Role is either client or server.', choices=['client', 'server'])
    parser.add_argument('server', help='Server.')
    parser.add_argument('port', help='Port.', type=int)
    args = parser.parse_args()
    
    rdt = RDT(args.role, args.server, args.port)
    if args.role == 'client':
        rdt.rdt_1_0_send('MSG_FROM_CLIENT')
        sleep(2)
        print(rdt.rdt_1_0_receive())
        rdt.disconnect()
        
        
    else:
        sleep(1)
        print(rdt.rdt_1_0_receive())
        rdt.rdt_1_0_send('MSG_FROM_SERVER')
        rdt.disconnect()
        


        
        