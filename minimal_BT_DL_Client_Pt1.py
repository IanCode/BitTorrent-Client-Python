
# XXX SOURCES :
# http://www.kristenwidman.com/blog/33/how-to-write-a-bittorrent-client-part-1/
# https://wiki.theory.org/BitTorrentSpecification#Tracker_HTTP.2FHTTPS_Protocol
# https://github.com/eweast/BencodePy

# from bencodepy import * # bencoding library. If this isn't found by default,
# install it with 'pip install bencodepy'
import bencodepy
from socket import *
from bitarray import bitarray
import requests     # http requests
import hashlib      # SHA1 hashing for info hash
import binascii     # use unhexlify to convert ascii hex sequences into binary
import random       # create the local peer id
import math         # you'll need to use the ceil function in a few places
import sys
import re
from string import ascii_letters, digits
import urllib

ALPHANUM    = ascii_letters + digits
INTERESTED  = b'\x00\x00\x00\x01\x02'
CHOKE       = b'\x00\x00\x00\x01\x00'
UNCHOKE     = b'\x00\x00\x00\x01\x01'
NOT_INTERESTED = b'\x00\x00\x00\x01\x03'
KEEP_ALIVE = b'\x00\x00\x00\x00'

# Here are some global variables for your use throughout the program.
local_port          = 62690
peer_id             = ('M0-0-1-' +  ''.join(random.sample(ALPHANUM, 13)))
protocol_string     = 'BitTorrent protocol'
reserved_hex_ascii  = '0000000000000000' # The reserved sequence for your handshake
peer_connections    = [] # An array of PeerConnection objects
total_length        = 0 # Total length of the file being downlaoded
no_of_pieces        = 0 # Number of pieces the file's divided into
piece_length        = 0 # Size of each piece
piece_length_bytes  = 0
i_have              = None # A bitarray representing which pieces we have
file_array          = [] # An array of pieces (binary sequences)
req_block_size_int  = 16384 # Recommended size for requesting blocks of data
req_block_size_hex  = int(req_block_size_int).to_bytes(4, byteorder='big', signed=True)
last_block_size_int = 0 # The size of the last block of the file
output_filename     = None # The name of the file we'll write to the filesystem
total_bytes_gotten  = 0 # Total number of bytes received towards the full file so far
total_length_bytes  = 0
done                = False # Are we done yet?
torrent_url         = ''
announce_url        = ''
list_have_pieces         = [] #list of numbers from "have" messages from a peer  
# variable used to store the global bencodepy decoded ordered dict & info
btdata_backup       = None
btdata_info_backup  = None
newline             = "\n" 



def main():
    global done
    if (len(sys.argv)==2):
        bt_data     = get_data_from_torrent(sys.argv[1])
        info_hash   = get_info_hash(bt_data)
        print(newline)
        # call tracker request
        tracker_req(bt_data, info_hash)
    else:
        print('incorrect number of arguments')

    for p in peer_connections:

        if done:
            sys.exit(1)
        else:
            # XXX test print XXX
            print('trying handshake...')
            print("Try to handshake "+ p.ip +" "+str(p.port))
            handle = p.handshake(info_hash)
            if handle:
                request = p.handle_messages(s)
                if request:
                    print("returned true on unchoke")
                    print("requesting peer " + str(p.ip))
                    i = 0
                    while i < torrent_data.no_of_pieces:
                        print("requesting piece " + str(i))
                        request_piece(p, s, i)
                        i = i + 1
            # try:
            #     # print("Try to handshake "+ p.ip.decode() +" "+str(p.port))
            #     print("Try to handshake "+ p.ip +" "+str(p.port))
            #     p.handshake(info_hash)
            # except:
            #     pass


        #full featured implementation would require multiple concurrent 
        #requests for different pieces of the file to different peers. 
        # multiple threads or other ways to handle concurrency, and would also
        #involve a bit more bookkeeping
        #This implementation: whole file from a single peer, cycling through the
        #list of peers until we find one that provides with the full file

# define a TorrentData object type
# the purpose of this class is to store data corresponding to the
# meta-data that's extracted from the .torrent file in an organized way
class TorrentData:
    # class constructor
    def __init__(self, output_filename, total_length, total_length_bytes, piece_length, piece_length_bytes, no_of_pieces, announce_url):
        self.output_filename = output_filename
        self.total_length = total_length
        self.total_length_bytes = total_length_bytes
        self.piece_length = piece_length
        self.piece_length_bytes = piece_length_bytes
        self.no_of_pieces = no_of_pieces
        self.announce_url = announce_url

class PeerConnection:
    """A class representing the connection to a peer"""
    def __init__(self, ip, port, pid):
        self.ip = ip
        self.port = port
        self.pid = pid
        self.have = bitarray()
    def handshake(self, info_hash):
        # Declare any necessary globals here
        global s
        # Your handshake message will be a bytes sequence
        # <pstrlen><pstr><reserved><info_hash><peer_id>
        # https://wiki.theory.org/BitTorrentSpecification#Handshake
        #http://bittorrent.org/beps/bep_0003.html#peer-protocol
        # In version 1.0 of the BitTorrent protocol, pstrlen = 19, and pstr = "BitTorrent protocol".
        pstrlen = 19

        # send byte string handshake to peer
        bin_reserved = binascii.unhexlify(reserved_hex_ascii)
        byte_string = chr(pstrlen)+protocol_string#+reserved_hex_ascii
        #byte_string = str.encode(byte_string)
        byte_string = str.encode(byte_string)
        byte_string = byte_string+bin_reserved +info_hash + str.encode(self.pid)
        #### TEST PRINTS ####
        #print('pid : ', self.pid)
        #print('info_hash : ', info_hash)
        #print('byte string : ', byte_string)
        #print('byte string post pid : ', byte_string)
        #binstr = reserved_hex_ascii.encode()
        s = socket(AF_INET, SOCK_STREAM)
        s.settimeout(10)
        print("Trying to connect to {0}:{1}".format(self.ip, self.port))
        try:
            s.connect((self.ip, self.port))
            print('sending byte_string handshake...')
            s.send(byte_string)


        # The global reserved_hex_ascii stores the reserved value, but you'll
        # need to convert it from ascii-written hex to binary data.
 
        # You'll need to set up a TCP socket here to the peer (the self value
        # for this object represents the peer connection, remember)


        # Here you'll need to consume the response. Use recv on this socket to
        # get the message. First you need to discover how big the message is
        # going to be, and then you need to consume the full handshake.
        #handshake is (49+len(pstr)) bytes long.
            resp_length = s.recv(1)
            resp_length = int.from_bytes(resp_length, byteorder='big')
            return_protocol = s.recv(resp_length)
            res_bytes = s.recv(8)
            return_hash = s.recv(20)
            resp_pid = s.recv(20)

            #### TEST PRINTS ####
            #print("Response protocol")
            #print(return_protocol)
            #print("reserved bytes")
            #print(res_bytes)
            #print("Response hash")
            #print(return_hash)
            #print("Response pid")
            #print(resp_pid)

            return True
            # If you got a handshake, it's time to handle incoming messages.

        except:
            print("[Errno 51]: Network is unreachable")
            print("No returned handshake from peer")
            return False
 
    def handle_messages(self, sock):
        # This method will handle messages from the peer coming
        # in on the socket. Read the section of the BT specification
        # closely! Read until the "Algorithms" section.
        # https://wiki.theory.org/BitTorrentSpecification#Peer_wire_protocol_.28TCP.29

        # Declare any necessary global variables
        # here using the 'global' keyword
        #<length_prefix><message ID><payload> form of these messages
        #length is 4 bytes, length is 1 byte, payload is length-dependent (length-5bytes)

        while True:
            # Grab first four bytes of the message to see how
            # long the message is going to be. You can tell a lot (most of
            # what you need to know) just by the length of the message.
            data = s.recv(4)

            # Remember, the argument to recv() tells the socket how many bytes
            # to read. Use this to control the incoming message flow.


            # Remember, the data coming in is in bytes. You'll need to get an
            # int value to determine the size of the message. Use
            #
            # int.from_bytes(data, byteorder='big')
            #
            # for this, where data is the 4 byte sequence you just read in. FYI,
            # the second argument here indicates that the bytes should be
            # read in the "big-endian" way, meaning most significant on the left.
            fart = b'\x00\x00@\x00'
            shart = int.from_bytes(fart, byteorder='big')
            size = int.from_bytes(data, byteorder='big')
            fucker = b'\x00\x00\x40\x00'
            fuck = 16384
            test = fuck.to_bytes(4, byteorder = 'big') 
            shit = int.from_bytes(fucker, byteorder = 'big')
            ####### TEST PRINTS #########
            print("size " + str(size))
            print(test)
            print(shit)
            print(fuck)
            print("shart")
            print(shart)
            # Now to handle the different size cases:
            #
            # if #SIZE IS BITFIELD SIZE (in bytes, of course)
            if size == 2:
                #get the id of the message
                messid = s.recv(1)
                messid = int.from_bytes(messid, byteorder='big')
                # In this case, the peer is sending us a message composed of a series
                # of *bits* corresponding to which *pieces* of the file it has. So, the
                # length of this will be... bits, bytes, pieces, oh dear! Remember there's
                # always an extra byte corresponding to the message type, which comes
                # right after the length sequence and in this case should be 5.
                # Just to be sure, you should receive another byte and make sure it is
                # in fact equal to 5, before consuming the whole bitfield.
                # if # Check the message type is 5, indicating bitfield
                if messid == 5: #tmp
                    print("Receiving bitfield")
                    # The peer's 'have' attribute is a bitarray. You can assign
                    # that here based on what you've just consumed, using
                    # bitarray's frombytes method.
                    #
                    # https://pypi.python.org/pypi/bitarray
                    bitlength = size - 1
                    print("bitlength = " + str(bitlength))
                    self.have = bitarray(endian='big')
                    havebytes = s.recv(bitlength)
                    self.have.frombytes(havebytes)
                    self.have = self.have[:torrent_data.no_of_pieces]
                    print("Peer have: ")
                    print(self.have)
                    # you can use the bitarray all() method to determine
                    # if the peer has all the pieces. For this exercise,
                    # we'll keep it simple and only request pieces from
                    # peers that can provide us with the whole file. Of course
                    # in a real BT client this would defeat the purpose.
                    has_whole_file = all(self.have)
                    # If the peer does have all the pieces, now would be a good time
                    # to let them know we're interested.
                    if has_whole_file == True:
                        ######TEST PRINTS######
                        print("Interested in peer {0}".format(self.ip))
                        s.send(INTERESTED)
                    else:
                        print("Incomplete bitfield")



            elif size == 0:
            # SIZE IS ZERO
                print("keep alive")
            # It's a keep alive message. The least interesting message in the
            # world. You can handle this however you think works best for your
            # program, but you should probably handle it somehow.
                pass

            elif size == 1:
                #get the id of the message
                messid = s.recv(1)
                messid = int.from_bytes(messid, byteorder='big')
            # SIZE IS ONE
            # If the message size is one, it could be one of several simple
            # messages. The only one we definitely need to care about is unchoke,
            # so that we know whether it's okay to request pieces. The message
            # code for unchoke is 1, so make sure you consume a byte and deal with
            # that message.
            # If you do get an unchoke, then you're doing great! You've found
            # a peer out there who will give you some data. Now would be the time
            # to go pluck up your courage and make that request!
                if messid == 1:
                    print("Unchoked by peer {0}".format(self.ip))
                    return True
            # When making a request here, we'll go ahead and simply start with
            # the first piece at the zero index (block) and progress through in
            # order requesting from the same peer. Note: In a real implementation,
            # you would probably take a different approach. A common way to do
            # it is to look at all peers' bitfields and find the rarest piece
            # among them, then request that one first.
                    #i = 0
                    #while i < torrent_data.no_of_pieces:
                     #   print("requesting piece " + str(i))
                      #  self.request_piece(s, i)
                       # i = i + 1

            elif size == 5:
                #get the id of the message
                messid = s.recv(1)
                messid = int.from_bytes(messid, byteorder='big')
            # SIZE IS FIVE
                if messid == 4:
                    piece_index = s.recv(4)
                    piece_index = int.from_bytes(piece_index, byteorder='big')
                    print("have piece " + str(piece_index))
                    list_have_pieces.append(piece_index)
            # It's a have. Some clients don't want so send just a bitfield, or
            # maybe not send one at all. Instead, they want to tell you index
            # by index which pieces they have. This message would include a
            # single byte for the message type (have is 4) followed by 4 bytes
            # representing an integer index corresponding to the piece the have.
                    num_have_pieces = len(list_have_pieces)
            # If you get have messages for all the pieces, that also tells you
            # that the peer has the pieces you need, so now is also a good time
            # to check their have array, and if they've got all the pieces send
            # them an interested message.
                    print("num_have_pieces = " + str(num_have_pieces))
                    print("no_of_pieces = " + str(torrent_data.no_of_pieces))
                    if num_have_pieces == torrent_data.no_of_pieces:
                        print("Peer has all the pieces")
                        s.send(INTERESTED)

 


            elif size == req_block_size_int or size == last_block_size_int+9:
                #get the id of the message
                print("This is a block of data")
                messid = s.recv(1)
                messid = int.from_bytes(messid, byteorder='big')
            # SIZE IS REQUESTED BLOCK SIZE OR LAST BLOCK SIZE (PLUS 9)
            # This must be a block of data. You'll have to do the bookkeeping
            # to know whether you're consuming a standard sized block (defined
            # in global variable req_block_size_int) or a smaller one for the
            # last block, because you'll need to consume the appropriate
            # number of bytes. Check the wireshark traces for why this size
            # should be "plus 9".

            # Remember, a block isn't a full piece. Here is where I'd suggest you
            # call the function that consumes the block.

                # get_block(self, data, sock)
                pass

            if not data:
            # There's also the case that there's no data for the socket. You probably
            # want to handle this in some way, particularly while you're developing
            # and haven't got all the message handling fully implemented.
                break
def get_block(peer, data, sock):
    # This is where we consume a block of data and use it to
    # build our pieces

    # Include any necessary globals

    # We need to know how big the block is going to be (we can get that
    # from 'data'. We then want to double check that the message type is
    # the appropriate value (check the specs for the "piece" message value,
    # which is what we're reading right now))
    #piece message: <len=0009+X><id=7><index><begin><block>
    recv = sock.recv(4)
    len_block = data
    len_piece = int.from_bytes(recv, byteorder='big')
    recv = sock.recv(1)
    messid = int.from_bytes(recv, byteorder='big')
    if messid == 7:#tmp, the message value is correct
        # get the index and offset. Read the description of the "piece" message
        # to see how to do this.
        print("Processing piece (block) message...")
        index = sock.recv(4)
        offset = sock.recv(4)
        block = []
        while len(block) < size:# as long as the block is smaller than the expected block size
            data = s.recv(1)
            block.extend(data)
            # continue to receive data from your socket and
            # append it to the block. When the block is the size
            # you're expecting, break out of the loop.
            # You can use len() to check the size of the block.
            if len(block) == size:
                break
        # You've got a block. Now add it to the piece it belongs to. I suggest
        # Making an array of pieces which can be accessed by index.

        # It may also be helpful to keep a record of how many bytes you've gotten
        # in total towards the full file.

        # He's a little report
        print("Got a block (size: {0})\tTotal so far: {1} out of {2}".format(len(block), total_bytes_gotten, total_length))

        # If you haven't fully downloaded a piece, you need to get the next block
        # within the piece. The piece index stays the same, but the offset must
        # be shifted to get a later block. This is done by adding the requested
        # block size to the previous offset.

        if False:# if the resulting offset is still within the same piece,
            # the same piece with the new offset
            pass

        else :# if the new offset is greater than the length of the piece, you
            # must be done with that piece. Since we're just getting pieces in
            # order, you can just go ahead and request the next piece, beginning
            # with an offset of 0. (Of course, if the next index is greater than
            # or equal to the total number of pieces, you are finished downloading
            # and should write your downloaded data to a file).

            if False:# There's still pieces to be downloaded
                # Request the first block of the next piece.
                pass
            else:
                # Join all the elements of the downloaded pieces array using
                # .join()
                outfile = open(output_filename, 'wb')
                # Write the full content to the outfile file

                print("Download complete. Wrote file to {0}".format(output_filename))
                done = True
                sys.exit(1)

def request_piece(peer, sock, index):# You'll need access to the socket,
    # the index of the piece you're requesting, and the offset of the block
    # within the piece.
    # Declare any necessary globals here
    #piece_length
    #req_block_size_int
    #piece_length        = 0 # Size of each piece
    #piece_length_bytes  = 0
    # The piece index and offset will need to be converted to bytes
    # Read the specs for request structure:
    # <len=0013><id=6><index (4 bytes)><begin (4 bytes)><length (4 bytes)>
    offset = total_bytes_gotten
    print("offset " + str(offset))
    length = req_block_size_int
    print("length " + str(length))
    #length = length.to_bytes(10, byteorder='big')
    print("length in bytes")
    print(length)
    print("index " + str(index))

    #last_piece = piece_length > no_of_pieces*
    # Build the request here before sending it into the socket.
    # Length is set as a global at the recommended 16384 bytes. However, the
    # request will be disregarded if there is less data to send than that
    # amount, which is likely to be the case for the final block in the file.
    # For this reason, will probably want to build the request slighly
    # differently for the final block case. Keeping track of the total number
    # of bytes you've collected can be helpful for this.
    # request: <len=0013><id=6><index><begin><length>
    flag = b'!IB'
    flag = bencodepy.encode(flag)
    req = b'\x00\x00\x01\x03\x06\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x40\x00'
    #req = b'\x00\x00\x01\x03\x06' + index.to_bytes(2, byteorder='big') + offset.to_bytes(4, byteorder='big') + b'\x00\x04\x00\x00'#length.to_bytes(4, byteorder='big')

    print("*** LENGTH PORTION ***")
    lenmess = str(length).encode()
    print(lenmess)
    print("***REQUEST MESSAGE***")
    print(req)

    # Send the request:
    sock.send(req)
    get_block(peer, length, sock)


# this function is used to make a request to the remote tracker server.
# the tracer server listens for a request of a given torrent
# if the tracker has a record for the torrent,
# then the tracker will respond with a "map" of peers that have the desired
# torrent "pieces" available
# note, if parameters are sent to the script via an HTTP GET request (a question mark appended to the URL, followed by param=value pairs; in the example, ?and=a&query=string)
# example, ?and=a&query=string
def tracker_req(btdata, info_hash):

    # XXX test print XXX
    # print('\n\nannounce url ::', btdata['announce'])

    # Build the params object. Read the bittorrent specs for tracker querying.
    # The parameters are then added to this URL, using standard CGI methods (i.e. a '?' after the announce URL, followed by 'param=value' sequences separated by '&').
    # https://wiki.theory.org/BitTorrentSpecification#Tracker_HTTP.2FHTTPS_Protocol

    # the uploaded request parameter is used to indicate the number of bytes that have been
    # uploaded to the server,
    uploaded = 0

    # left = total_length_bytes - total_bytes_gotten
    left = btdata['info']['length']/8 - total_bytes_gotten

    # assign request parameter key:value pairs
    reqParams = {'info_hash':info_hash, 'peer_id':peer_id, 'port': local_port, 'uploaded':uploaded, 'downloaded':total_bytes_gotten, 'left': left, 'compact':0, 'event':""} #

    # use the requests library to send an HTTP GET request to the tracker
    response = requests.get(btdata['announce'], params=reqParams)

    # XXX test print XXX
    # print('response : ', response)
    # print('response text :', response.text)
    # print('response directory :', dir(response))
    # print('response content :', response.content)

    # decode response text with bencodepy library.
    decoded_response_content = bencodepy.decode(response.content)

    # XXX test print XXX
    # print('\nbencodepy.decoded response content', decoded_response_content)

    # decoded_dict builder for housing the decoded-data that makes up the repsonse dictionary
    decoded_dict = {}

    # for each of the key:value pairs in the OrderedDict, try to decode both the key and the value
    # finally, append the results to the builder dictionary : decoded_dict
    for x,y in decoded_response_content.items():

        # decode the key, utf-8
        x = x.decode('UTF-8')
        # try to decode the value associated with the key...
        try:
            y = y.decode('UTF-8')
        except AttributeError:
            # if we can't decode the value, just pass it for now
            pass
        decoded_dict[x] = y

    # XXX test print XXX
    # print('\ndecoded dict : ', decoded_dict)

    # decode the array elements that exist as the value for the 'url-list' key in the decoded_dict
    for x, member in enumerate(decoded_dict['peers']):
        # peer builder
        peer_builder = {}

        # for the key:value pairs in the peer section of the decoded-dictionary
        for i,j in decoded_dict['peers'][x].items():

            # decode the key, utf-8
            i = i.decode('UTF-8')
            # try to decode the value, pass if it's an int or not containing 'peer'
            if isinstance(j, int):
                pass
            elif 'peer' not in i:
                j = j.decode('UTF-8')
            else :
                pass

            # add data about the peer to the temporary peer_builder
            peer_builder[i] = j

            # XXX test print XXX
            # print(x,i,j)

        # TODO :
        # need to decode the peer_id values that are returned in the tracker's response :
        # decode_pid = bencodepy.decode(peer_builder['peer id'])
        # print('peer builder ID ::::', bencodepy.decode(peer_builder['peer id']))
        # print('peer builder ID ::::', peer_builder['peer id'].decode('UTF-8'))
        # print('peer builder ID ::::' + peer_builder['peer id'])
        # bbb = peer_builder['peer id'].decode("utf-8")
        # bbb = bencodepy.decode(peer_builder['peer id'])
        # decode_pid = peer_builder['peer id'].decode('latin-1')

        # XXX test print XXX
        # print(decode_pid)

        # append the peer_connection to the list
        peer_connections.append(PeerConnection(peer_builder['ip'], peer_builder['port'], peer_builder['peer id'].decode('latin-1')))

    # XXX test print XXX
    # print(peer_connections)

    # The tracker responds with "text/plain" document consisting of a bencoded dictionary

    # bencodepy is a library for parsing bencoded data:
    # https://github.com/eweast/BencodePy
    # read the response in and decode it with bencodepy's decode function

    # Once you've got the dictionary parsed as "tracker_data" print out the tracker request report:
    report_tracker()

# the purpose of this is to produce the info_hash variable, which is requisite in the
# request for the tracker server
def get_info_hash(btdata):
    # https://docs.python.org/3/library/hashlib.html
    # get the info directory, re-encode it into bencode, then encrypt it with
    # SHA1 using the hashlib library and generate a digest.

    # XXX test print XXX
    # print("\n\n::::::btdata backup  : \n\n", btdata_backup, "\n\n")
    # print("\n\n::::::INFO btdata backup  : \n\n", btdata_info_backup, "\n\n")

    # XXX test print XXX
    # print('re-encoded : ', btdata['info'])

    # first, encode info_dictionary in bencode before encrypting using sha1
    encoded_info_dictionary = bencodepy.encode(btdata_info_backup)

    # XXX test print XXX
    # print('encoded info dictionary : ', encoded_info_dictionary)

    # encrypt the encoded_info_dictionary using sha1 & generate sha1 hash digest
    digest_builder = hashlib.sha1()
    digest_builder.update(encoded_info_dictionary)
    digest_builder = digest_builder.digest()

    # XXX test print XXX
    # print('digest builder : ', digest_builder,'\n\n')

    return digest_builder

def get_data_from_torrent(arg):
    # https://github.com/eweast/BencodePy
    global torrent_data
    # try to parse and decode the torrent file...
    try:

        # assign file_path based on the command line arg/param
        file_path = arg

        # call the decode_from_file() function that's a member of the bencodepy class`
        btdata = bencodepy.decode_from_file(file_path)

        # store the fresh, bencodepy decoded data in the global scope
        global btdata_backup
        btdata_backup = btdata

        # XXX test print XXX
        # print("\n\n::::::btdata backup  : \n\n", btdata_backup, "\n\n")

        # next, build the decoded dictionary through a series of iterative statements within the btdata OrderedDict object
        # the "builder" variable used for this we'll call decoded_dict
        decoded_dict = {}

        # for each of the key:value pairs in the OrderedDict, try to decode both the key and the value
        # finally, append the results to the builder dictionary : decoded_dict
        for x,y in btdata.items():

            # decode the key
            x = x.decode('UTF-8')
            # try to decode the value associated with the key...
            try:
                y = y.decode('UTF-8')
            except AttributeError:
                # if we can't decode the value, just pass it for now
                pass
            decoded_dict[x] = y

        # decode the array elements that exist as the value for the 'url-list' key in the decoded_dict
        for x, member in enumerate(decoded_dict['url-list']):
            decoded_dict['url-list'][x] = decoded_dict['url-list'][x].decode('UTF-8')

        # decode the array elements that exist as the value for the 'announce-list' key in the decoded_dict
        # this has another layer of complexity compared to decoding the elements in the 'url-list', this is
        # because some of the elements of the decoded_dict['announce-list'] are arrays themselves, need a nested loop :
        for x, member in enumerate(decoded_dict['announce-list']):
            for y, member in enumerate(decoded_dict['announce-list'][x]):
                decoded_dict['announce-list'][x][y] = decoded_dict['announce-list'][x][y].decode('UTF-8')


        # store freshly bencodepy decoded info-ordered-dictionary
        global btdata_info_backup
        btdata_info_backup = decoded_dict['info']

        # decode the (sub)ordered-dictionary that exists as a value corresponding to the 'info' key inside the decoded_dict dictionary
        # access this (sub)ordered-dictionary with : decoded_dict['info']
        # use the appendage_dict={} in order to temporarily store the sub-ordered-dictionary, this will be appended to the decoded_dict at the correct 'info' key after traversal
        appendage_dict = {}
        for x, y in decoded_dict['info'].items():

            # decode the key
            x = x.decode('UTF-8')
            # try to decode the value associated with the key...
            try:
                # we don't want to decode the value at the pieces key... this is a byte string
                if x != 'pieces':
                    y = y.decode('UTF-8')

            except AttributeError:
                # if we can't decode the value, just pass it for now
                pass

            # append the key:value pair to the dictionary
            appendage_dict[x] = y

        # append the appendage_dict to the 'info' key of the decoded_dict dictionary, the same place where it came encoded from
        decoded_dict['info'] = appendage_dict

        # XXX test print XXX
        # print(decoded_dict)
        # XXX test print XXX

        # Do what you need to do with the torrent data.
        # You'll probably want to set some globals, such as
        # total_length, piece_length, number of pieces (you'll)
        # need to calculate that) etc. You might want to give
        # file_array its initial value here as an array of
        # empty binary sequences (b'') that can later be appended
        # to. There may be other values you want to initialize here.

        # instantiate an object to have the TorrentData class type
        # assign all of the key:value pairs to correspond to the relevant bit_torrent data
        # note : the number of pieces is thus determined by 'ceil( total length / piece size )'
        torrent_data = TorrentData(\
            decoded_dict['info']['name'],\
            decoded_dict['info']['length'],\
            decoded_dict['info']['length']/8,\
            decoded_dict['info']['piece length'],\
            decoded_dict['info']['piece length']/8,\
            math.ceil(decoded_dict['info']['length']/decoded_dict['info']['piece length']),\
            decoded_dict['announce'])

        #  XXX test print XXX
        # print('total length : ', total_length)
        # print('piece length : ', piece_length)
        # print('piece length bytes : ', piece_length_bytes)
        # print('number of pieces :', no_of_pieces)
        # print('announce url :', announce_url)
        # print('output file name : ', output_filename)
        # print(decoded_dict['info']['pieces'])
        # print('type :', type(decoded_dict['info']['pieces'])) # type of
        #  XXX test print XXX

        # reporting torrent :
        report_torrent(torrent_data)

    except:
        print('Failed to parse input. Usage: python btClient.py torrent_file"\ntorrent_file must be a .torrent file')
        sys.exit(2)

    return decoded_dict


# note : i modified professor mullen's original function to accept a TorrentData-type object
# as the parameter—this is a class defined above. instead of reporting data from the global
# variables assiciated with this program, read datas that are associated with the TorrentData object
def report_torrent(torrent_data):
    # Nothing special here, just reporting the data from
    # the torrent. Note the Python 3 format syntax

    # assume that the number of files in the torrent is "one"
    no_of_files = "one"

    print("\nAnnounce URL: {0}".format(torrent_data.announce_url))
    print("Name: {0}".format(torrent_data.output_filename))
    try:
        print("Includes {0} files".format(no_of_files))
    except:
        print("Includes one file")
    print("Piece length: {0}".format(torrent_data.piece_length))
    print("Piece len (bytes): {0}".format(torrent_data.piece_length_bytes))
    print("Total length: {0} ({1} bytes)".format(torrent_data.total_length, torrent_data.total_length_bytes))
    print("Number of pieces: {0}".format(torrent_data.no_of_pieces))

# report_tracker() is used to report peer information
def report_tracker():
    for p in peer_connections: # peer array returned by tracker
        print ("Peer: {0} (ip addr: {1})".format(p.pid, p.ip)) #
# main
if __name__=="__main__":
    main()
