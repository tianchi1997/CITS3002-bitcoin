#NAMES_FILE="names.csv"
#Miner acts as server.
#Message: Separated by commas
import socket as Sock
from socket import *
import hashlib
import random
import rsa
import pickle
import queue
import csv
import time
import os
import signal
import ssl
import threading
#NONCE_LENGTH=4
QUEUE_MAXSIZE=10
BLOCK_NAME='blockchain.csv'
pow_Q=queue.Queue(QUEUE_MAXSIZE)
notify_Q=queue.Queue(QUEUE_MAXSIZE)

names_list=[]
def csvWriter(filename, newEntry):

    with open(filename, mode='a', newline='') as f:
        Writer = csv.writer(f)
        Writer.writerow(newEntry)


def csvReWriter(filename, Entries):
    with open(filename, mode='w', newline='') as f:
        Writer = csv.writer(f)
        Writer.writerows(Entries)

def csvReader(filename):
    data = []
    dataReader = csv.reader(open(filename, newline=''))
    try:
        for row in dataReader:
            data.append(row)
    except csv.Error as e:
        print(e)
        exit(1)
    return data


def storeUser(name,publickeyS):
    print("Storing User")
    global names_list
    #determine if user already exists, else add.
    for i in range(0,len(names_list)):
        if names_list[i][0]==name:
            print("Did not store User, Name Already Exists")
            return (False,"Name :"+ name + ", is taken")
        elif names_list[i][1]==publickeyS:
            print("Did not store User, Already Exists")
            return (False,"User Exists Under Name :"+names_list[i][0])
    names_list.append([name,publickeyS])
    return (True,"Successfully Added User :"+str(publickeyS) + " as :" + name)


def removeUser(publickeyS):
    global names_list
    name=''
    for i in range(len(names_list)):
        if names_list[i][1]==publickeyS :
            names_list.remove([names_list[i][0],publickeyS])
            print("Removed User")
            break


def listNames():
    global names_list
    response = ""

    for i in range(0,len(names_list)):
        if i != len(names_list)-1:
            response += names_list[i][0]+",,,"
        else :
            response += names_list[i][0]
    print("Listing Names")
    return response


def send_msg(c, m_type, nonce="", msg="") :
    #sending a transaction
    if m_type == 0:
        message = '0,,,' + msg
        c.send(message.encode("utf-8"))
        print("Message type 0 sent")
    elif m_type == 1:
        message = '1,,,'+nonce+',,,'+ msg
        c.send(message.encode("utf-8"))
        print("Message type 1 sent")
        #waits for a reply of successful transaction or server busy
    elif m_type ==2:
        message = '2,,,'+msg
        c.send(message.encode("utf-8"))
        print("Message type 2 sent")
    else:
        message='3,,,'+msg
        c.send(message.encode("utf-8"))
        print("Message type 3 sent")


def generate_nonce(length=8):
    #   print("Generating Nonce")
    return ''.join([str(random.randint(0,9))for i in range(length)])


def proof_of_work(message):
    start_time=time.time()
    m=hashlib.new('sha256')
    testLen=8
    strZero='00000000'
    altered=False
    while m.hexdigest()[:testLen]!=strZero:
        if not altered:
            if time.time()-start_time > 110:
                #if after 110 seconds we can't find an 8-long POW, do a four long pow.
                print("pow too difficult, making easier")
                testLen=4
                strZero='0000'
                altered=True

        nonce=bytes(generate_nonce(32),'utf-8')
        msg=message.encode('utf-8')
        m = hashlib.new('sha256')
        m.update(msg+nonce)
        #print(nonce)
        #  print(m.hexdigest()[:3 ])
        # print("swag : "+str(nonce))

    print("Work Complete, Nonce Generated")
    return nonce


def proof_of_work_handler():
    while True:
        try:

            temp=pow_Q.get()
            print("Found some work to prove: ",end="")
            print(temp, end=" ")
            print(temp[0])
            nonce=proof_of_work(temp[0])
            complete_Transaction(temp,nonce)
        except queue.Empty:
            print("Proof of work thread sleeping, empty queue")
            #sleep for 10s if queue empty.
            time.sleep(10)


#Proof of concept for T
def verify_nonce(message,nonce):
    m=hashlib.new('sha256')
    m.update(message.encode('utf-8')+nonce)
    if m.hexdigest()[:2]=='00':
        return True
def verify_signature(msg,publicKeyS,sig):
    print("Verifying Signature")
    public_key=pickle.loads(publicKeyS)
    signature=pickle.loads(sig)
    if rsa.verify(msg.encode('utf-8'),signature,pub_key=public_key):
        return True
    print("Signature failed to verify for {:}".format(publicKeyS))
    return False

def complete_Transaction(temp,nonce):
    print("Completing Transaction")
    c=temp[1]
    msg=temp[0].split(',,,')
    to_send=msg[1]+',,,'+msg[2]+',,,'+msg[3]
    send_msg(c,1,nonce=nonce.decode("utf-8"),msg=to_send)
    try:
        print('Placing on queue to notify')
        notify_Q.put([c,1,nonce,msg[1:],msg[2]])
        write_to_blockChain(msg[1],msg[2],msg[3])
        #csvWriter(BLOCK_NAME,msg[1:])

    except queue.Full:
        print("notification_Queue is full. This shouldn't have been possible")

def write_to_blockChain(sender,recvr,amount):
    global BLOCK_NAME
    #make sendr recvr their pub keys.
    for i in range(0,len(names_list)):
        if names_list[i][0]==sender:
            sender=names_list[i][1]
        elif names_list[i][0]==recvr:
            recvr=names_list[i][1]
    Blkchain=csvReader(BLOCK_NAME)
    prevHash=Blkchain[len(Blkchain)-1][3]
    msg=sender+recvr+amount.encode("utf-8")
    hash=hash_blockchain(prevHash,msg)
    csvWriter(BLOCK_NAME,[sender,recvr,amount,hash])


def hash_blockchain(prev,message):
    m=hashlib.new('sha256')
    msg=prev.encode("utf-8")+message
    m.update(msg)
    return m.hexdigest()

def notification_Available(name):
    print("checking notifications for user:" +name)
    try:
        temp=notify_Q.get()
    except queue.Empty:
        print("Notify queue empty")
        return False
    print(temp)
    if temp[4]==name:
        return temp[:4]
    else:
        notify_Q.put(temp)
    return False

def notify_Handler(c,name):
    print("notifyHandler Running for user")
    while True:
        if listNames().count(name)<=0:
            #Usr has disconnected, break out of infinite loop so thread ends
            break
        note = notification_Available(name)
        # convoluted !=False because notification returns the msg or False.
        if note != False and name != '':
            print("Sending Notification Message")
            message = note[3][0]+',,,' + note[3][1]+',,,' + note[3][2]
            send_msg(c, note[1], nonce=note[2].decode("utf-8"), msg=message)
        else:
            print("no notification available")
        print("Notify Handler Sleeping 10s")
        time.sleep(10)

def clientHandler(s):
    def wrapper():
        c, addr = s.accept()
        c = ssl.wrap_socket(c,
                                           server_side=True,
                                           certfile="./ca.crt",
                                           keyfile="./ca.key",
                                           cert_reqs=ssl.CERT_NONE,
                                           do_handshake_on_connect=True,
                                           suppress_ragged_eofs=True,
                                           ciphers="SSLv3")
        print("Cipher in use :",end="")
        print(c.cipher())
        publicKeyS=''
        name=''
        print("connection from: :" + str(addr))
        try:
            while True:
                data = c.recv(1024)

                data=data.decode("utf-8")
                # end connnection if client conn end.
                if not data:
                    print("Breaking")
                    break
                dataA=data.split(',,,')
                print(dataA)

                #if message type 0, name is given straight away, wait for pubKey
                if dataA[0]=='0':
                    if len(dataA)==2:
                        name=dataA[1]
                        publicKeyS=c.recv(4096)
                        response=storeUser(dataA[1],publicKeyS)
                        if response[0]:
                            #Start watching for incoming Tsct
                            threading.Thread(target=notify_Handler,args=(c,name)).start()

                            print(response[1])
                            send_msg(c,0,msg="")
                            time.sleep(0.1)
                            send_msg(c, 2, msg=listNames())

                        #if adding to table failed,
                        else:
                            #Failure
                            send_msg(c,3,msg=response[1])
                    #Failure
                    else :
                        send_msg(c,3,msg="")
                        print("failure, too short/long, msg = :"+dataA[2])

                #1:Transaction
                #verify, then put on queue for proof of work.
                elif dataA[0] == '1':
                    if (len(dataA) >= 4):
                        print("Type 1 msg recv")
                        print(names_list[0])

                        if listNames().count(dataA[2])!=1:
                            send_msg(c,3,msg="User Not Online")
                            #throwaway signature
                            c.recv(4096)
                        else:
                            msg=str(dataA[0])+',,,'+str(dataA[1])+',,,'+str(dataA[2])+',,,'+str(dataA[3])
                            sig=c.recv(4096)
                            if verify_signature(msg,publicKeyS,sig):
                                try:
                                    pow_Q.put([msg,c])
                                except queue.Full:
                                    send_msg(c,3,msg="Proof of Work Queue is full, try again later")
                # Request for Users
                # return comma separated names of all users. headed by 2 to indicate msg type.
                elif dataA[0] == '2':
                    send_msg(c, 2, msg=listNames())
        except:
            pass
        finally:
            # when connection closed by client, adjust names list, then close.
            removeUser(publicKeyS)
            c.close()
    return wrapper()

class clientThread(threading.Thread)  :
    def __init__(self,s):
        threading.Thread.__init__(self)
        self.s=s
    def run(self):
            clientHandler(self.s)

def serverProg():
    #Find MY IP
    host = Sock.gethostbyname(Sock.gethostname())

    print("Server Adress: "+str(host))
    port = input("Please enter desired port, >1000 : ")
    threading.Thread(target=commandHandler).start()
    if not port.isnumeric():
        print("desired port must be a number, exiting")
        exit("Problem exists between chair and keyboard")
    if int(port)<1000:
        port=5505
        print("Selected port 5505 for you")
    port=int(port)
    print("Port Selected :"+ str(port))
    threading.Thread(target=proof_of_work_handler).start()
    print("Pow Handler Started")
    s = socket(AF_INET,SOCK_STREAM)
    s.bind((host, port))
    # Listen for five connections
    print("Listening for 5 connections:")
    s.listen()
    ListenThreads=[]
    for i in range(0,5):
        ListenThreads.append(clientThread(s))
        ListenThreads[i].start()
        print("Listen Thread {:} starting".format(i))
        # accept connection
    while True:
        for i in range(0,5):
            try:
                if not ListenThreads[i].is_alive():
                    ListenThreads[i] = clientThread(s)
                    ListenThreads[i].start()
                #print("MY NAME IS JEFF")
            except :
                print(" ERROR ENCOUNTERED, HURRAY")

                print("Re-starting L thread "+str(i))


#main
def commandHandler():
    while True:
        print("Enter Q at any time to exit miner")
        command=input().strip().title()
        if command=='Q':
            break
        #send free Chriscoins to a wallet.
        elif command=='Gift Chriscoins':
            amount=input("amount:")
            reciever=input("reciever:")
            message="1"+",,,"+"Someone Kind"+",,,"+reciever+",,,"+amount
            nonce=proof_of_work(message)
            notify_Q.put(['socket,oops',1,nonce,["Someone Kind",reciever,amount],reciever])
    os.kill(os.getpid(), signal.CTRL_C_EVENT)
def Main():
    serverProg()
if __name__=='__main__':
    Main()
