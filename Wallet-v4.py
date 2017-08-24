#Tianchi Ren - 21722208
#Jelyn Thong - 21659439
#Lachie Black - 21707385
#Terence Leong - 21707741


import rsa
import pickle
import csv
import socket
import time
import threading
import hashlib
import os
import signal
import ssl

#Global Variables
data = [] #data from csvreader
currentuserlist = [] #list of currently connected users
pendingtransactions = 0 #the number of pending transactions
currbalance = 0 #user's balance

#variables for server
sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s=ssl.wrap_socket(sock,server_side=False, cert_reqs=ssl.CERT_NONE,ca_certs=None,do_handshake_on_connect=True, suppress_ragged_eofs=True,ciphers="SSLv3")
#s=sock
IP = '0'
port = 0

#private and public key
privatekey = ""
publickey = ""

#List of other nodes currently connected to the network, updated everytime
def check_current_users():
    global s
    send_msg(2,'0','0','0')
    print("Sent request for user list")
    #


#Generates a signature for a message
def gen_signature(message):
    encodedmsg = message.encode('UTF-8') #encode the message
    signature = rsa.sign(encodedmsg,privatekey,'SHA-256')
    print("Message signed")
    #sign Private key + Message
    return signature

#types : 0 for init, 1 for transaction, 2 for check users
def send_msg(type,sender,receiver,amount) :
    #sending a transaction
    global pendingtransactions
    global name
    if type == 0:
        #initialises the connection by sending the miner name + public key
        pubkey = pickle.dumps(publickey)
        message = '0'+',,,'+str(name)
        s.send(message.encode("utf-8"))
        time.sleep(.1)
        s.send(pubkey)
    elif type == 1:
        time.sleep(.1)
        pendingtransactions +=1 #incremement the number of pending transactions
        message = '1'+',,,'+sender+',,,'+receiver+',,,'+amount
        signature = gen_signature(message)
        #print(signature)
        #print(publickey)
        pickledsig = pickle.dumps(signature)
        #print("sending msg")
        s.send(message.encode('utf-8'))

        time.sleep(.1)
        #print("sending pickledsig")
        s.send(pickledsig)
        print("Signed and sent message to miner")
    elif type ==2:
        message = '2'
        s.send(message.encode("utf-8"))
        print("Check Users Request Sent")

def csvReader(filename):
    global data
    data = []
    dataReader = csv.reader(open(filename, newline=''))
    try:
        for row in dataReader:
            data.append(row)
    except csv.Error as e:
        print(e)
        exit(1)
    #print(data)
def csvWriter(filename,newentry):

    global data
    data.append(newentry)
    with open(filename, mode='a', newline='') as f:
        Writer = csv.writer(f)

        Writer.writerow(newentry)

#verifies the nonce produced by the server
def verify_nonce(message, nonce):
    m = hashlib.new('sha256')
    nonce = nonce.encode('utf-8')
    message = message.encode('utf-8')
    m.update(message + nonce)
    if m.hexdigest()[:4] == '0000':
        return True
        print("Nonce verified")
    print("Bad nonce")
    print(nonce)
    return False

   #receives a successful transaction record from the miner and saves this to the csv file.
    #updates bitcoin balance, and prints it on screen
def save_transaction(sender,receiver,amount,nonce):
    #calculate new balance
    global name
    global currbalance
    if(sender == name):
        currbalance -= int(amount)
        sender=publickey
    elif(receiver == name):
        currbalance += int(amount)
        receiver=publickey
    else :
        print ("Error, transaction not for me")
        return -1
    print( "New Balance: " + str(currbalance))
    # transaction record includes your psuedonym at the time of transaction. this means you can re-confirm the nonce for amount later if you choose, verifying that the file hasn't been altered.
    transaction = [sender,receiver,amount,nonce,currbalance,name]
    print("Transaction : ", end="" )
    print(transaction )
    csvWriter('wallet.csv',transaction)
    print ("transaction saved")

def check_balance():
    global currbalance
    print("balance = " + str(currbalance))


def display_transactions() :
    # prints the transactions when the user requests
    number = int(input("-> How many transactions to display? ->"))
    csvReader('wallet.csv')
    if number > len(data) :
        number = len(data)
    if int(number) == 0 :
        for i in range(0,len(data)):
            #these if statements test whether we are sender or recipient, and fetches our name from the corrrect location
            if len(data[i][0]) < 50:
                sender = data[i][0]
            else:
                sender = data[i][5]
            if len(data[i][1]) <50:
                receiver = data[i][1]
            else:
                receiver = data[i][5]
            print("Sender: " + sender + ", Receiver: " + receiver + ", Amount: " + data[i][2] + ", Nonce: " + data[i][3])
    else :
        for i in range(len(data)-number,len(data)) :
            # these if statements test whether we are sender or recipient, and fetches our name from the corrrect location
            #assumes that anything above 50 is a public key
            if (len(data[i][0]) < 50):
                sender = data[i][0]
            else:
                sender = data[i][5]
            if len(data[i][1]) < 50:
                receiver = data[i][1]
            else:
                receiver = data[i][5]
            print(
                "Sender: " + sender + ", Receiver: " + receiver + ", Amount: " + data[i][2] + ", Nonce: " + data[i][3])



    #0 means print everything
def display_users(UsrList):
    for name in UsrList:
        print(name, end=" \t")
    print("\n",end="")
def helpme():
    print("Available Commands :")
    print("Display Transactions \t Displays x transactions")
    print("Check Balance \t Displays available ChrisCoin")
    print("Send Chriscoins \t interactively begins a transaction")
    print("Help \t displays this menu")
    print("Check Users \t Lists online users")
    print("Q \t to Quit")
    # lists the possible functions that can be called
    return
def init():
    # check for keys, if there are none then generate keys
    print("Getting keys")
    try:

        with open('private.pem', mode='rb') as privatekeyfile:
            global privatekey
            privatekey = pickle.load(privatekeyfile)
            print(privatekey)
            privatekeyfile.close()
        with open('public.pem', mode='rb') as publickeyfile:
            global publickey
            publickey = pickle.load(publickeyfile)
            print(publickey)
            publickeyfile.close()
    except FileNotFoundError:

        print("No key found, creating keys")
        (publickey, privatekey) = rsa.newkeys(2048)
        with open('private.pem', mode='wb') as f:
            pickle.dump(privatekey, f)
            f.close()
        with open('public.pem', mode='wb') as f2:
            pickle.dump(publickey, f2)
            f2.close()

    global s
    global name
    global IP
    global port
    global currbalance
    global data
    global sock
    #establish a connection to the server (miner)
    name = input("Specify your name : ")

    IP = input("Miner's IP : ")
    port = int(input("Port :"))
    connected = False
    tries = 5
    while connected == False :
        print("Trying to connect to miner")
        try :
            s.connect((IP,port))
            print("Connected to miner")
            connected = True
        except socket.error :
            tries-= 1
            if tries <= 0 :
                print("Cannot find server, exiting")
                exit(1)
            print("Failed to find server, please enter alternative, or q to quit ")
            inp = input("New host IP :")
            if inp == "q" :
                exit(0)
            else :
                IP = inp
            inp2 = int(input("New port :"))
            if inp == "q" :
                exit(0)
            else :
                port = inp2

    # the wallet will also send the server its name and public key
    send_msg(0, '0', '0', '0')
    csvReader('wallet.csv')
    currbalance = int(data[len(data)-1][4])

    #Once connected, server will send back a list of currently connected users, same as check_current_users.
def notifications():
    global s
    global name
    while True:
        data = s.recv(1024)
        #print("Message received from server")
        data=data.decode("utf-8")
        dataA=data.split(',,,')
        #Init Acknowledged
        if dataA[0]=='0':
            print("Successful Init")
        #Transaction Notification
        elif dataA[0]=='1':
            nonce = dataA[1]
            sender = dataA[2]
            receiver = dataA[3]
            amount = dataA[4]
            message = dataA[0] + ',,,' + sender + ',,,' + receiver + ',,,' + amount
            # verify the nonce
            verify = verify_nonce(message, nonce)
            if verify:
                save_transaction(sender, receiver, amount, nonce)
                #Reciever of a tnsct
            else:
                print("failed to verify message")
                #just sent tnsct, success
        #User list reply
        elif dataA[0]=='2':
            currentuserlist=dataA[1:]
            display_users(currentuserlist)
        #Notification of Failure
        else:
            if len(dataA)>=2:
               # print(dataA)
                if dataA[1][:4] == 'Name':
                    name = input("please enter a new name :")
                    send_msg(0,0,0,0)
                elif dataA[1][:8]=='User Not':
                    print("user not online")
                elif dataA[1][:4] == 'User':
                    print("public key is already online, exiting")
                    exit()
            print(dataA)
            #Error, Print out to usr.
    print("Type 'help' for list of commands ")
def Main():
    #program enters an infinite event loop that handles inputs from the user
    init()
    execute = True
    n_thread=threading.Thread(target=notifications).start()
    global currentuserlist
    while execute :
        #sleep here ensures -> comes up below any responses if at all possible.
        time.sleep(.1)
        commands = str(input("-> ").strip())
        commands=commands.title()
        if(commands == "Display Transactions") :
            display_transactions()
        elif commands == "Check Balance":
            check_balance()
        elif commands == "Send Chriscoins" or commands=="Send Chriscoin" :
            if pendingtransactions >= 5 :
                print("Too many pending transactions")
            else:
                amount = input("->How many Chriscoins? -> ")
                if float(amount) > currbalance :
                    print("You can't afford that")

                elif not amount.isnumeric():
                    print("amount to send must be a number, Try again")

                else :
                    recv = str(input("->Amount->Recipient->").strip('\n'))
                    send_msg(1,name,recv,amount)
        elif commands == "Help" :
            helpme()
            #displays the list of possible function calls
        elif commands == "Check Users" :
            check_current_users()
        elif commands == "Q" :
            execute = False

        else :
            print("Invalid command")
    print ("Leaving Program")
    s.close()
    os.kill(os.getpid(),signal.CTRL_C_EVENT)
#start running the program

if __name__=='__main__':
    Main()
