import hashlib
def crack(user,salt, hash):
    #check the empty string how does it react with concat in a list
    list = ["", "0", "1", "2", "3", "4", "5", "6", "7", "8", "9"]

    for digit1 in list:
        for digit2 in list:
            for digit3 in list:
                for digit4 in list:
                    for digit5 in list:
                        for digit6 in list:
                            for digit7 in list:
                                for digit8 in list:
                                    guess = digit1 + digit2 + digit3 + digit4 + digit5 + digit6 + digit7 + digit8
                                    wantToHash = user + "," + guess + "," + salt
                                    currHash = hashlib.sha256(wantToHash.encode()).hexdigest()
                                    if currHash == hash:
                                        print("password for "+user+":" ) 
                                        print(guess)
                                        return

hashVal1 = "c9808f6d88ffb8089d44b903aed1e09be2d7432be46db8c06c273ca65a0e6fe7"
user1 = "mazharul"
salt1 = "20193833"
crack(user1,salt1,hashVal1)
user = "suleman"
salt = "20202293"
hashVal = "53b8da235e6ab04edfe2d73dfd976d4ab26e2bf4e356840ca8104c24a22af139"
crack(user,salt, hashVal)
#guess = "11232020" this is for mazharul
#guess = "63953293" this is for suleman

#wantToHash = user + "," + guess + "," + salt
#h = hashlib.sha256(wantToHash.encode()).hexdigest()
#if h == hashVal:
    #print("burger")
# do this in the virtual eniv to check that we run on the same thingy
