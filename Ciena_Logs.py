import ipaddress
import time
import paramiko
import datetime
import tkinter
from tkinter import *
from threading import Thread
import yaml

with open('credentials.yaml', 'r') as f:
    load = yaml.load(f, Loader=yaml.Loader)

bpo_username = load['BPO']['username']
bpo_password = load['BPO']['password']
saos_username = load['SAOS']['username']
saos_password = load['SAOS']['password']
dnfvi_username = load['DNFVI']['username']
dnfvi_password = load['DNFVI']['password']


def trylogin(ip, SAOS):
    """
    Test device reachability
    :param ip: SAOS IP
    :return: ssh object
    """
    global bpo_username, bpo_password, saos_username, saos_password

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    Store = ''

    try:
        ssh.connect('100.111.4.17', username=bpo_username, password=bpo_password)
        time.sleep(3)
        chan = ssh.invoke_shell()
        chan.send('ping -c 3 -w 1 ' + ip + '\n')
        time.sleep(5)
        stdout = chan.recv(9999)
        print_out = stdout.decode('utf-8')

        if ', 0% packet loss' not in print_out:
            print(f'\n{SAOS} Device Down\n')
            print(
                f"Can't connect to {SAOS} device because it's down or facing drops, restart VPN and run again. "
                f"if not working use backup to access manually\n+++++++++++++++")
            if SAOS != 'primary':
                print(f"can't collect  {SAOS} device logs")
                input(f'####################\n\npress enter to exit\n')
                quit()
            else:
                print(f"can't collect  {SAOS} logs")
                return 'down', 'down'
        else:
            print(f'\n####################\n\n{SAOS} Device is Reachable from BPO\n')
            vmtransport = ssh.get_transport()
            dest_addr = (ip, 22)
            local_addr = ('100.111.4.17', 22)
            vmchannel = vmtransport.open_channel("direct-tcpip", dest_addr, local_addr)
            jhost = paramiko.SSHClient()
            jhost.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            jhost.connect(saos_ip, username=saos_username, password=saos_password, sock=vmchannel)
            ch = jhost.invoke_shell()
            ch.send('\n')
            time.sleep(1)
            buff = ''
            buff = ch.recv(9999999)
            x = buff.decode('utf-8')
            try:
                StoreNo = re.search(r'LOWE.*[0-9][0-9][0-9][0-9]', x).group(0)
                BoxNo = re.search(r'0[1-2]S>', x).group(0)
                if '1' in BoxNo:
                    Store = StoreNo + '_PRI'
                elif '2' in BoxNo:
                    Store = StoreNo + '_SEC'
            except:
                Store = ip

    except paramiko.AuthenticationException:
        print("[-] Authentication Exception! ... please connect to dayton ...")

    except paramiko.SSHException:
        print("[-] SSH Exception! ... please connect to dayton ...")

    return ssh, Store


def connect_saos(ip, vm, Store):
    """
    connect to device and collect state dump
    :param ip: SAOS IP
    :return: none
    """
    global bpo_username, bpo_password, saos_username, saos_password

    ftp_ip = '100.111.4.17'
    ftp_username = bpo_username
    ftp_password = bpo_password
    ftp_protocol = 'sftp-server'
    server = 'BPO'

    print('####################\n\nConnecting to SAOS\n')
    vmtransport = vm.get_transport()
    dest_addr = (ip, 22)
    local_addr = ('100.111.4.17', 22)
    vmchannel = vmtransport.open_channel("direct-tcpip", dest_addr, local_addr)
    jhost = paramiko.SSHClient()
    jhost.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    jhost.connect(saos_ip, username=saos_username, password=saos_password, sock=vmchannel)
    print('####################\n\nConnected to SAOS\n')
    print('####################\n\nCollecting SAOS Logs\n')

    ch = jhost.invoke_shell()
    ch.send('system shell set global-more off\n')
    time.sleep(0.3)
    ch.send('config save\n')
    time.sleep(0.3)
    ch.send('port show \n')
    time.sleep(0.5)

    for p in range(1, 7):
        ch.send(f'port show port {p} statistics active\n')
        time.sleep(0.5)
        ch.send(f'port show port {p} statistics active\n')
        time.sleep(0.5)
    for p in range(1, 5):
        ch.send(f'port show port i{p} statistics active\n')
        time.sleep(0.5)
        ch.send(f'port show port i{p} statistics active\n')
        time.sleep(0.5)

    ch.send('port sh statistics active \n')
    time.sleep(0.5)
    ch.send('port show throughput active count 5\n')
    time.sleep(20)
    ch.send('flow mac show\n')
    time.sleep(0.5)
    ch.send('flow mac show\n')
    time.sleep(0.5)

    for p in range(1, 7):
        ch.send(f'traffic-services queuing egress-port-queue-group show port {p} statistics\n')
        time.sleep(0.5)
        ch.send(f'traffic-services queuing egress-port-queue-group show port {p} statistics\n')
        time.sleep(0.5)
    for p in range(1, 5):
        ch.send(f'traffic-services queuing egress-port-queue-group show port i{p} statistics\n')
        time.sleep(0.5)
        ch.send(f'traffic-services queuing egress-port-queue-group show port i{p} statistics\n')
        time.sleep(0.5)

    ch.send('broadcast-containment show\n')
    time.sleep(0.5)
    ch.send('broadcast-containment show\n')
    time.sleep(0.5)

    buff = ''
    buff = ch.recv(9999999)
    x = buff.decode('utf-8')
    t = datetime.datetime.now().strftime("%Y-%m-%d_%H.%M")

    with open(f'{Store}_SAOS_output_{t}.txt', 'w') as f:
        f.write(x)
        buff = ''
        print(f'####################\n\nSAOS Logs Collected .. Please Check {Store}_SAOS_output_{t}.txt file\n')
    t = datetime.datetime.now().strftime("%Y%m%d_%H:%M")
    ch.send(
        f"system state-dump include-datapath include-corefiles {ftp_protocol} {ftp_ip} file-name "
        f"'{Store}_SAOS_State_Dump_{t}' login-id {ftp_username} echoless-password\n")
    time.sleep(0.5)
    buff = ch.recv(9999999)
    x = buff.decode('utf-8')
    print('####################\n\nCollecting SAOS State-Dump\n')
    ps = 0
    spb = ''
    while 'Enter Password:' not in x:
        buff += ch.recv(9999999)
        x = buff.decode('utf-8')
    ch.send(f'{ftp_password}\n')
    buff = ''
    buff = ch.recv(9999999)
    x = buff.decode('utf-8')

    while 'State-dump finished' not in x:
        buff += ch.recv(9999999)
        x = buff.decode('utf-8')
        if ps in range(0, 100):
            print(f'SAOS SD In Progress....: |{spb}|{ps}%')
            ps += 7
            spb += '##'
        elif ps not in range(0, 100):
            print('SAOS SD In Progress....: |##################################|99%')
        time.sleep(5)
    print('SAOS SD is Complete....: |##################################|100%')
    SSD = tkinter.Tk()
    SSD.title("SAOS STATE DUMP LOGS")
    Ssbar = tkinter.Scrollbar(SSD)
    Ssbar.pack(side=tkinter.RIGHT, fill=Y)
    STxt = tkinter.Text(SSD, height=500, width=350, yscrollcommand=Ssbar.set)
    STxt.pack(expand=0, fill=tkinter.BOTH)
    STxt.insert(tkinter.END, x)
    Ssbar.config(command=STxt.yview())
    SSD.geometry("1366x758")
    jhost.close()
    print(
        f'####################\n\nSAOS State-Dump Collection has been completed, Please check {server} to collect file\n'
        f'Check the Output Log Window & Close it to proceed')
    SSD.mainloop()


def connect_dnfvi(dnfvi_ip, vm, Store):
    """
    connect to dnfvi, collect state dump and commands
    :param ip: Dnfvi IP, vm
    :return:
    """
    global bpo_username, bpo_password, dnfvi_username, dnfvi_password
    ftp_ip = '100.111.4.17'
    ftp_username = bpo_username
    ftp_password = bpo_password
    ftp_protocol = 'scp'
    extension = '://100.111.4.17/home/bpadmin/'
    server = 'BPO'

    print('####################\n\nConnecting to DNFVI\n')
    try:
        vmtransport = vm.get_transport()
        dest_addr = (dnfvi_ip, 830)
        local_addr = ('100.111.4.17', 22)
        vmchannel = vmtransport.open_channel("direct-tcpip", dest_addr, local_addr)
        jhost = paramiko.SSHClient()
        jhost.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        jhost.connect(saos_ip, username=dnfvi_username, password=dnfvi_password, sock=vmchannel)
        print('####################\n\nConnected to DNFVI\n')

        ch = jhost.invoke_shell()
        print('####################\n\nCollecting DNFVI Logs\n')

        # Commands

        jhosttrans = jhost.get_transport()
        dest_addr2 = ('dnfvi', 22)
        local_addr2 = (dnfvi_ip, 830)
        jhostchannel = jhosttrans.open_channel('direct-tcpip', dest_addr2, local_addr2)
        jhost2 = paramiko.SSHClient()
        jhost2.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        jhost2.connect('dnfvi', username=dnfvi_username, password=dnfvi_password, sock=jhostchannel)
        ch = jhost2.invoke_shell()
        ch.send('sudo su\n')
        buff = ''
        time.sleep(1)
        ch.send('docker exec cn_cnfp_1 cnfp-dbg dump mac 0 line all\n')
        time.sleep(0.5)
        ch.send('docker exec cn_cnfp_1 cnfp-dbg dump mac 0 line all\n')
        time.sleep(0.5)
        ch.send('docker exec cn_cnfp_1 cnfp-dbg getif 0 all\n')
        time.sleep(0.5)
        ch.send('docker exec cn_cnfp_1 cnfp-dbg getif 0 all reset\n')
        time.sleep(0.5)
        ch.send('docker exec cn_cnfp_1 cnfp-dbg getif 0 all\n')
        time.sleep(0.5)
        ch.send('docker exec cn_cnfp_1 cnfp-dbg getif 0 all\n')
        time.sleep(0.5)
        ch.send('docker exec cn_cnfp_1 cnfp-dbg searchc 0\n')
        time.sleep(0.5)
        ch.send('docker exec cn_cnfp_1 cnfp-dbg searchc 0 reset\n')
        time.sleep(0.5)
        ch.send('docker exec cn_cnfp_1 cnfp-dbg searchc 0\n')
        time.sleep(0.5)
        ch.send('docker exec cn_cnfp_1 cnfp-dbg searchc 0\n')
        time.sleep(0.5)
        ch.send('docker exec cn_cnfp_1 cnfp-dbg searchc 0\n')
        time.sleep(0.5)
        buff = ch.recv(999999)
        x = buff.decode('utf-8')
        t = datetime.datetime.now().strftime("%Y-%m-%d_%H.%M")
        with open(f'{Store}_DNFVI_output_{t}.txt', 'w') as f:
            f.write(x)
            print(f'####################\n\nDNFVI Logs Collected .. Please Check {Store}_DNFVI_Output_{t}.txt file\n')
        ch.send('exit\n')
        jhost2.close()

        # State dump
        t = datetime.datetime.now().strftime("%Y%m%d_%H.%M")
        print('####################\n\nCollecting DNFVI State-Dump\n')
        ch = jhost.invoke_shell()
        buff = ''
        ch.send('sudo -i\n')
        time.sleep(0.5)

        ch.send(
            f"cn-state-dump --username {ftp_username} --timeout 120 --filename '{Store}_DNFVI_State_Dump_{t}"
            f"' --targetpath {ftp_protocol}{extension}\n")
        time.sleep(1)
        buff = ch.recv(9999999)
        x = buff.decode('utf-8')
        pd = 0
        dpb = ''
        while 'Enter remote password for authentication' not in x:
            buff += ch.recv(9999999)
            x = buff.decode('utf-8')
            time.sleep(1)
        ch.send(f'{bpo_password}\n')
        buff = ''
        buff = ch.recv(9999999)
        x = buff.decode('utf-8')
        while ' Process Completed!!!' not in x:
            buff += ch.recv(9999999)
            x = buff.decode('utf-8')
            if pd in range(0, 100):
                print(f'DNFVI SD In Progress...: |{dpb}|{pd}%')
                pd += 3
                dpb += '#'
            elif pd not in range(0, 100):
                print('DNFVI SD In Progress...: |##################################|99%')
            time.sleep(5)
        print('DNFVI SD is Complete...: |##################################|100%')
        DSD = tkinter.Tk()
        DSD.title("DNFVI STATE DUMP LOGS")
        Dsbar = tkinter.Scrollbar(DSD)
        Dsbar.pack(side=tkinter.RIGHT, fill=Y)
        DTxt = tkinter.Text(DSD, height=500, width=350, yscrollcommand=Dsbar.set)
        DTxt.pack(expand=0, fill=tkinter.BOTH)
        DTxt.insert(tkinter.END, x)
        Dsbar.config(command=DTxt.yview())
        DSD.geometry("1366x758")
        print(f'####################\n\nDNFVI State-Dump has been collected, Please check {server} to collect file\n'
              f'Check the Output Log Window & Close it to proceed')
        jhost.close()
        DSD.mainloop()
    except:
        print('####################\n\nFailed to connect to DNFVI, Please collect DNFVI logs manually\n')


def ips():
    useri = input('\nPlease pick option from the below:\nLowes customer press 1\nOther Ciena customer press 2\n')
    saos_ip = input('\nPlease Enter Primary SAOS IP:\n ').strip()
    saos_ip = ipaddress.ip_address(saos_ip)
    dnfvi_ip = str(saos_ip - 1)
    S_saos_ip = ''
    S_dnfvi_ip = ''

    if useri == '1':
        S_saos_ip = str(saos_ip + 8)
        S_dnfvi_ip = str(saos_ip + 7)
        saos_ip = str(saos_ip)
        return saos_ip, S_saos_ip, dnfvi_ip, S_dnfvi_ip, 'y'

    elif useri == '2':
        ui = input("Do you have Secondary SAOS IP?(Y/N)\n")
        if ui.lower() == 'y':
            S_saos_ip = input('\nPlease Enter Secondary SAOS IP:\n').strip()
            S_saos_ip = ipaddress.ip_address(S_saos_ip)
            S_dnfvi_ip = str(S_saos_ip - 1)
            saos_ip = str(saos_ip)
            S_saos_ip = str(S_saos_ip)
            return saos_ip, S_saos_ip, dnfvi_ip, S_dnfvi_ip, ui
        else:
            saos_ip = str(saos_ip)
            return saos_ip, S_saos_ip, dnfvi_ip, S_dnfvi_ip, 'N'
    else:
        print("Wrong input please check the ip and run program again")
        quit()


def Primary_access(saos_ip, dnfvi_ip):
    SAOS = 'primary'
    print('####################\n\nPrimary SAOS\n\n####################')
    vm, Store = trylogin(saos_ip, SAOS)
    if vm != 'down':
        T1 = Thread(target=connect_saos, args=(saos_ip, vm, Store,))
        T1.start()
        time.sleep(1)
        T2 = Thread(target=connect_dnfvi, args=(dnfvi_ip, vm, Store,))
        T2.start()
        T1.join()
        T2.join()
        vm.close()
        print('####################\n\nPrimary SAOS Logs are Collected\n')


def Secondry_access(S_saos_ip, S_dnfvi_ip, ui):
    if ui.lower() == "y":
        print('####################\n\nSecondary SAOS\n\n####################')
        SAOS = 'Secondary'
        vm, Store = trylogin(S_saos_ip, SAOS)
        T1 = Thread(target=connect_saos, args=(S_saos_ip, vm, Store,))
        T1.start()
        time.sleep(1)
        T2 = Thread(target=connect_dnfvi, args=(S_dnfvi_ip, vm, Store,))
        T2.start()
        T1.join()
        T2.join()
        vm.close()
        print('####################\n\nSecondary SAOS Logs are Collected\n')


if __name__ == '__main__':
    saos_ip, S_saos_ip, dnfvi_ip, S_dnfvi_ip, ui = ips()
    Primary_access(saos_ip, dnfvi_ip)
    Secondry_access(S_saos_ip, S_dnfvi_ip, ui)
    input(f'####################\n\nPress Enter to Exit\n')
