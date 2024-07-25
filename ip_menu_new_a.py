from time import sleep
import boto3
import getpass
import os
import paramiko
from scp import SCPClient
import re
from pyfiglet import Figlet
from botocore.exceptions import ClientError
import webbrowser
import time
import pyautogui as gui
import xlrd
import smtplib

        #                      **                 **                      #
        #                      ***  SSh connect  ***                      #
        #                      **                 **                      #

# Connecting to remote machine using Paramiko over SSH
def ssh_cmd(ip, user, password, cmd, host):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(hostname=ip, username=user, password=password)
    if host is not None:
        f = open('hostname.txt', "w")
        f.write(host)
        f.close()
        scp = SCPClient(client.get_transport())
        scp.put('hostname.txt', recursive=True, remote_path='/root/')
        scp.close()

    stdin, stdout, stderr = client.exec_command(cmd)
    opt = stdout.readlines()
    opt = "".join(opt)
    return opt

        #                      **                 **                      #
        #                      ***  SSh keygen   ***                      #
        #                      **                 **                      #

# Exchanging keys with the remote machine
def ssh_keygen(ip):
    os.system('ssh-keygen -t rsa -b 4096 -P "" -f "/var/root/.ssh/id_rsa.pub"')
    os.system('ssh-copy-id root@{}'.format(ip))
    choose = input("Your keys have been exchanged successfully, would you like to connect? y/n: ".lower())
    print("----------------------------------------")
    if choose == "y":
        os.system('ssh root@{}'.format(ip))
    elif choose == "n":
        menu()
    else:
        print("Please type y/n only!")
    print("----------------------------------------")

    back_to_main()

        #                      **                       **                      #
        #                      ***  Install packages   ***                      #
        #                      **                       **                      #

# Installing required packages on the remote machine
def set_install():
    print("Please hold while we are installing your packages...")
    sleep(1)
    cod = "cat /root/hostname.txt  > /etc/hostname;" \
          "apt-get install ssh" \
          "apt-get install python3.7 -y;" \
          "apt-get install net-tools -y;" \
          "apt-get install trace-route -y;" \
          "apt-get install sshpass -y;" \
          "apt-get install snmp -y;" \
          "apt-get install python3-pip -y;" \
          "apt-get install apache2 -y;" \
          "pip install paramiko -y;" \
          "pip install boto3 -y;" \
          "apt-get install htop -y;" \
          "apt-get install tree -y;" \
          "apt-get install openjdk-8-jdk -y;" \
          "apt-get install nmap -y;" \
          "apt-get install tcpdump -y;" \
          "apt-get upgrade -y;" \
          "rm -rf /root/hostname.txt;" \
          "reboot"
    return cod

        #                      **                   **                      #
        #                      ***  AWS Services   ***                      #
        #                      **                   **                      #

# A preferences function of ec2 in AWS
def ec2():
    ec = boto3.resource('ec2', region_name='us-east-2')
    return ec


# A function that deploying the machines in AWS
def deploy_AWS():
    print("----------------------------------------")
    print("Welcome to deploy menu!")
    dict_image = {1: {'ami-0fc20dd1da406780b': 'Ubuntu'},
                  2: {'ami-0520e698dd500b1d1': 'CentOS'},
                  3: {'ami-04c5bab51cc146925': 'Suse linux'},
                  4: {'ami-067317d2d40fd5919': 'Microsoft windows 2019'}}

    image_id = int(input(
        '\nWhich machine you would like to create ?\n1. Ubuntu\n2. CentOS\n3. Suse linux\n4. Microsoft '
        'Windows 2019 \n----------------------------------------\nEnter your choose: '))

    for key, val in dict_image[image_id].items():
        id = key
        name = val
        print("----------------------------------------")

    num = int(input('How many machines you want to deploy: '))
    print("----------------------------------------\nCreating virtual " + name + " machine...")
    print("----------------------------------------")
    sleep(3)

    instance = ec2().create_instances(
        ImageId=id,
        MinCount=1,
        MaxCount=num,
        InstanceType='t2.micro',
        KeyName='aws-key',
        SecurityGroupIds=['launch-wizard-2'])
    for i in range(num):
        Tag_AWS = input("Enter your instance name: ")
        os.system('aws ec2 create-tags --tags Key=Name,Value={} --resources {}'.format(Tag_AWS, instance[i].id))
        print("----------------------------------------")
        print('The details of new AWS instance : ' + '\nInstance Name: ' + Tag_AWS + '\nType instance: ' + name +
              '\nInstance ID: ' + instance[i].id)
        print("----------------------------------------")

    back_to_main()


# A function that pausing the machines in AWS
def stop_AWS():
    print("----------------------------------------")


    show_machines_AWS()
    Pause_all = input("you would like to pause all the instances that be in status: Running? y/n: ").lower()
    print("----------------------------------------")
    if Pause_all == "y":
        ec2().instances.all().stop()
        print("Pausing all your aws machines...")
        sleep(3)
        print("----------------------------------------")
        print("all the virtual machines has been paused")
        sleep(3)
        while True:
            choose = input("you would like to to return to AWS menu? y/n: ").lower()
            if choose == "y":
                AWS_menu()
            if choose == "n":
                menu()
            else:
                print("Please type your selection (only y or n) ")

    if Pause_all == "n":
        pass
    else:
        stop_AWS()
    id = input("Enter the ID of your AWS machine that you'd like to pause: ")
    ids = [id]
    while True:
        print("----------------------------------------")
        sure = input("Are you sure that you would like to pause this machine: " + id + " ? y/n ".lower())
        if sure == "y":
            print("Pausing your aws machine...")
            sleep(3)
            ec2().instances.filter(InstanceIds=ids).stop()
            while True:
                print("----------------------------------------")
                option = input("This virtual machine: " + id + "has been stopped\n, you would like to stopping"
                                                               " another virtual machine? y/n: ".lower())
                if option == "y":
                    stop_AWS()
                elif option == "n":
                    AWS_menu()
                else:
                    print("Please type your selection (only y or n): ")
        elif sure == "n":
            AWS_menu()
        else:
            print("Please type your selection (only y or n): ")
            continue


# A function that starting the machines in AWS
def start_AWS():
    print("----------------------------------------")
    print("Welcome to start menu!")
    show_machines_AWS()
    id = input("Enter ID of your virtual machine: ")
    ids = [id]
    while True:
        print("----------------------------------------")
        sure = input("Are you sure that you would like to start this machine: " + id + "? y/n ".lower())
        if sure == "y":
            print("Starting your virtual machine...")
            sleep(3)
            ec2().instances.filter(InstanceIds=ids).start()
            while True:
                print("----------------------------------------")
                option = input("This virtual machine: " + id + "has been started, you would like to starting"
                                                               " another virtual machine? y/n :".lower())
                if option == "y":
                    start_AWS()
                elif option == "n":
                    AWS_menu()
                else:
                    print("Please type your selection (only y or n): ")
        elif sure == "n":
            AWS_menu()
        else:
            print("Please type your selection (only y or n): ")
            continue


# A function that rebooting the machines in AWS
def reboot_AWS():
    print("----------------------------------------")
    print("Welcome to reboot menu!")
    show_machines_AWS()
    id = input("Enter ID of your virtual machine: ")
    ids = [id]
    while True:
        print("----------------------------------------")
        sure = input("Are you sure that you would like to rebooting this virtual machine: " + id + "  y/n: ".lower())
        if sure == "y":
            print("Rebooting your virtual machine...")
            sleep(3)
            ec2().instances.filter(InstanceIds=ids).reboot()
            while True:
                print("----------------------------------------")
                option = input("This virtual machine: " + id + "has been rebooted, you would like to rebooting"
                                                               " another virtual machine? y/n: ".lower())
                if option == "y":
                    reboot_AWS()
                elif option == "n":
                    AWS_menu()
                else:
                    print("Please type your selection (only y or n): ")
        elif sure == "n":
            AWS_menu()
        else:
            print("Please type your selection (only y or n): ")
            continue


# A function that terminating the machines in AWS
def terminate_AWS():
    print("----------------------------------------")
    print("Welcome to terminate menu!")
    show_machines_AWS()
    id = input("Enter ID of your virtual machine: ")
    ids = [id]
    while True:
        print("----------------------------------------")
        destroy = input("This will terminate your virtual machine: " + id + ". Are you sure? y/n: ".lower())
        if destroy == "y":
            print("Terminating your virtual machine...")
            sleep(3)
            ec2().instances.filter(InstanceIds=ids).terminate()
            while True:
                print("----------------------------------------")
                option = input("This virtual machine: " + id + "has been terminated, you would like to terminate"
                                                               " another virtual machine? y/n: ".lower())
                if option == "y":
                    terminate_AWS()
                elif option == "n":
                    AWS_menu()
                else:
                    print("Please type your selection (only y or n): ")
        elif destroy == "n":
            print("Your machine was not deleted")
            AWS_menu()
        else:
            print("Please type your selection (only y or n): ")


# A function that creating/adding tags to specific instance in AWS
def Create_Tag_AWS():
    show_machines_AWS()
    InstanceID = input('Enter the AWS instanse-ID: ')
    print("----------------------------------------")
    while True:
        num = int(input('How many tags you would like to create for this instance? '))
        print("----------------------------------------")
        for i in range(num):
            Title_tag = str(input("Enter the title-tag (key) of the tag that you would like to create: "))
            if Title_tag == "Name":
                print("this tags already exist, pleas try another tag ")
                sleep(2)
                continue

            Content_tag = input("Enter the content-tag (value) that you would like to create: ")
            print("----------------------------------------")
            print("creating a new tag....")
            os.system('aws ec2 create-tags --tags Key={},Value={} --resources {}'.format(Title_tag,Content_tag,InstanceID))
            sleep(1)
            print("----------------------------------------")
            print('The new tag will created in successfully !!')
            print("----------------------------------------")
        choose = input('you would like to create another tag on this instanse '+InstanceID+' ? y/n: ').lower()
        if choose == "y":
            continue
        if choose == "n":
            option = input('you would like to create a new tag on another instance? y/n: ').lower()
            if option == "y":
                print("----------------------------------------")
                Create_Tag_AWS()
            if option == "n":
                AWS_menu()


# A function that display all exist machines in AWS
def show_machines_AWS():
    print("These are your machines: ")
    for instance in ec2().instances.all():
        print("\nMachine ID: " + ("".join('{}'.format(k) for k, in instance.id)),
              "\nIP address: ", instance.public_ip_address, "\nType: ", instance.instance_type,
              "\nAmi: ", instance.image_id)
        for v in instance.state.items():
            print(str(v[0] + ': ' + str(v[1])))
    print("----------------------------------------")


# A function that connecting to AWS machine with SSh
def connect_AWS():
    show_machines_AWS()
    IP_AWS = input("Please type your desired IP: ")
    regex = '''^(25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\.( 
                25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\.( 
                25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\.( 
                25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)'''

    while True:
        if re.search(regex, IP_AWS):
            print("Your IP address is valid!")
            print("----------------------------------------\n")
            break
        else:
            print("----------------------------------------")
            print("Your IP address is invalid!")
            print("----------------------------------------\n")
            while True:
                choose = input("Do you want to type another IP? y/n: ").lower()
                if choose == "y":
                    connect_AWS()
                if choose == "n":
                    AWS_menu()
                else:
                    print("Please type your selection (only y or n): ")
                    continue

    path : str = os.popen("find /home/ -name 'aws-key.pem'").read()
    IP_list = list(IP_AWS)
    for i in range(len(IP_list)):
        if IP_list[i] == ".":
            IP_list[i] = "-"
    IP_AWS_connect = "".join(IP_list)
    print("Your location AWS 'key.pem' is: ",path)
    print("----------------------------------------\n")

    # The function os.popen uses "find" command to search the pem certificate.
    #".read" library as defult adds to the output of the command a prefix (b') and a suffix (\n’) in the backend
    # In our example: path: str = os.popen("find /home/ -name 'aws-key.pem'").read()

    # In the backend: path.encode("utf8") - how does the library functions behind the scene?
    # What we actually see (using the print command): path = /home/parallels/Desktop/aws-key.pem
    # What actually happens: b'/home/parallels/Desktop/aws-key.pem\n’
    # Using the ".split" command, we remove the prefix and the suffix.

    split_startswith = path.split("/home")                      # b'/home
    split_endswith = "".join(split_startswith[1]).split(".")    # .pem\n’
    final_path = "".join(split_endswith[0])                     # /parallels/Desktop/aws-key

    os.system('ssh -i "/home{}.pem" ubuntu@ec2-{}.us-east-2.compute.amazonaws.com -y'.format(final_path,IP_AWS_connect))

        #                      **                    **                      #
        #                      ***   AWS S3 cloud   ***                      #
        #                      **                    **                      #

# A function that display all the buckets in AWS S3 cloud
def Show_buckets_AWS():
    print("--- All buckets ---")
    s3 = boto3.resource('s3')
    for bucket in s3.buckets.all():
        print("Bucket name :",bucket.name)
    while True:
        print("----------------------------------------\n")
        choose = input("You'd like to return to AWS S3 menu? y/n: ".lower())
        if choose == "y":
            AWS_S3_menu()
        if choose == "n":
            AWS_menu()
        else:
            print("Please type your selection (only y or n): ")
            continue


# A function that deploy/terminate directory from inside the bucket
def Folder_AWS_S3():
    choose = input("Please choose what you'd like to do: \n\n1. Create a folder inside the bucket "
                   "\n2. Delete a folder inside the bucket \n----------------------------------------"
                   "\nEnter your choice ")
    print("----------------------------------------\n")
    if choose == "1":
        bucket_name = input("Enter the bucket name: ")
        print("----------------------------------------")
        folder_name = input("Enter the folder name that you want to create: ")
        print("----------------------------------------")
        s3 = boto3.client('s3')
        s3.put_object(Bucket=bucket_name, Key=(folder_name +'/'))

    elif choose == "2":
        s3 = boto3.resource('s3')
        buck = input("Enter the bucket name: ")
        print("----------------------------------------")
        folder = input("Enter the folder that you'd like to delete: ")
        print("----------------------------------------")
        bucket = s3.Bucket(buck)
        for obj in bucket.objects.filter(Prefix=folder):
            s3.Object(bucket.name,obj.key).delete()
    else:
        print("Please type your selection (only 1 or 2): ")
        Folder_AWS_S3()


# A function that deploy/terminate bucket from AWS S3 cloud
def Buckets_AWS_S3():
    choose = input("Please choose what you'd like to do: \n\n1. Create buckets \n2. Delete buckets "
                   "\n----------------------------------------\nEnter your choice: \n")
    print("----------------------------------------")
    if choose == "1":
        num = int(input("How many buckets do you want to Create? "))
        print("----------------------------------------")
        for i in range(num):
            name = input("Enter the new Bucket name: ")
            print("----------------------------------------")
            region = "us-east-2"
            print("----------------------------------------")
            s3 = boto3.resource('s3')
            s3.create_bucket(Bucket=name, CreateBucketConfiguration={'LocationConstraint': region})

    elif choose == "2":
        num_d = int(input("How many buckets do you want to delete? "))
        print("----------------------------------------")
        for i in range(num_d):
            name_d = input("Enter the bucket name that you'd like to delete: ")
            print("----------------------------------------")
            s3 = boto3.resource('s3')
            bucket = s3.Bucket(name_d)
            bucket.delete()
    else:
        print("Please type your selection (only 1 or 2")
        Buckets_AWS_S3()


# A function that upload files to bucket in AWS S3 cloud
def Upload_AWS_S3():
    num = int(input("How many files you'd like to upload? "))
    for i in range(num):
        name = input("Enter the bucket name: ")
        file = input("Enter the file name that you'd like to upload: ")
        data = open(file, 'rb')
        s3 = boto3.client('s3')
        s3.put_object(Bucket=name, Key=file, Body=data)


# A function that manage the cloud in AWS S3
def AWS_S3_menu():
    while True:
        print("----------------------------------------")
        print("Welcome to AWS S3 cloud menu!")
        f = Figlet(font='slant')
        print(f.renderText('Aws S3 cloud menu :'))
        print("Please choose what you'd like to do: \n\n1. all AWS services from your account \n2. Show AWS S3 Buckets "
              "\n3. Create/delete AWS S3 buckets \n4. Create/delete folder from AWS S3 \n5. Upload Files "
              "\n6. Back to AWS main menu")
        print("----------------------------------------")
        choose = input("Enter your choice: ")
        print("----------------------------------------")
        if choose == "1":
            os.system("aws configure")

        elif choose == "2":
            Show_buckets_AWS()

        elif choose == "3":
            Buckets_AWS_S3()

        elif choose == "4":
            Show_buckets_AWS()
            Folder_AWS_S3()

        elif choose == "5":
            Show_buckets_AWS()
            Upload_AWS_S3()

        elif choose == "6":
            AWS_menu()

        else:
            print("Please type your selection (only 1 or 6): ")
            continue


# A function that display the options that you can do in AWS
def AWS_menu():
    while True:
        print("----------------------------------------")
        print("Welcome to AWS menu!" )
        f = Figlet(font='slant')
        print(f.renderText('Aws menu :'))
        line = input("Please choose what you'd like to do: \n\n1. Deploy AWS machine \n2. Pause AWS machine"
                     " \n3. Start AWS machine \n4. Reboot AWS machine \n5. Terminate AWS machine "
                     "\n6. Create tag to AWS machine\n7. Show status machines in AWS \n8. SSh connect to AWS machine "
                     "\n9. Menage AWS S3 cloud \n10.  Back to main menu\n----------------------------------------\nEnter your choose: ")
        dict_choose = {'1': deploy_AWS, '2': stop_AWS, '3': start_AWS, '4': reboot_AWS, '5': terminate_AWS,
                       '6': Create_Tag_AWS, '7': show_machines_AWS, '8': connect_AWS, '9': AWS_S3_menu, '10': back_to_main}
        lines = ["1", "2", "3", "4", "5", "6", "7", "8", "9"]

        if line in lines:
            functionToCall = dict_choose[line]
            functionToCall()
        else:
            print("Please type your selection (only 1 or 9")

        #                      **                 **                      #
        #                      ***    Jenkins    ***                      #
        #                      **                 **                      #

# A function that installing jenkins
def install_jenkins():
    print("For installing Jenkins, we need to prepare the environment \nto make sure it will go smoothly.")

    cmd = "apt-get install nginx -y;" \
          "apt-get install openjdk-8-jdk -y;" \
          "wget -q -O - https://pkg.jenkins.io/debian/jenkins-ci.org.key | sudo apt-key add - ;" \
          "sudo sh -c 'echo deb http://pkg.jenkins.io/debian-stable binary/ > /etc/apt/sources.list.d/jenkins.list' ;" \
          "apt-get update -y;" \
          "apt-get install jenkins -y;"
    set_install()
    return cmd

        #                      **                 **                      #
        #                      ***     Nagios    ***                      #
        #                      **                 **                      #

# A function that installing nagios
def install_nagios():
    cmd = "apt-get update;" \
          "apt-get install curl -y;" \
          "apt install autoconf gcc make unzip libgd-dev libmcrypt-dev libssl-dev dc snmp libnet-snmp-perl gettext -y;" \
          "cd ~;" \
          "curl -L -O https://github.com/NagiosEnterprises/nagioscore/archive/nagios-4.4.4.tar.gz;" \
          "tar zxf nagios-4.4.4.tar.gz;" \
          "cd nagioscore-nagios-4.4.4;" \
          "./configure --with-httpd-conf=/etc/apache2/sites-enabled;" \
          "make all;" \
          "make install-groups-users;" \
          "make install;" \
          "make install-daemoninit;" \
          "make install-commandmode;" \
          "make install-config;" \
          "make install-webconf;" \
          "a2enmod rewrite;" \
          "a2enmod cgi;" \
          "usermod -a -G nagios www-data;" \
          "htpasswd -b -c /usr/local/nagios/etc/htpasswd.users nagiosadmin nagios123;" \
          "systemctl restart apache2;" \
          "cd ~;" \
          "curl -L -O https://nagios-plugins.org/download/nagios-plugins-2.2.1.tar.gz;" \
          "tar zxf nagios-plugins-<^>2.2.1<^.tar.gz;" \
          "cd nagios-plugins-2.2.1;" \
          "./configure;" \
          "make;" \
          "make install;" \
          "cd ~;" \
          "curl -L -O https://github.com/NagiosEnterprises/nrpe/releases/download/nrpe-3.2.1/nrpe-3.2.1.tar.gz;" \
          "tar zxf nrpe-3.2.1.tar.gz;" \
          "cd nrpe-3.2.1;" \
          "./configure;" \
          "make check_nrpe;" \
          "make install-plugin;"
    return cmd

        #                      **                  **                      #
        #                      ***   Speed test   ***                      #
        #                      **                  **                      #

# A function that checking the the speed network
def Speed_test(ip):
    os.system("ssh root@{} <<EOF".format(ip))
    os.system("""speedtest-cli>speedtest.txt && date >>speedtest.txt && cat speedtest.txt""")

        #                      **                       **                      #
        #                      ***   Docker services   ***                      #
        #                      **                       **                      #

# A function that installing docker
def Installation(ip):
    print("This Script Will Install Docker And Pull Nginx & Centos Images")
    sleep(1)
    print("Starting With Docker...")
    sleep(1)
    ssh_cmd(ip, user="root", password=getpass.getpass('Root Password:'), cmd=Pull(), host=None)
    os.system("curl - fsSL https: // get.docker.com - o get - docker.sh")
    os.system("bash get - docker.sh")
    print("Docker Installation is Done")


# A function that pulling Nginx & Centos Images in docker
def Pull():
    while True:
        image = input("Which image would you like to pull ?")
        try:
            print("Checking if the image exist... ")
            os.system("sudo docker pull" + image)
        except:
            print("Error: invalid image please retype the correctly name")
            continue

        print("Starting pulling" + image + "Image...")
        choose = input("Would you like to pull another image ? y/n ".lower())
        if choose == "y":
            Pull()
        if choose == "n":
            docker_menu()
        else:
            print("Please type your selection (only yes or no")


# A function that deploy Images in docker
def Deploy():
    while True:
        choice = input("Choose The Image You'd Like To Deploy: \n1) Deploy Nginx. \n2) Deploy Centos.")

        if choice == "1":
            num = input("How many Containers Would you like to Deploy")
            for i in num:
                os.system("sudo docker run -d  `sudo docker images | grep nginx | awk 'NR==1 {print $3}'`")
                print(i, "Done!")
            break
        elif choice == "2":
            num = input("How many Containers Would you like to Deploy")
            for i in num:
                os.system("sudo docker run -d  `sudo docker images | grep centos | awk 'NR==1 {print $3}'`")
                print(i, "Done!")
        else:
            print("Please type 1-2 only")
            continue

        os.system("sudo docker ps -a")


# A function that getting Images Info in docker
def info(ip):
    ssh_cmd(ip, user="root", password=getpass.getpass('Root Password:'), cmd=os.system('docker ps -a'), host=None)
    print("Docker IP: \n")
    os.system("sudo docker inspect | grep 'IP' ")


# A function that terminating Images in docker
def Delete():
    while True:
        choice = input("\nChoose The Image You'd Like To Delete:\n1) Delete Nginx.\n2) Delete "
                       "Centos.\n----------------------------------------\nEnter your "
                       "choice: ")
        if choice == "1":
            quan = input("How many Containers Would you like to Delete?")
            for i in quan:
                os.system("sudo docker stop  `sudo docker ps -a | grep nginx | awk 'NR==1 {print $1}'`")
                os.system("sudo docker rm  `sudo docker ps -a | grep nginx | awk 'NR==1 {print $1}'`")
                print(i, "Done!")
        elif choice == "2":
            quan = input("How many Containers Would you like to Delete?")
            for i in quan:
                os.system("sudo docker stop  `sudo docker ps -a | grep bash | awk 'NR==1 {print $1}'`")
                os.system("sudo docker rm  `sudo docker ps -a | grep bash | awk 'NR==1 {print $1}'`")
                print(i, "Done!")
        else:
            print("Please type 1-2 only")
            continue

        os.system("sudo docker ps -a")


# A function that display the docker Menu
def docker_menu(ip):
    while True:
        f = Figlet(font='slant')
        print(f.renderText("Docker Menu :"))
        choice = input("1. Install docker\n2. Pull images\n3. Deploy images\n4. Get info\n5. Delete\n6. Back to main "
                       "menu "
                       "Images\n----------------------------------------\nEnter your choice: ")
        print("----------------------------------------")
        if choice == "1":
            Installation(ip)
        elif choice == "2":
            Pull()
        elif choice == "3":
            Deploy()
        elif choice == "4":
            info(ip)
        elif choice == "5":
            Delete()
        elif choice == "6":
            back_to_main()
        else:
            print("Please type 1-6 only")

        #                      **                 **                      #
        #                      ***    Ansible    ***                      #
        #                      **                 **                      #

# A function that installing ansible
def Ansible():
    choose = input("would you like to install ansible on your machine ? y/n: ").lower()
    if choose == "y":
        os.system("sudo apt update && sudo apt install software-properties-common -y && sudo apt-add-repository "
                  "ppa:ansible/ansible -y && sudo apt update && sudo apt install ansible -y ")
    if choose == "n":
        IP_server = input("Please type the desired IP: ")
        passwd = getpass.getpass('Enter your password: ')
        os.system("sshpass -p '{}' ssh root@{} sudo apt update && sudo apt install software-properties-common -y && "
                  "sudo apt-add-repository ppa:ansible/ansible -y && sudo apt update && sudo apt install ansible -y "
                  "".format(passwd, IP_server))
    else:
        Ansible()

        #                      **                          **                      #
        #                      ***    Department_sales    ***                      #
        #                      **                          **                      #

def WhatsAPP():
    # don't delete
    interval = 2
    position = 730, 190

    path = "/Users/user/Desktop/file.xlsx"

    readxl = xlrd.open_workbook(path)
    readxlsheet = readxl.sheet_by_index(0)
    rows = readxlsheet.nrows

    nums = []
    names = []
    mail = []
    for y in range(1, rows):
        nums.append(int(readxlsheet.cell_value(y, 0)))
        names.append(readxlsheet.cell_value(y, 1))

    print(nums)
    print(names)

    for c in range(len(nums)):
        message = "Hello {} this is a text message for integrity check".format(names[c])
        print(message)

        url = 'https://web.whatsapp.com/send?phone=+972+{}&text={}'.format(nums[c], message)

        webbrowser.open(url)
        time.sleep(10)
        gui.click(position)
        time.sleep(3)
        gui.press('enter')
        time.sleep(interval)


def Email():
    email = os.environ.get('email')
    passwd = os.environ.get('password')

    with smtplib.SMTP('smtp.gmail.com', 587) as smtp:
        smtp.ehlo()
        smtp.starttls()
        smtp.ehlo()

        smtp.login(email, passwd)

        subject = 'test'
        body = 'sdfasfdsfdsf'

        msg = f'subject: {subject}\n\n{body}'
        smtp.sendmail(email,'email@gmail.com',msg)


def Department_sales_menu():
    while True:
        f = Figlet(font='slant')
        print(f.renderText("Department sales :"))
        choice = input("1. Menage mailing list on WhatsAPP \n2. Menage mailing list on Email\n3. Back to main "
                       "menu "
                       "Images\n----------------------------------------\nEnter your choice: ")
        print("----------------------------------------")
        if choice == "1":
            WhatsAPP()
        elif choice == "2":
            Email()
        elif choice == "3":
            menu()
        else:
            print("please type 1-3 only ")

        #                      **                          **                      #
        #                      ***   System Preferences   ***                      #
        #                      ***      "IP address"      ***                      #
        #                      **                          **                      #

# A function that validate your IP address
def Check_IP(ip):
    regex = '''^(25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\.( 
                25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\.( 
                25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\.( 
                25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)'''

    while True:
        if re.search(regex, ip):
            print("Your IP address is valid!")
            break
        else:
            print("----------------------------------------")
            print("Your IP address is invalid!\n")
            menu()


###########   must to check what is this function ##########
def ipaws():
    ec2 = boto3.client('ec2')

    try:
        ec2.release_address(AllocationId='i-0d07bc4043c6e52d8')
        print('Address released')
    except ClientError as e:
        print(e)


# A function that return back to the main menu
def back_to_main():
    while True:
        main = input("\nWould like to return to main menu? y/n: ".lower())
        if main == "y":
            menu()
        elif main == "n":
            break
        else:
            print("\nPlease type y/n only!")

        #                      **                 **                      #
        #                      ***   Main menu   ***                      #
        #                      **                 **                      #

# A function that display all the options on this script
def menu():
    print("\nHello, welcome to menage script :)")
    print("----------------------------------------")
    ip = input("Please type the desired IP: ")
    Check_IP(ip)
    print("----------------------------------------")
    f = Figlet(font='slant')
    print(f.renderText('menu :'))
    choose = input("Please choose what you'd like to do: \n"
                   "\n1. Install my key on a remote machine"
                   "\n2. Configure basic installations and packages on my VM"
                   "\n3. Manage AWS machine"
                   "\n4. Install Jenkins master on my VM"
                   "\n5. Install Nagios server"
                   "\n6. Install Speed-test"
                   "\n7. Manage Docker"
                   "\n8. Install Ansible"
                   "\n9. Manege department sales"
                   "\n10. Replace your ip address"
                   '\n----------------------------------------'
                   "\nEnter your choice: ")
    if choose == "1":
        ssh_keygen(ip=ip)
    elif choose == "2":
        host = input("Please type the desired hostname: ")
        x = ssh_cmd(ip, user="root", password=getpass.getpass('Root Password:'), cmd=set_install(), host=host)
        f = open('set_install_log.txt', "w")
        f.write(x)
        f.close()
        os.system('touch log.txt; {} >log.txt'.format(x))
        os.system('scp log.txt root@{}:/root/'.format(ip))
    elif choose == "3":
        AWS_menu()
    elif choose == "4":
        x = ssh_cmd(ip, user="root", password=getpass.getpass('Root Password:'), cmd=install_jenkins(), host=None)
        f = open('log.txt', "w")
        f.write(x)
        f.close()
        print(x)
    elif choose == "5":
        ssh_cmd(ip, user="root", password=getpass.getpass('Root Password:'), cmd=install_nagios(), host=None)
    elif choose == "5":
        ssh_cmd(ip, user="root", password=getpass.getpass('Root Password:'), cmd=install_nagios(), host=None)
    elif choose == "6":
        Speed_test(ip)
    elif choose == "7":
        docker_menu(ip)
    elif choose == "8":
        Ansible()
    elif choose == "9":
        Department_sales_menu()
    elif choose == "10":
        menu()
    else:
        print("Please type your selection (only 1-9): ")
        menu()


menu()


        #                      **                 **                      #
        #                      ***    THE END    ***                      #
        #                      **                 **                      #