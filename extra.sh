# Find uid=0 users
if input("Find UID/GID=0 users? (y/n) ") == "y":
    uid0 = [x for x in current_users if (x["uid"] == "0" or x["gid"] == "0") and x["user"] != "root"]
    if len(uid0) > 0:
        print("WARNING: UID/GID=0 USERS FOUND")
        print(json.dumps(uid0, indent=4))
        input()
    else:
        print("No UID/GID=0 users found")
print("---------")

# Reset rc.local file
if input("Reset /etc/rc.local? (y/n) ") == "y":
    subprocess.call(["sudo", "cp", "-n", "/etc/rc.local", "backup/rc.local"])
    with open("/etc/rc.local", "w") as conf:
        conf.write("\n".join(get_file("defaults/default_rc.local")))
print("---------")

# Reset sources.list
# https://askubuntu.com/questions/586595/restore-default-apt-repositories-in-sources-list-from-command-line/586606
if input("Reset sources.list? (y/n) ") == "y":
    subprocess.call(["sudo", "cp", "-n", "/etc/apt/sources.list", "backup/sources.list"])
    with open("/etc/apt/sources.list", "w") as conf:
        conf.write("deb http://archive.ubuntu.com/ubuntu " + codename + " main multiverse universe restricted\n")
        conf.write("deb http://archive.ubuntu.com/ubuntu " + codename + "-security main multiverse universe restricted")
    subprocess.call(["sudo", "apt", "update"])
print("---------")

# Change all users' passwords (not admins)
only_users = allowed_users - allowed_admins

print("allowed users: {}".format(only_users))
if input("Change all allowed users passwords? (y/n) ") == "y":
    for user in only_users:
        proc = subprocess.Popen(["sudo", "passwd", user], 
            stdin=subprocess.PIPE, 
            stdout=subprocess.PIPE)
        proc.stdin.write("Cyberpatriot1!\n".encode("ascii"))
        proc.stdin.write("Cyberpatriot1!\n".encode("ascii"))
        proc.stdin.flush()
        print("Changed password of user {}".format(user))
        time.sleep(1)
print("---------")

# Secure shared memory
if input("Secure shared memory? (y/n)"):
    with open("/etc/fstab", "a+") as fstab:
        fstab_lines = fstab.read().splitlines()
        if "# Script ran" not in fstab_lines:
            fstab.write("\n# Script ran\nnone     /run/shm     tmpfs     rw,noexec,nosuid,nodev     0     0")
            print("Shared memory secured.")
        else:
            print("Shared memory already secured.")
print("---------")

# Install and configure fail2ban
echo "Installing and configuring fail2ban..."
sudo apt install -y fail2ban
sudo cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local
sudo systemctl enable fail2ban
sudo systemctl start fail2ban
