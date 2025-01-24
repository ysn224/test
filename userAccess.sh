echo "Did you add approved users and admin to the txt file? If not, break out of script and do so"
read -a check

getent passwd | cut -d: -f1 > systemUsers.txt
sort systemUsers.txt -o systemUsers.txt
sort approvedUsers.txt -o approvedUsers.txt

toDel=$(comm -13 approvedUsers.txt systemUsers.txt)

for user in $toDel; do
  userdel $user
done

toAdd=$(comm -23 approvedUsers.txt systemUsers.txt)

for user in $toAdd; do
  adduser $user
done

getent group sudo | cut -d: -f4 > systemAdmin.txt
sed 's/,/\n/g' systemAdmin.txt > tmp.txt && mv tmp.txt systemAdmin.txt
sort systemAdmin.txt -o systemAdmin.txt
sort approvedAdmin.txt -o approvedAdmin.txt

toMakeReg=$(comm -13 approvedAdmin.txt systemAdmin.txt)
for user in $toMakeReg; do
  gpasswd -d $user sudo
done

toMakeAdmin=$(comm -23 approvedAdmin.txt systemAdmin.txt)

for user in $toMakeAdmin; do
  usermod -aG sudo $user
done
