#Runs rkhunter and saves any warnings
(echo "rkhunter says:" >> Warnings.rkhunter.txt; rkhunter -c --rwo >> Warnings.rkhunter.txt; echo "" >> Warnings.txt; echo "Finished rkhunter scan" ) &
disown; sleep 2; 

#run chkrootkit and save output into Warnings
( echo "Chkrootkit found (NOTE There may be false positives):" >> Warnings.chkrootkit.txt; chkrootkit -q >> Warnings.txt; echo "" >> Warnings.txt; echo "Finished chkrootkit scan" ) &
disown; sleep 2; 


#runs Debsums to check and see if there are any weirdly changed files around
( echo "Debsums says:" >> Warnings.txt; debsums -a -s >> Warnings.txt 2>&1; echo "" >> Warnings.txt; echo "Finished debsums scan" ) &
disown; sleep 2; 


#install Clamav onto the computer and begin running it
#apt-get install clamav	gets installed earlier
( freshclam; clamscan -r --bell -i / >> Clamav.txt; echo "Finished Clamav scanning" ) &
disown; sleep 2; 

#install lynis first??
#Starts lynis, which helps in securing computer
( lynis -c -Q >> LynisOutput.txt; echo "Finished Lynis" ) &
disown; sleep 2; 
