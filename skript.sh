
for zprava in "00 00 00 00  00 00 00 00" "FF FF FF FF  FF FF FF FF"; do
   for klic in "00 00 00 00  00 00 00 00  00 00"  "FF FF FF FF  FF FF FF FF  FF FF"; 
   do echo "$zprava" | ./present.out -k "$klic"; 
   done
done

