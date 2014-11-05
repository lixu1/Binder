#安装某一个文件夹下所有的APK
filelist=`ls .`
for file in $filelist
do 
adb install $file
done
