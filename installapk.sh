#将该文件放在一个文件夹下，运行即可自动安装该文件夹下所有的APK
filelist=`ls .`
for file in $filelist
do 
adb install $file
done
