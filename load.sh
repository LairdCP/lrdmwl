

if [ $# != "1" ]; then
echo "./load.sh <s/p/u>"
exit
fi

insmod mwlwifi_comm.ko

if [ $1 == "s" ]; then
echo Sdio
insmod mwlwifi_sdio.ko
elif [ $1 == "p" ]; then
echo Pcie
insmod mwlwifi_pcie.ko
else
echo Usb
insmod mwlwifi_usb.ko
fi
