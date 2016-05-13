

for image in `otc images list |grep \"name\"|cut -d':' -f 2 | tr -d '"'| tr -d ' '| tr -d ','`; do
	flavor=computev2-2
	#for flavor in `./otc ecs flavor-list |grep "id"|cut -d':' -f 2 | tr -d '"'| tr -d ' '| tr -d ','`; do	  
	echo "Create VM from image $image flavor $flavor"
	otc ecs create --instance-type "$flavor" --instance-name "DEMO-$flavor-$image" "DEMO-$flavor-$image" --image-name "$image" --subnet-name subnet-128 --vpc-name vpc-DEMO --security-group-name sg-ssh --key-name SSHkey-202demo --public false
	#done
done

