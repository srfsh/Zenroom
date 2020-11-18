#!/usr/bin/env bash

RNGSEED="hex:00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"

####################
# common script init
if ! test -r ../utils.sh; then
	echo "run executable from its own directory: $0"; exit 1; fi
. ../utils.sh
Z="`detect_zenroom_path` `detect_zenroom_conf`"
####################
# use zexe if you have zenroom in a system-wide path
#
# zexe() {
#	out="$1"
#	shift 1
#	>&2 echo "test: $out"
#	tee "$out" | zenroom -z $*
# }
####################


## Path: ../../docs/examples/zencode_cookbook/

n=0

# File to be hashed
tmpFile="../../docs/pages/lua.md"

tmpFileToHash=`mktemp`

tmpData1=`mktemp`
tmpData2=`mktemp`

tmpKeys1=`mktemp`
tmpKeys2=`mktemp`

tmpZencode1=`mktemp`
tmpZencode2=`mktemp`



let n=n+1
echo "                                                "
echo "-------------------------------------------------------------------"
echo " 												  "
echo "    Script number '$n' that hashes the file: 	  "
echo "    '$tmpFile'											  "
echo "    and signs the hashes		  "
echo " 												  "
echo "-------------------------------------------------------------------"
echo "                                                "


# echo $tmpFile


cat << EOF > ../../docs/examples/zencode_cookbook/fileToHash.json
{
"fileToBeHashedBase64" : "$(base64 -w 0 $tmpFile)",
	"fileToBeHashed.Metadata" : {
		"nameOfFileToBeHashed" : "$tmpFile",
		"dateOfFileToBeHashed" : $(stat -c \"%y\" $tmpFile),
		"sizeOfFileToBeHashedinBytes" : $(stat -c \"%s\" $tmpFile)
	}
}
EOF




cat <<EOF  > $tmpData1
{
	"Alice": {
		"keypair": {
			"private_key": "WBdsWLDno9/DNaap8cOXyQsCG182NJ0ddjLo/k05mgs=",
			"public_key": "BNRzlJ4csYlWgycGGiK/wgoEw3OizCdx9MWg06rxUBTP5rP9qPASOW5KY8YgmNjW5k7lLpboboHrsApWsvgkMN4="
		}
	},
	"Bob": {
		"public_key": "BBA0kD35T9lUHR/WhDwBmgg/vMzlu1Vb0qtBjBZ8rbhdtW3AcX6z64a59RqF6FCV5q3lpiFNTmOgA264x1cZHE0="
	},
	"Carl": {
		"public_key": "BLdpLbIcpV5oQ3WWKFDmOQ/zZqTo93cT1SId8HNITgDzFeI6Y3FCBTxsKHeyY1GAbHzABsOf1Zo61FRQFLRAsc8="
	},
	"myUserName":"Alice",
	"myPassword":"myFancyPassword"
}
EOF




cat <<EOF  > $tmpZencode1
Rule check version 1.0.0
Scenario 'ecdh': Alice encrypts a message for Bob and Carl 

# Here we load keypair and public keys
Given my name is in a 'string' named 'myUserName'
Given that I have my 'keypair'
Given that I have a 'string' named 'myPassword'
Given that I have a 'string dictionary' named 'fileToBeHashed.Metadata'


# This is something new: here we are loading the payload to be encrypted,
# stating that it's encoded in base64
Given that I have a 'base64' named 'fileToBeHashedBase64'

# Here we create the simplest hash the file, using the default algorythm "sha256"
When I create the hash of 'fileToBeHashedBase64' using 'sha256'
And I rename the 'hash' to 'sha256HashOffile'

# Here we create the hash the file using sha512
When I create the hash of 'fileToBeHashedBase64' using 'sha512'
And I rename the 'hash' to 'sha512HashOffile'

# Here we create the simplest hash the file (using sha256)
When I create the HMAC of 'fileToBeHashedBase64' with key 'myPassword' 
And I rename the 'HMAC' to 'HMACHashOffile'

# Create a dictionary that contains all the hashes
When I create the 'base64 dictionary'
and I rename the 'base64 dictionary' to 'fileToBeHashed.Hashes'

When I insert 'sha256HashOffile' in 'fileToBeHashed.Hashes' 
When I insert 'sha512HashOffile' in 'fileToBeHashed.Hashes' 



# sign all the hashes
When I create the signature of 'fileToBeHashed.Hashes'
and I rename the 'signature' to 'fileToBeHashed.Hashes.signature'

# sign all the metadata
When I create the signature of 'fileToBeHashed.Metadata'
and I rename the 'signature' to 'fileToBeHashed.Metadata.signature'

When I create the 'base64 dictionary'
and I rename the 'base64 dictionary' to 'fileToBeHashed.signatures'
When I insert 'fileToBeHashed.Hashes.signature' in 'fileToBeHashed.signatures' 
When I insert 'fileToBeHashed.Metadata.signature' in 'fileToBeHashed.signatures' 

# and to finish, here we print out the encrypted payloads, for both the recipients
# Then print the 'sha256HashOffile'
# Then print the 'sha512HashOffile'
Then print the 'fileToBeHashed.Hashes'
Then print the 'fileToBeHashed.Metadata'
Then print the 'fileToBeHashed.signatures'
EOF





cat $tmpZencode1 | zexe ../../docs/examples/zencode_cookbook/temp.zen -z -k $tmpData1 -a ../../docs/examples/zencode_cookbook/fileToHash.json | jq . | tee ../../docs/examples/zencode_cookbook/fileToHashOutput.json | jq .





echo "                                                "
echo "------------------------------------------------"
echo "   	END of script $n			       		  "
echo "------------------------------------------------"
echo "                         			              "


let n=n+1
                                              



rm -f ../../docs/examples/zencode_cookbook/temp.zen

rm -f $tmp

rm -f $tmpData1
rm -f $tmpData2

rm -f $tmpKeys1
rm -f $tmpKeys2

rm -f $tmpZencode1
rm -f $tmpZencode2

rm -f $tmpFileToHash
