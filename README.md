High-S malleability fixer
===

  
 Bitcoin transactions suffer from a property known as malleability, where certain parts of a transaction inputs script, 
 which can never be committed by a signature (for example, the signatures themselves). Because of this,
 in certain cases the script can be changed, leaving the transaction still valid, but with a different identifier. 
 
 There are numerous avenues for malleability, but presently, an individiual is spamming the network using the low-s 
 vector. This entails mutating a transactions signature by setting the S value to: `-s mod n`, an operation which 
 leaves the signature perfectly valid for that transaction, but results in a different binary representation, and hence
 a different hash. 
 
 This script attempts listen for mutated transactions on the network, and leverge the malleability of signatures
 by changing them to it's low-s form. Approximately 95% of recent transactions have used the low-s form, and it 
 has been proposed on several occasions to have nodes automatically fix high-s signatures, as it saves a few bits per signature.
 