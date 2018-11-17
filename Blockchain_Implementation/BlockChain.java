package Blockchain_Implementation;

import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

public class BlockChain {

    private List<Block> blockChain;//these are immutable ledgers...and hence no "REMOVE" of blocks method
    /* can't remove or modify the block in the block_chain*/

    /*each block can contain more than 1 transaction*/
    public BlockChain(){
        blockChain=new ArrayList<>();
    }
    public void addBlock(Block block){
        this.blockChain.add(block);
    }

    public List<Block> getBlockChain() {
        return this.blockChain;
    }
    public int size(){
        return this.blockChain.size();
    }

    @Override
    public String toString() {
        String blockChain="";
        for (Block block:this.blockChain) {
            blockChain+=block.toString()+"\n";

        }
        return blockChain;
    }

    public static void main(String[] args){

        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());//adding the bouncy castle external jar
        BlockChain blockChain=new BlockChain();
        Miner miner=new Miner();//can be as many miners as we want---right now using only the single miner

        Block block0=new Block(0,"transaction1",Constants.GENESIS_PREV_HASH);
        miner.mine(block0,blockChain);

        Block block1=new Block(1,"transaction2",blockChain.getBlockChain().get(blockChain.size()-1).getHash());
        miner.mine(block1,blockChain);

        Block block2=new Block(2,"transaction3",blockChain.getBlockChain().get(blockChain.size()-1).getHash());
        miner.mine(block2,blockChain);

        System.out.println("\n"+ "BLOCKCHAIN:\n"+blockChain);
        System.out.println("Miner's Reward: "+miner.getReward());

        //TESTING MERKLE TREE IMPLEMENTATION
       /* List<String> transactions=new ArrayList<>();
        transactions.add("aa");
        transactions.add("bb");
        transactions.add("cc");
        transactions.add("dd");
        transactions.add("ee");
        transactions.add("11");
        transactions.add("22");
        transactions.add("33");
        transactions.add("44");
        transactions.add("55");

        MerkleTree merkleTree=new MerkleTree(transactions);
        System.out.println("MERKLE ROOT:"+merkleTree.getMerkleRoot().get(0));*/
    }
}

//**********MERKLE TREE IMPLEMENTATION***********************************************/
class MerkleTree{

    private List<String> transactions;

    public MerkleTree(List<String> transactions){
        this.transactions=transactions;

    }

    //the root is in the end of the list
    public List<String> getMerkleRoot(){
        return construct(this.transactions);
    }

    private List<String> construct(List<String> transactions) {

        //base case
        if(transactions.size()==1){//found the root
            return transactions;
        }

        //fewer items to merge with each iteration
        List<String> updatedList=new ArrayList<>();

        //merging the neighbouring items
        for(int i=0;i<transactions.size()-1;i+=2){
            updatedList.add(mergeHash(transactions.get(i),transactions.get(i+1)));
        }

        //if number of transactions is odd : the last item is hashed with itself
        if(transactions.size()%2==1){
            updatedList.add(mergeHash(transactions.get(transactions.size()-1),transactions.get(transactions.size()-1)));
        }

        //recursive call
        return construct(updatedList);


    }

    private String mergeHash(String data1, String data2) {
        String mergedData=data1+data2;
        return CryptographyHelper.generateHash(mergedData);
    }
}
//MINING PROCEDURE---miners will look for the hashes with the right difficulty mentioned
class Miner{

    private double reward;

    public void mine(Block block, BlockChain blockChain){

        while(notGoldenHash(block)){//THIS IS EXPENSIVE---(IN TERMS OF COMPUTATION AND ELECTRICITY)
            block.generateHash();
            block.incrementNonce();
        }
        System.out.println(block+" has just mined...");
        System.out.println("Hash is: "+block.getHash());

        blockChain.addBlock(block);//block added to the blockchain
        reward+=Constants.MINER_REWARD;//GET 10 CRYPTO-CURRENCIES ---GETTING PAID-------THIS IS HOW THEY EARN
    }

    private boolean notGoldenHash(Block block) {

        //the hash should have 5 leading zeroes which is the difficulty mentioned
        //if not then keep generating the hash by incrementing the nonce value
        //due to avalanche effect the increment of nonce value leads to a different hash
        //this is what makes GENERATING HASHES AS COMPUTATIONALLY HARD
        String leadingZeroes=new String(new char[Constants.DIFFICULTY]).replace('\0','0');
        return !block.getHash().substring(0,Constants.DIFFICULTY).equals(leadingZeroes);

    }

    public double getReward() {
        return this.reward;
    }
}
class Block{
    private int id;
    private int nonce;//keep incrementing the nonce until we get the right with the mentioned difficulty
    private long timeStamp;
    private String hash;
    private String previousHash;
    private String transaction;

    public Block(int id,String transaction,String previousHash){
        this.id=id;
        this.transaction=transaction;
        this.previousHash=previousHash;
        this.timeStamp=new Date().getTime();
        generateHash();
    }

    public void generateHash() {

        //generates the hash value for the current block
        String hashToData=Integer.toString(id)+previousHash+Long.toString(timeStamp)+Integer.toString(nonce)+transaction.toString();
        String hashValue=CryptographyHelper.generateHash(hashToData);//generates hash for the given block using the current block data
        this.hash=hashValue;
    }

    public String getHash() {
        return hash;
    }

    public void setHash(String hash) {
        this.hash = hash;
    }

    public String getPreviousHash() {
        return previousHash;
    }

    public void setPreviousHash(String previousHash) {
        this.previousHash = previousHash;
    }
    public void incrementNonce(){
        this.nonce++;
    }

    @Override
    public String toString() {
        return this.id+"-"+this.transaction+"-"+this.previousHash+"-";
    }
}


class CryptographyHelper{
    public static String generateHash(String data){
        try{

            MessageDigest digest=MessageDigest.getInstance("SHA-256");
            byte[] hash=digest.digest(data.getBytes("UTF-8"));

            //want only hexadecimal values and not bytyes
            StringBuffer hexadecimalString=new StringBuffer();

            for(int i=0;i<hash.length;i++){
                String hexadecimal=Integer.toHexString(0xff & hash[i]);
                if(hexadecimal.length()==1){
                    hexadecimalString.append('0');

                }
                hexadecimalString.append(hexadecimal);
            }
            return hexadecimalString.toString();
        }catch (Exception e){
            throw new RuntimeException(e);
        }
    }


    //this method is for generating key pair using ELLIPTIC CURVE CRYPTOGRAPHY with bouncy castle
    public static KeyPair ellipticCurveCrypto(){
        try{
            //KET PAIR HOLDS PUBLIC KEY AND PRIVATE KEY
            KeyPairGenerator keyPairGenerator=KeyPairGenerator.getInstance("ECDSA","BC");
            SecureRandom secureRandom=SecureRandom.getInstance("SHA1PRNG");
            ECGenParameterSpec params=new ECGenParameterSpec("sec192k1");//192 bits long prime number
            keyPairGenerator.initialize(params,secureRandom);
            KeyPair keyPair=keyPairGenerator.generateKeyPair();//container for public key and private key
            return keyPair;
        }catch (NoSuchAlgorithmException|NoSuchProviderException|InvalidAlgorithmParameterException e){
            e.printStackTrace();
        }
        return null;
    }


    //the owner of the transaction will Sign the message using the "PRIVATE KEY"
    public static byte[] applyECDSASignature(PrivateKey privateKey,String input){
        Signature signature;
        byte[] output=new byte[0];
        try{
            signature=Signature.getInstance("ECDSA","BC");
            signature.initSign(privateKey);//generating signature with the help of private key

            byte[] strByte=input.getBytes();
            signature.update(strByte);
            byte[] realSignature=signature.sign();//signing off the message with the signature

            output=realSignature;
        }catch (Exception e){
            e.printStackTrace();
        }
        return output;
    }

    //now the receiver will verify if the given transaction belongs to the sender only using PUBLIC KEY
    public static boolean verifyECDASSignature(PublicKey publicKey,String data,byte[] signature){
        try{
            Signature ecdasSignature=Signature.getInstance("ECDSA","BC");
            ecdasSignature.initVerify(publicKey);//initialization

            ecdasSignature.update(data.getBytes());//preparing the signature for verification
            return ecdasSignature.verify(signature);
        }catch (Exception e){
            throw new RuntimeException(e);
        }
    }
}
class Constants{
    private Constants(){

    }
    public static final int DIFFICULTY=5;//computational heavy parameter for generating the hashes will n leading zeroes
    public static final double MINER_REWARD=12.5;//REWARD THAT MINERS WILL GET AFTER MINING THE GIVEN BLOCK
    public static final String GENESIS_PREV_HASH="0000000000000000000000000000000000000000000000000000000000000000";//THIS IS FIRST BLOCK IN THE CHAIN
}


class TransactionInput{
    //every transaction input has an output as Transaction Id
    private String transactionOutputId;

    //this is the unspent transaction output
    private TransactionOutput UTXO;

    public TransactionInput(String transactionOutputId){
        this.transactionOutputId=transactionOutputId;
    }

    public String getTransactionOutputId() {
        return transactionOutputId;
    }

    public TransactionOutput getUTXO() {
        return UTXO;
    }

    public void setTransactionOutputId(String transactionOutputId) {
        this.transactionOutputId = transactionOutputId;
    }

    public void setUTXO(TransactionOutput UTXO) {
        this.UTXO = UTXO;
    }

}
class TransactionOutput{

    //identifier of the transaction output
    private String id;//sha256 hash it is
    //transaction id of the parent
    private String parentTransactionId;
    //the new owner of the coin
    private PublicKey receiver;
    //amount of coins
    private double amount;

    public TransactionOutput(PublicKey receiver,double amount,String parentTransactionId){
        this.receiver=receiver;
        this.amount=amount;
        this.parentTransactionId=parentTransactionId;
        generateId();
    }

    private void generateId() {
        //generates the id of the transaction output
        this.id=CryptographyHelper.generateHash(receiver.toString()+Double.toString(amount)+parentTransactionId);
    }

    public boolean isMine(PublicKey publicKey){
        return publicKey==receiver;
    }

    public String getId() {
        return id;
    }

    public double getAmount() {
        return amount;
    }

    public PublicKey getReceiver() {
        return receiver;
    }

    public String getParentTransactionId() {
        return parentTransactionId;
    }

    public void setId(String id) {
        this.id = id;
    }

    public void setAmount(double amount) {
        this.amount = amount;
    }

    public void setParentTransactionId(String parentTransactionId) {
        this.parentTransactionId = parentTransactionId;
    }

    public void setReceiver(PublicKey receiver) {
        this.receiver = receiver;
    }


}

class Transaction{
    //id of the transaction is a hash
    private String transactionId;
    //we use public key to reference sender or receiver
    private PublicKey sender;
    private PublicKey receiver;

    //amount of coins the transaction sends to the receiver from the sender
    private double amount;
    //make sure the transaction is signed to prevent anyone else from spending the coins
    private byte[] signature;


    //every transaction has inputs and ouputs
    public List<TransactionInput> inputs;
    public List<TransactionOutput> outputs;

    public Transaction(PublicKey sender,PublicKey receiver,double amount,List<TransactionInput> inputs){
        this.inputs=new ArrayList<>();
        this.outputs=new ArrayList<>();
        this.sender=sender;
        this.receiver=receiver;
        this.amount=amount;
        this.inputs=inputs;

        calculateHash();
    }

   /*     if(!verifySignature()){
            System.out.println("Invalid transaction because of invalid signature....");
            return false;
        }

        //now let's get the unspent transactions
        for(TransactionInput transactionInput:inputs){
           // transactionInput.setUTXO(BlockChain.UTXOs.ge);
        }

    }
*/
    private void calculateHash() {
        String hashData=sender.toString()+receiver.toString()+Double.toString(amount);
        this.transactionId=CryptographyHelper.generateHash(hashData);
    }
    //generate signature
    public void generateSignature(PrivateKey privateKey){
        String data=sender.toString()+receiver.toString()+Double.toString(amount);
        this.signature=CryptographyHelper.applyECDSASignature(privateKey,data);
    }
    //verify signature
    public boolean verifySignature(){
        String data=sender.toString()+receiver.toString()+Double.toString(amount);
        return CryptographyHelper.verifyECDASSignature(sender,data,signature);
    }
}


