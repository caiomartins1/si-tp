package pt.ubi.di.security.model;

import java.io.*;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Random;

/**
 * //TODO different ciphers
 * //TODO add comment
 *  plaintext   |  16B   |   4B  |        20B         | TOTAL 40B
 *  message     | secret | index | SHA1(secret|index) |
 *
 *  random     |    20B     |       20B      | TOTAL 40B
 *   noise     | SHA1(key) | SHA1(SHA1(key)) |
 *
 *  puzzle     |        40B        |       6B        | TOTAL 46B
 *             | message XOR noise | key(incomplete) |
 */
public class SecurityMP implements Serializable {

    private final int N; //number of puzzles
    private final int secretSize; //size of the secret key to be exchanged
    private final int keySize; //size of the key to be used for encryption
    private final int bytesToGuess; //amount of bytes to be omitted from the encryption key
    private boolean flag; // flag to know if solution was found
    private static final int HASHSIZE=20; // size of the hash produced by SHA1

    /**
     * A byte array of the chosen secret key:
     * The key to be used for secure communication
     */
    private byte[] chosenSecretKey;
    /**
     * A byte array of the index of the secret key:
     * Index given to the secret key (not position on the array list)
     */
    private int indexOfSecretKey;
    /**
     * A merkle puzzle with the encrypted index and index hash of the solved puzzle
     * to return to sender
     */
    MerklePuzzle finalSolvedPuzzle;

    /**
     * Array list of all the available ids to give to the puzzles
     */
    private final ArrayList<Integer> ids;

    /**
     * Array list of all the created puzzles
     */
    private ArrayList<MerklePuzzle> puzzles; //list of puzzles
    /**
     * Array list of all the keys that where created to send in puzzle format
     */
    private final ArrayList<byte[]> secretKeys; //list of puzzles

    Random rand = new Random();

    /**
     * <p>Constructor to setup a key exchange using Merkle Puzzle</p>
     * <p>Will create a N amount of puzzles with all the parameters given and save and arrayList of them</p>
     * @param N int - amount of puzzles to create
     * @param secretSize int - size of the secret key to be exchanged
     * @param keySize int - size of the key to be used for encryption
     * @param bytesToGuess int - amount of bytes to be omitted from the encryption key (higher values means more time and more secure)
     * @param verbose boolean - allow verbose
     */
    public SecurityMP(int N, int secretSize,int keySize,int bytesToGuess,boolean verbose) {
        if(N>0)
            this.N = N;
        else {
            System.out.println("Amount of puzzles invalid - 10000 being used as default.");
            this.N = 10000;
        }
        if(secretSize>0)
            this.secretSize = secretSize;
        else {
            System.out.println("Secret key size invalid - 32 being used as default.");
            this.secretSize = 32;
        }
        if(keySize>0)
            this.keySize = keySize;
        else {
            System.out.println("Encryption key size invalid - 16 being used as default.");
            this.keySize = 16;
        }
        if(0<bytesToGuess && bytesToGuess<=keySize)
            this.bytesToGuess = bytesToGuess;
        else {
            if(this.keySize==1) {
                System.out.println("Bytes to be removed from key invalid - 1 being used as default.");
                this.bytesToGuess = 1;
            }
            else {
                System.out.println("Bytes to be removed from key invalid - 2 being used as default.");
                this.bytesToGuess = 2;
            }
        }
        this.chosenSecretKey = new byte[secretSize];
        flag = false;
        this.ids = new ArrayList<>();
        this.puzzles = new ArrayList<>();
        this.secretKeys = new ArrayList<>();

        for(int i=1;i<=N;++i) { ids.add(i); }
        if(verbose)
            System.out.println("Creating puzzles.....");
        for(int i=0;i<N;++i) {
            if(verbose)
                System.out.print("*");
            puzzles.add(CreatePuzzle(secretSize,keySize,bytesToGuess));
        }
    }

    /**
     * <p>Constructor for an already created set of puzzles</p>
     * <p>Will solve a given puzzle, creating</p>
     * @param puzzles ArrayList<MerklePuzzle> - list of puzzles
     * @param index int - index of the desired puzzle to solve (on the list)
     */
    public SecurityMP(ArrayList<MerklePuzzle> puzzles,int index) {
        this(puzzles.size(),puzzles.get(0).getSizeSecret(),puzzles.get(0).getSizeKey(),puzzles.get(0).getBytesToGuess(),false);
        this.puzzles = puzzles;
        solve(index);
    }

    /**
     * <p>Constructor for an already created set of puzzles</p>
     * @param puzzles ArrayList<MerklePuzzle> - list of puzzles
     */
    public SecurityMP(ArrayList<MerklePuzzle> puzzles) {
        this(puzzles.size(),puzzles.get(0).getSizeSecret(),puzzles.get(0).getSizeKey(),puzzles.get(0).getBytesToGuess(),false);
        this.puzzles = puzzles;
        solve(-1);
    }

    /**
     * <p>Empty constructor uses default values</p>
     * <p>Will create a N amount of puzzles with all the parameters given and save and arrayList of them</p>
     * <p>N=100 secret=32 key=16 bytesMissing=3</p>
     */
    public SecurityMP() {
        this(10000,32,16,3,false);
    }

    /**
     * <p>Constructor that allows you to choose how many puzzles to create</p>
     * <p>Uses default values for the rest</p>
     * <p>secret=32 key=16 bytesMissing=3</p>
     * <p>Will create a N amount of puzzles with all the parameters given and save and arrayList of them</p>
     * @param N int - amount of puzzles to create
     */
    public SecurityMP(int N) {
        this(N,32,16,3,false);
    }

    /**
     * <p>Constructor that allows you to choose how many puzzles to create and secret key size</p>
     * <p>Uses default values for the rest</p>
     * <p>key=16 bytesMissing=3</p>
     * <p>Will create a N amount of puzzles with all the parameters given and save and arrayList of them</p>
     * @param N int - amount of puzzles to create
     * @param secretSize int - how many bytes should the secret key have
     */
    public SecurityMP(int N,int secretSize) {
        this(N,secretSize,16,3,false);
    }

    /**
     * <p>Constructor that allows you to choose how many puzzles to create, secret key size and how many bytes to remove from the key</p>
     * <p>Uses default values for the rest<p>
     * <p>key=16</p>
     * <p>Will create a N amount of puzzles with all the parameters given and save and arrayList of them</p>
     * @param N int - amount of puzzles to create
     * @param secretSize int - how many bytes should the secret key have
     * @param bytesToGuess int - how many bytes should be removed from the key
     */
    public SecurityMP(int N, int secretSize,int bytesToGuess) {
        this(N,secretSize,16,bytesToGuess,false);
    }

    private void solve(int puzzleToGuess) {
        if (0<puzzleToGuess && puzzleToGuess<puzzles.size()) {
            solvePuzzleRec(puzzleToGuess);
        }
        else {
            solvePuzzleRec(SecurityUtil.generateNumber(BigInteger.valueOf(puzzles.size()),false).intValue());
        }
    }

    /**
     * <p>Create a single puzzle:</p>
     * <p>PUZZLE(48B): puzzle message XOR noise(40B) | key(8B)</p>
     * @param secretSize int - size of secret key
     * @param keySize int - size of key used to generate noise -> "encrypt message"
     * @param bytesToGuess int - amount of bytes to remove from key
     * @return MerklePuzzle
     */
    private MerklePuzzle CreatePuzzle(int secretSize, int keySize, int bytesToGuess) {
        byte[] key = SecurityUtil.generateNumber(keySize);
        byte[] keyShorted = new byte[key.length-bytesToGuess];
        for(int i=0;i<key.length-bytesToGuess;i++)//TODO
            keyShorted[i]=key[i+bytesToGuess];
        byte[] message = createMessage(secretSize);
        byte[] cipher = SecurityUtil.oneTimePadEncrypt(message,key,message.length);
        byte[] puzzle = new byte[cipher.length+keyShorted.length];
        System.arraycopy(cipher,0,puzzle,0,cipher.length);
        System.arraycopy(keyShorted,0,puzzle,cipher.length,keyShorted.length);

        /*System.out.println("__________________Create Puzzle__________________");
        System.out.println("KEY:"+SecurityUtil.byteArrayToHex(key)+"SIZE: "+key.length);
        System.out.println("PARTIAL KEY:"+SecurityUtil.byteArrayToHex(keyShorted)+" SIZE:"+keyShorted.length);
        System.out.println("cipher:"+SecurityUtil.byteArrayToString(cipher)+" SIZE:"+cipher.length);
        System.out.println("puzzle:"+SecurityUtil.byteArrayToString(puzzle)+" SIZE:"+puzzle.length);*/

        return new MerklePuzzle(puzzle,cipher.length,keySize,bytesToGuess,puzzle.length,secretSize);
    }

    /**
     * <p>Create a message to encrypt and send as a puzzle</p>
     * <p>Example: MESSAGE(40B): secret(16B) | index(4B) | SHA1(secret|index)(20B)</p>
     * @param byteSize int - size of the secure key
     * @return message byte[] - in byte array
     */
    private byte[] createMessage(int byteSize) {
        byte[] secret = SecurityUtil.generateNumber(byteSize);
        byte[] index = SecurityUtil.intToByte(getAvailableIDOrder());
        byte[] digest = SecurityUtil.hash("SHA1",secret);
        byte[] message = new byte[secret.length+index.length+digest.length];
        System.arraycopy(secret,0,message,0,secret.length);
        System.arraycopy(index,0,message,secret.length,index.length);
        System.arraycopy(digest,0,message,secret.length+index.length,digest.length);//TODO need to add index
        secretKeys.add(secret);
        /*System.out.println("__________________Create Message__________________");
        System.out.println("Secret key unencrypted(hex):"+SecurityUtil.byteArrayToHex(secret)+" Size:"+secret.length);
        System.out.println("hash: "+SecurityUtil.byteArrayToHex(digest)+" Size:"+digest.length);
        System.out.println("Index: "+SecurityUtil.byteToInt(index)+" Size:"+index.length);*/
        return message;
    }

    /**
     * Function that calls a recursive function to solve a given puzzle
     * @param index int - index of the puzzle to solve (on the list)
     */
    private void solvePuzzleRec(int index) {
        MerklePuzzle puzzle = puzzles.get(index);
        byte[] partKey = new byte[puzzle.getSizeKey()];// partKey + values to guess
        System.arraycopy(puzzle.getPuzzle(),puzzle.getSizeCipherMessage(),partKey,puzzle.getBytesToGuess(),partKey.length-puzzle.getBytesToGuess());
        byte[] cipher = new byte[puzzle.getSizeCipherMessage()];
        System.arraycopy(puzzle.getPuzzle(),0,cipher,0,cipher.length);
        flag = false;
        System.out.println("__________________Solving puzzle__________________");
        System.out.println("Puzzle:"+SecurityUtil.byteArrayToString(puzzle.getPuzzle()));
        System.out.println("Partial key(hex):"+SecurityUtil.byteArrayToHex(partKey));

        solvePuzzleAux(puzzle,cipher,puzzle.getBytesToGuess()-1,partKey);
    }

    /**
     * Function that calls a recursive function to solve a given puzzle
     * @param puzzle MerklePuzzle - puzzle to solve
     */
    private void solvePuzzleRec(MerklePuzzle puzzle) {
        byte[] partKey = new byte[puzzle.getSizeKey()];// partKey + values to guess
        System.arraycopy(puzzle.getPuzzle(),puzzle.getSizeCipherMessage(),partKey,puzzle.getBytesToGuess(),partKey.length-puzzle.getBytesToGuess());
        byte[] cipher = new byte[puzzle.getSizeCipherMessage()];
        System.arraycopy(puzzle.getPuzzle(),0,cipher,0,cipher.length);
        flag = false;
        System.out.println("__________________Solving puzzle__________________");
        System.out.println("Puzzle:"+SecurityUtil.byteArrayToString(puzzle.getPuzzle()));
        System.out.println("Partial key(hex):"+SecurityUtil.byteArrayToHex(partKey));

        solvePuzzleAux(puzzle,cipher,puzzle.getBytesToGuess()-1,partKey);
    }

    /**
     * <p>Solve a given puzzle by brute forcing the partial key until the right key is found:</p>
     * <p>its known that the key is the right one when the hash on the message matches the message digest from the secret found</p>
     * <p>If a puzzle was found message is printed and the resulting key and index are saved</p>
     * @param puzzle MerklePuzzle - the puzzle to be solved
     * @param cipher byte[] - byte array of the cipher to crack
     * @param dept int - amount of bytes to brute force (depth of the array)
     * @param partKey byte[] - byte array of the partial key "fill" the blanks with possible values
     */
    private void solvePuzzleAux(MerklePuzzle puzzle, byte[] cipher, int dept, byte[] partKey) {
        if(dept<0 || flag) {
            return;
        }
        for(int i =-128;i<128;i++) {
            //System.out.print(".");TODO
            partKey[dept]=(byte) i;//try to replicate key

            byte[] message = SecurityUtil.oneTimePadEncrypt(cipher,partKey,puzzle.getSizeCipherMessage());//try to decipher the cipher

            byte[] messageDigestExpected = new byte[HASHSIZE];//get the hash in the message
            System.arraycopy(message,message.length-HASHSIZE,messageDigestExpected,0,messageDigestExpected.length);

            byte[] secretKey = new byte[puzzle.getSizeSecret()];//get the secretKey from the message
            System.arraycopy(message,0,secretKey,0,secretKey.length);

            byte[] messageDigestActual = SecurityUtil.hash("SHA1",secretKey);//message digest the secretKey

            if(SecurityUtil.checkHash(messageDigestActual,messageDigestExpected)) {//compare the hashes if they are equal than means puzzle has been cracked
                byte[] indexByteArray = new byte[puzzle.getTotalSize()-(puzzle.getSizeKey()-puzzle.getBytesToGuess())-puzzle.getSizeSecret()-HASHSIZE];
                System.arraycopy(message,0,chosenSecretKey,0,chosenSecretKey.length);//get secretKey
                System.arraycopy(message,chosenSecretKey.length,indexByteArray,0,indexByteArray.length);//get index
                indexOfSecretKey = SecurityUtil.byteToInt(indexByteArray);
                flag = true;
                System.out.println("\n__________________Puzzle solved__________________");
                System.out.println("KEY(hex): "+ SecurityUtil.byteArrayToHex(chosenSecretKey));
                System.out.println("INDEX: "+ indexOfSecretKey);
                break;
            }
            if(flag)
                return;
            //System.out.print("*");TODO
            solvePuzzleAux(puzzle,cipher,dept-1,partKey);
        }
    }

    /**
     * <p>Function that encrypts the index and the index message digest of the solved puzzle, to be sent to the puzzles creator</p>
     * <p>Saves a MerklePuzzle with the indexEncrypted and indexHashEncrypted of the solved puzzle</p>
     */
    public void encryptIndex() {
        System.out.println("encrypting Index...");
        byte[] indexOfSecretKeyByte = SecurityUtil.intToByte(indexOfSecretKey);
        byte[] indexEncrypted = SecurityUtil.oneTimePadEncrypt(indexOfSecretKeyByte,chosenSecretKey,indexOfSecretKeyByte.length);
        byte[] indexHashEncrypted = SecurityUtil.oneTimePadEncrypt(SecurityUtil.hash("SHA1",indexOfSecretKeyByte),chosenSecretKey,HASHSIZE);
        //finalSolvedPuzzle.toStringSolved();
        finalSolvedPuzzle = new MerklePuzzle(indexEncrypted,indexHashEncrypted);
    }

    /**
     * <p>Function that encrypts the index and the index message digest of the solved puzzle, to be sent to the puzzles creator</p>
     * @return MerklePuzzle - returns a MerklePuzzle with the indexEncrypted and indexHashEncrypted of the solved puzzle
     */
    public MerklePuzzle encryptIndexRet() {
        System.out.println("encrypting Index...");
        byte[] indexOfSecretKeyByte = SecurityUtil.intToByte(indexOfSecretKey);
        byte[] indexEncrypted = SecurityUtil.oneTimePadEncrypt(indexOfSecretKeyByte,chosenSecretKey,indexOfSecretKeyByte.length);
        byte[] indexHashEncrypted = SecurityUtil.oneTimePadEncrypt(SecurityUtil.hash("SHA1",indexOfSecretKeyByte),chosenSecretKey,HASHSIZE);
        finalSolvedPuzzle = new MerklePuzzle(indexEncrypted,indexHashEncrypted);
        return new MerklePuzzle(indexEncrypted,indexHashEncrypted);
    }

    /**
     * <p>Function to solve an encrypted index to its matching key</p>
     * @param puzzle MerklePuzzle - puzzle with the index to solve
     */
    public void solveIndex(MerklePuzzle puzzle) {
        System.out.println("Decrypting index...");
        System.out.println("AA:"+puzzle.toStringSolved());
        finalSolvedPuzzle = puzzle;
        byte[] indexEncryptedTemp = puzzle.getIndexEncrypted();
        byte[] indexHashEncryptedTemp = puzzle.getIndexHashEncrypted();
        for(byte[] k : secretKeys) {
            byte[] index = SecurityUtil.oneTimePadEncrypt(indexEncryptedTemp,k,indexEncryptedTemp.length);
            byte[] indexHashExpected = SecurityUtil.oneTimePadEncrypt(indexHashEncryptedTemp,k,HASHSIZE);
            byte[] indexHash = SecurityUtil.hash("SHA1",index);
            if(SecurityUtil.checkHash(indexHash,indexHashExpected)) {
                System.out.println("KEY(hex): "+SecurityUtil.byteArrayToHex(k));
                System.out.println("INDEX: "+SecurityUtil.byteToInt(index));
                chosenSecretKey = k;
                return;
            }
        }
    }

    public static byte[] startExchange(ObjectOutputStream outputStream, ObjectInputStream inputStream) {
        System.out.println("_____________Starting Merkle Puzzles key exchange_____________");
        try {
            SecurityMP factoryMP = new SecurityMP();
            outputStream.writeObject(factoryMP);
            MerklePuzzle puzzleIndex = (MerklePuzzle) inputStream.readObject();
            factoryMP.solveIndex(puzzleIndex);
            return factoryMP.getChosenSecretKey();
        } catch (Exception e) {
            System.out.println("Error on MP key exchange(start): "+e.getMessage());
        }
        return new byte[0];
    }

    public static byte[] receiveExchange(ObjectOutputStream outputStream, ObjectInputStream inputStream) {
        System.out.println("_____________Starting Merkle Puzzles key exchange_____________");
        try {
            SecurityMP factoryMP = (SecurityMP) inputStream.readObject();
            SecurityMP resultMP = new SecurityMP(factoryMP.getPuzzles());
            resultMP.encryptIndex();
            outputStream.writeObject(resultMP.getFinalSolvedPuzzle());

            return resultMP.getChosenSecretKey();
        } catch (Exception e) {
            System.out.println("Error on MP key exchange(receive): "+e.getMessage());
        }
        return new byte[0];
    }

    /**
     * Chooses a random id from the available ones,
     * removes the chosen one from the pool
     * @return int id
     */
    private int getAvailableID() {
        return ids.remove(rand.nextInt(ids.size()));
    }

    /**
     * Chooses a id by order from the available ones,
     * removes the chosen one from the pool
     * @return int id
     */
    private int getAvailableIDOrder() {
        return ids.remove(0);
    }

    public ArrayList<MerklePuzzle> getPuzzles() {
        return puzzles;
    }

    public byte[] getChosenSecretKey() {
        return chosenSecretKey;
    }

    public String getChosenSecretKeyToString() {
        return SecurityUtil.byteArrayToHex(chosenSecretKey);
    }

    public void setFinalSolvedPuzzle(MerklePuzzle finalSolvedPuzzle) {
        this.finalSolvedPuzzle = finalSolvedPuzzle;
    }

    public MerklePuzzle getFinalSolvedPuzzle() {
        return finalSolvedPuzzle;
    }

    public int getIndex() {
        return indexOfSecretKey;
    }
}