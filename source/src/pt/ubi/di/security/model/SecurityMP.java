package pt.ubi.di.security.model;

import java.io.*;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Random;

/**
 * //TODO different ciphers
 *  plaintext   |            XB                       |
 *  message     | secret | index | SHA1(secret|index) |
 *
 *  random     |             XB              |
 *   noise     | SHA1(key) | SHA1(SHA1(key)) |
 *
 *  puzzle     |         XB        |       YB        |
 *             | message XOR noise | key(incomplete) |
 */
public class SecurityMP implements Serializable {

    private final int N; //number of puzzles
    private final int secretSize; //size of the key to be used for encryption
    private final int keySize; //size of the key to be used for encryption
    private final int bytesToGuess; //amount of bytes to be omitted from the encryption key
    private boolean flag; // flag to know if solution was found
    private static final int HASH_SIZE=20; // size of the hash produced by SHA1

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
     * @param secretSize int - (Bytes) size of the secret key to be exchanged
     * @param keySize int - (Bytes) size of the key to be used for encryption
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

        for(int i=1;i<=this.N;++i) { ids.add(i); }
        if(verbose)
            System.out.println("Creating puzzles.....");
        int count = 0;
        for(int i=0;i<this.N;++i) {
            if(verbose) {
                if( count%100 == 0 && i!=0)
                    System.out.print("*");
                if( count%10000 == 0 && i!=0)
                    System.out.print("\n");
                count++;
            }
            puzzles.add(CreatePuzzle(this.secretSize,this.keySize,this.bytesToGuess));
        }
        if(verbose)
            System.out.print("\n");
    }

    /**
     * <p>Constructor for an already created set of puzzles</p>
     * <p>Will solve a given puzzle, creating</p>
     * @param puzzles ArrayList<MerklePuzzle> - list of puzzles
     * @param index int - index of the desired puzzle to solve (on the list)
     */
    public SecurityMP(ArrayList<MerklePuzzle> puzzles,int index,boolean verbose) {
        this(puzzles.size(),puzzles.get(0).getSizeSecret(),puzzles.get(0).getSizeKey(),puzzles.get(0).getBytesToGuess(),false);
        this.puzzles = puzzles;
        solve(index, verbose);
    }

    /**
     * <p>Constructor for an already created set of puzzles</p>
     * @param puzzles ArrayList<MerklePuzzle> - list of puzzles
     */
    public SecurityMP(ArrayList<MerklePuzzle> puzzles, boolean verbose) {
        this(puzzles.size(),puzzles.get(0).getSizeSecret(),puzzles.get(0).getSizeKey(),puzzles.get(0).getBytesToGuess(),false);
        this.puzzles = puzzles;
        solve(-1,verbose);
    }

    /**
     * Method to start a key exchange with whoever is connected, allows different options
     * @param outputStream ObjectOutputStream - output information to send information
     * @param inputStream ObjectInputStream - inputStream to receive information
     * @param options String[] - string array of options for more custom interaction
     * @return byte[] - returns the key in byte array format
     */
    public static byte[] startExchange(ObjectOutputStream outputStream, ObjectInputStream inputStream, String[] options) {
        System.out.println(">Starting Merkle Puzzles key exchange");
        try {
            int N = 10000;
            int secretSizeBytes = 32;
            int keySizeBytes = 16;
            int bytesToGuess = 2;
            boolean verbose = false;

            int index = SecurityUtil.lookOptions(options,new String[]{"-n"});
            if (index!=-1) {
                try {
                    N = Integer.parseInt(options[index + 1]);
                } catch (Exception e) {
                    System.out.println("Error: "+e.getMessage() + " 10000 being used as default.");
                }
            }

            index = SecurityUtil.lookOptions(options,new String[]{"-lK","-lengthK","--lengthK"});
            if(index!=-1) {
                try {
                    secretSizeBytes = Integer.parseInt(options[index + 1]);
                } catch (Exception e) {
                    System.out.println("Error: "+e.getMessage() + " 32 being used as default.");
                }
            }
            index = SecurityUtil.lookOptions(options,new String[]{"-lk","-lengthk","--lengthk"});
            if(index!=-1) {
                try {
                    keySizeBytes = Integer.parseInt(options[index + 1]);
                } catch (Exception e) {
                    System.out.println("Error: "+e.getMessage() + " 16 being used as default.");
                }
            }
            index = SecurityUtil.lookOptions(options,new String[]{"-d","-difficulty","--difficulty"});
            if(index!=-1) {
                try {
                    bytesToGuess = Integer.parseInt(options[index + 1]);
                } catch (Exception e) {
                    System.out.println("Error: "+e.getMessage() + " 2 being used as default.");
                }
            }
            index = SecurityUtil.lookOptions(options,new String[]{"-v","-verbose","--verbose"});
            if(index!=-1)
                verbose = true;
            outputStream.writeObject(verbose);
            SecurityMP factoryMP = new SecurityMP(N,secretSizeBytes,keySizeBytes,bytesToGuess,verbose);
            outputStream.writeObject(factoryMP);
            MerklePuzzle puzzleIndex = (MerklePuzzle) inputStream.readObject();
            factoryMP.solveIndex(puzzleIndex, verbose);
            return factoryMP.getChosenSecretKey();
        } catch (Exception e) {
            System.out.println("Error on MP key exchange(start): "+e.getMessage());
        }
        return new byte[0];
    }

    /**
     * Method to accept and participate on a key exchange with whoever is connected
     * @param outputStream ObjectOutputStream - output information to send information
     * @param inputStream ObjectInputStream - inputStream to receive information
     * @return byte[] - returns the key in byte array format
     */
    public static byte[] receiveExchange(ObjectOutputStream outputStream, ObjectInputStream inputStream) {
        System.out.println(">Starting Merkle Puzzles key exchange");
        try {
            boolean verbose = (boolean) inputStream.readObject();
            SecurityMP factoryMP = (SecurityMP) inputStream.readObject();
            SecurityMP resultMP = new SecurityMP(factoryMP.getPuzzles(),verbose);
            resultMP.encryptIndex(verbose);
            outputStream.writeObject(resultMP.getFinalSolvedPuzzle());

            return resultMP.getChosenSecretKey();
        } catch (Exception e) {
            System.out.println("Error on MP key exchange(receive): "+e.getMessage());
        }
        return new byte[0];
    }

    /**
     * <p>Create a single puzzle:</p>
     * <p>PUZZLE(48B): puzzle message XOR noise(40B) | key(8B)</p>
     * @param secretSize int - (Bytes) size of secret key
     * @param keySize int - (Bytes) size of key used to generate noise -> "encrypt message"
     * @param bytesToGuess int - amount of bytes to remove from key
     * @return MerklePuzzle
     */
    private MerklePuzzle CreatePuzzle(int secretSize, int keySize, int bytesToGuess) {
        byte[] key = SecurityUtil.generateNumber(keySize);
        byte[] keyShorted = new byte[key.length-bytesToGuess];
        if (key.length - bytesToGuess >= 0)
            System.arraycopy(key, bytesToGuess, keyShorted, 0, key.length - bytesToGuess);
        byte[] message = createMessage(secretSize);
        byte[] cipher = SecurityUtil.oneTimePadEncrypt(message,key,message.length);
        byte[] puzzle = new byte[cipher.length+keyShorted.length];
        System.arraycopy(cipher,0,puzzle,0,cipher.length);
        System.arraycopy(keyShorted,0,puzzle,cipher.length,keyShorted.length);
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
        byte[] index = SecurityUtil.intToByte(getAvailableID());
        byte[] digest = SecurityUtil.hash("SHA1",secret);
        byte[] message = new byte[secret.length+index.length+digest.length];
        System.arraycopy(secret,0,message,0,secret.length);
        System.arraycopy(index,0,message,secret.length,index.length);
        System.arraycopy(digest,0,message,secret.length+index.length,digest.length);
        secretKeys.add(secret);
        return message;
    }

    /**
     * Solves a puzzle, using a recursive function
     * @param puzzleToGuess int - index of the puzzle to solve
     * @param verbose boolean - verbose
     */
    private void solve(int puzzleToGuess, boolean verbose) {
        if (0<puzzleToGuess && puzzleToGuess<puzzles.size()) {
            solvePuzzleRec(puzzleToGuess,verbose);
        }
        else {
            solvePuzzleRec(SecurityUtil.generateNumber(BigInteger.valueOf(puzzles.size()),false).intValue(),verbose);
        }
    }

    /**
     * Function that calls a recursive function to solve a given puzzle
     * @param index int - index of the puzzle to solve (on the list)
     */
    public void solvePuzzleRec(int index,boolean verbose) {
        MerklePuzzle puzzle = puzzles.get(index);
        solvePuzzleRec(puzzle,verbose);
    }

    /**
     * Function that calls a recursive function to solve a given puzzle
     * @param puzzle MerklePuzzle - puzzle to solve
     */
    public void solvePuzzleRec(MerklePuzzle puzzle,boolean verbose) {
        byte[] partKey = new byte[puzzle.getSizeKey()];// partKey + values to guess
        System.arraycopy(puzzle.getPuzzle(),puzzle.getSizeCipherMessage(),partKey,puzzle.getBytesToGuess(),partKey.length-puzzle.getBytesToGuess());
        byte[] cipher = new byte[puzzle.getSizeCipherMessage()];
        System.arraycopy(puzzle.getPuzzle(),0,cipher,0,cipher.length);
        flag = false;
        if (verbose) {
            System.out.println(">Solving puzzle");
            System.out.println("Puzzle: " + SecurityUtil.byteArrayToString(puzzle.getPuzzle()));
            System.out.println("Partial key: " + SecurityUtil.byteArrayToHex(partKey));
        }

        solvePuzzleAux(puzzle,cipher,puzzle.getBytesToGuess()-1,partKey,verbose);
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
    private void solvePuzzleAux(MerklePuzzle puzzle, byte[] cipher, int dept, byte[] partKey, boolean verbose) {
        int count = 0;
        if(dept<0 || flag) {
            return;
        }
        for(int i =-128;i<128;i++) {
            if(verbose) {
                if( count % 5 == 0) {
                    System.out.print(".");
                }
                if( i == 127) {
                    System.out.print("\n");
                }
                count++;
            }

            partKey[dept]=(byte) i;//try to replicate key

            byte[] message = SecurityUtil.oneTimePadEncrypt(cipher,partKey,puzzle.getSizeCipherMessage());//try to decipher the cipher

            byte[] messageDigestExpected = new byte[HASH_SIZE];//get the hash in the message
            System.arraycopy(message,message.length-HASH_SIZE,messageDigestExpected,0,messageDigestExpected.length);

            byte[] secretKey = new byte[puzzle.getSizeSecret()];//get the secretKey from the message
            System.arraycopy(message,0,secretKey,0,secretKey.length);

            byte[] messageDigestActual = SecurityUtil.hash("SHA1",secretKey);//message digest the secretKey

            if(SecurityUtil.checkHash(messageDigestActual,messageDigestExpected)) {//compare the hashes if they are equal than means puzzle has been cracked
                byte[] indexByteArray = new byte[puzzle.getTotalSize()-(puzzle.getSizeKey()-puzzle.getBytesToGuess())-puzzle.getSizeSecret()-HASH_SIZE];
                System.arraycopy(message,0,chosenSecretKey,0,chosenSecretKey.length);//get secretKey
                System.arraycopy(message,chosenSecretKey.length,indexByteArray,0,indexByteArray.length);//get index
                indexOfSecretKey = SecurityUtil.byteToInt(indexByteArray);
                flag = true;
                if(verbose) {
                    System.out.println("\n>Puzzle solved!!!!");
                    System.out.println("KEY: "+ SecurityUtil.byteArrayToHex(chosenSecretKey));
                    System.out.println("INDEX: "+ indexOfSecretKey);
                }
                break;
            }
            if(flag)
                return;
            solvePuzzleAux(puzzle,cipher,dept-1,partKey,verbose);
        }
    }

    /**
     * <p>Function that encrypts the index and the index message digest of the solved puzzle, to be sent to the puzzles creator</p>
     * <p>Saves a MerklePuzzle with the indexEncrypted and indexHashEncrypted of the solved puzzle</p>
     */
    public void encryptIndex(boolean verbose) {
        if(verbose)
            System.out.println("Encrypting index...");
        byte[] indexOfSecretKeyByte = SecurityUtil.intToByte(indexOfSecretKey);
        byte[] indexEncrypted = SecurityUtil.oneTimePadEncrypt(indexOfSecretKeyByte,chosenSecretKey,indexOfSecretKeyByte.length);
        byte[] indexHashEncrypted = SecurityUtil.oneTimePadEncrypt(SecurityUtil.hash("SHA1",indexOfSecretKeyByte),chosenSecretKey,HASH_SIZE);
        finalSolvedPuzzle = new MerklePuzzle(indexEncrypted,indexHashEncrypted);
        if(verbose)
            System.out.println(finalSolvedPuzzle.toStringSolved());
    }

    /**
     * <p>Function that encrypts the index and the index message digest of the solved puzzle, to be sent to the puzzles creator</p>
     * @return MerklePuzzle - returns a MerklePuzzle with the indexEncrypted and indexHashEncrypted of the solved puzzle
     */
    public MerklePuzzle encryptIndexRet(boolean verbose) {
        if(verbose)
            System.out.println("Encrypting index...");
        byte[] indexOfSecretKeyByte = SecurityUtil.intToByte(indexOfSecretKey);
        byte[] indexEncrypted = SecurityUtil.oneTimePadEncrypt(indexOfSecretKeyByte,chosenSecretKey,indexOfSecretKeyByte.length);
        byte[] indexHashEncrypted = SecurityUtil.oneTimePadEncrypt(SecurityUtil.hash("SHA1",indexOfSecretKeyByte),chosenSecretKey,HASH_SIZE);
        finalSolvedPuzzle = new MerklePuzzle(indexEncrypted,indexHashEncrypted);
        if(verbose)
            System.out.println(finalSolvedPuzzle.toStringSolved());
        return new MerklePuzzle(indexEncrypted,indexHashEncrypted);
    }

    /**
     * <p>Function to solve an encrypted index to its matching key</p>
     * @param puzzle MerklePuzzle - puzzle with the index to solve
     */
    public void solveIndex(MerklePuzzle puzzle, boolean verbose) {
        if(verbose)
            System.out.println("Decrypting index...");
        finalSolvedPuzzle = puzzle;
        byte[] indexEncryptedTemp = puzzle.getIndexEncrypted();
        byte[] indexHashEncryptedTemp = puzzle.getIndexHashEncrypted();
        for(byte[] k : secretKeys) {
            byte[] index = SecurityUtil.oneTimePadEncrypt(indexEncryptedTemp,k,indexEncryptedTemp.length);
            byte[] indexHashExpected = SecurityUtil.oneTimePadEncrypt(indexHashEncryptedTemp,k,HASH_SIZE);
            byte[] indexHash = SecurityUtil.hash("SHA1",index);
            if(SecurityUtil.checkHash(indexHash,indexHashExpected)) {
                if(verbose) {
                    System.out.println("KEY: " + SecurityUtil.byteArrayToHex(k));
                    System.out.println("INDEX: " + SecurityUtil.byteToInt(index));
                }
                chosenSecretKey = k;
                return;
            }
        }
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

    public static void help() {
        System.out.println(
                """
                        Merkle Puzzles KAP Commands =====================================================================================
                        -n \033[3mnumber\033[0m, amount of puzzles - default 10000
                        -lK -lengthK --lengthK \033[3mlengthByte\033[0m, length in bytes of the secret key - default 32
                        -lk -lengthk --lengthk \033[3mlengthByte\033[0m, length in bytes of (puzzle) encryption key - default 16
                        -d -difficulty --difficulty \033[3mamountOfBytes\033[0m, amount of bytes to remove from encryption key (the higher the longer) - default 2
                        -v -verbose --verbose, shows verbose
                        ==================================================================================================================
                        """
        );
    }

    public ArrayList<MerklePuzzle> getPuzzles() {
        return puzzles;
    }

    public byte[] getChosenSecretKey() {
        return chosenSecretKey;
    }

    public MerklePuzzle getFinalSolvedPuzzle() {
        return finalSolvedPuzzle;
    }
}