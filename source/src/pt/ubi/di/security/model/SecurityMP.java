package pt.ubi.di.security.model;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Random;

/**
 * //TODO had verbose
 * //TODO multiple/variable sizes
 * //TODO different ciphers
 * //TODO fix try catches
 *
 * Need to create puzzle
 * Cipher the puzzle <- this the puzzle the solution is solving the cipher (5min per each many puzzles means
 * more time
 *
 * maybe create class for chiper
 *
 * do this multiple times
 *
 * a puzzle has a key and a number in there (random)
 * send puzzles wait for number that was solved
 *
 *  plaintext   |  16B   |   4B  |        20B         | TOTAL 40B
 *  message     | secret | index | SHA1(secret|index) |
 *
 *  random     |    20B     |       20B      | TOTAL 40B
 *   noise     | SHA1(key) | SHA1(SHA1(key)) |
 *
 *  puzzle     |        40B        |       6B        | TOTAL 46B
 *             | message XOR noise | key(incomplete) |
 */
public class SecurityMP {
    int N; //number of puzzles
    ArrayList<Integer> ids; //all ids available

    ArrayList<MerklePuzzle> puzzles; //list of puzzles

    Random rand;

    /** TODO
     * Constructs the interaction
     * creates N puzzles to be sent
     * @param N amount of puzzles
     */
    public SecurityMP(int N) {
        rand = new Random();
        this.N = N;
        this.ids = new ArrayList<>();
        this.puzzles = new ArrayList<>();
        for(int i=1;i<=N;++i) {
            ids.add(i);
        }
        for(int i=0;i<N;++i) {
            puzzles.add(CreatePuzzle(16));
        }
        System.out.println("--------\n"+            puzzles.get(40).toString() + "--------\n");
        SolvePuzzle(puzzles.remove(40));
    }


    /**
     * Create a single puzzle:
     * PUZZLE(48B): puzzle message XOR noise(40B) | key(8B)
     * @param secretSize - size of secret key
     * @return
     */
    private MerklePuzzle CreatePuzzle(int secretSize) {
        int keySize = 8;
        int bytesToGuess = 2;
        byte[] key = SecurityUtil.generateNumber(keySize);
        byte[] keyShorted = new byte[key.length-2];
        for(int i=0;i<key.length-2;i++)
            keyShorted[i]=key[i+2];



        byte[] cipher = OneTimePadEncrypt(CreateMessage(secretSize),CreateNoise(key,40));
        byte[] puzzle = new byte[cipher.length+keyShorted.length];
        System.arraycopy(cipher,0,puzzle,0,cipher.length);
        System.arraycopy(keyShorted,0,puzzle,cipher.length,keyShorted.length);

        /*System.out.println("KEY:"+SecurityUtil.byteToString(key));
        //System.out.println("KEY SIZE:"+key.length);
        System.out.println("KEY S:"+SecurityUtil.byteToString(keyShorted));
        //System.out.println("KEY S SIZE:"+keyShorted.length);
        System.out.println("cipher:"+SecurityUtil.byteToString(cipher));
        //System.out.println("cipher SIZE:"+cipher.length);
        System.out.println("puzzle:"+SecurityUtil.byteToString(puzzle));
        //System.out.println("puzzle SIZE:"+puzzle.length);*/

        return new MerklePuzzle(puzzle,cipher.length,keySize,bytesToGuess,puzzle.length,secretSize);
    }

    /**
     * Create a message to encrypt and send as a puzzle
     * Example: MESSAGE(40B): secret(16B) | index(4B) | SHA1(secret|index)(20B)
     * @param byteSize size of secure key
     * @return message in byte array - byte[]
     */
    private byte[] CreateMessage(int byteSize) {

        byte[] message = new byte[0];
        byte[] secret = SecurityUtil.generateNumber(byteSize);
        int index = getAvailableID();
        byte[] digest;
        try {
            MessageDigest md = MessageDigest.getInstance("SHA1");
            md.update(secret);
            digest = md.digest();
            message = new byte[secret.length+4+digest.length];
            System.arraycopy(secret,0,message,0,secret.length);
            System.arraycopy(digest,0,message,secret.length+4,digest.length);//TODO need to add index


            /*System.out.println("Message unencrypted(byte):"+SecurityUtil.byteToString(message));
            System.out.println("Message unencrypted(hex):"+SecurityUtil.byteArrayToHex(message));
            System.out.println("Message size:"+message.length);
            System.out.println("Secret size:"+secret.length);
            System.out.println("msgDigest size:"+digest.length);*/

        } catch (NoSuchAlgorithmException e) {
            System.out.println("Error in message creation for Merkle Puzzle: "+e.getMessage());
        }

        return message;
    }

    /**
     * Create noise to encrypt message with,
     * Example: NOISE(40B): SHA1(key)(20B) | SHA1(SHA1(key))(20B)
     * @param key byte[] - array of bytes to be used to generate noise
     * @param sizeBytes int - size in bytes of the noise
     * @return byte[]- noise in byte array
     */
    private byte[] CreateNoise(byte[] key, int sizeBytes) {
        int index = 0;
        int n = (int) sizeBytes/20;
        byte[] prevDigest = SecurityUtil.Hash("SHA1",key);
        byte[] noise = new byte[sizeBytes];
        System.arraycopy(prevDigest,0,noise,index,(sizeBytes <20) ? noise.length : prevDigest.length);
        index = prevDigest.length;
        for(int i=1;i<n;i++) {
            byte[] digest = SecurityUtil.Hash("SHA1",prevDigest);
            System.arraycopy(digest,0,noise,index,(index <20) ? noise.length : digest.length);
            index += digest.length;
            prevDigest = digest;
        }
        //System.out.println("Noise unencrypted(byte):"+SecurityUtil.byteToString(noise));
        //System.out.println("Noise size:"+noise.length);
        return noise;
    }

    /**
     * One time pad encryption by doing --> message XOR key
     * @param message message to encrypt/decipher in byte[]
     * @param key key to encrypt/decipher with in byte[]
     * @return byte[] of encrypted/decrypted message
     */
    private static byte[] OneTimePadEncrypt(byte[] message, byte[] key) {
        if (message.length != key.length) {
            System.out.println("Key not same size as message");
            return new byte[0];
        }
        byte[] cipherBytes = new byte[message.length];
        for(int i=0;i<message.length;i++) {
            cipherBytes[i] = (byte) (message[i] ^ key[i]);
        }
        return cipherBytes;
    }

    private void SolvePuzzle(MerklePuzzle puzzle) {
        byte[] partKey = new byte[puzzle.getSizeKey()];// partKey + values to guess
        System.arraycopy(puzzle.getPuzzle(),puzzle.getTotalSize()-puzzle.getSizeKey()+puzzle.getBytesToGuess(),partKey,2,puzzle.getSizeKey()-puzzle.getBytesToGuess());
        System.out.println("puzzle(SOLVING):"+SecurityUtil.byteToString(puzzle.getPuzzle()));
        System.out.println("partKey(SOLVING):"+SecurityUtil.byteToString(partKey));

        for(int i =-128;i<128;i++) {
            for(int j =-128;j<128;j++) {
                partKey[0] = (byte) i;
                partKey[1] = (byte) j;

                byte[] noise = CreateNoise(partKey,40);

                byte[] cipher = new byte[puzzle.getSizeCipherMessage()];
                System.arraycopy(puzzle.getPuzzle(),0,cipher,0,cipher.length);

                byte[] decipher = OneTimePadEncrypt(cipher,noise);//TODO fucking stupid variable name change it later


                byte[] messageDigestExpected = new byte[20];
                System.arraycopy(decipher,/*TODO*/20,messageDigestExpected,0,messageDigestExpected.length);

                byte[] secret = new byte[puzzle.getSizeSecret()];
                System.arraycopy(decipher,0,secret,0,secret.length);
                byte[] messageDigestActual = SecurityUtil.Hash("SHA1",secret);

                if(MessageDigest.isEqual(messageDigestActual,messageDigestExpected)) {
                    System.out.println("Puzzle solved");
                    System.out.println("KEY(byte): "+ SecurityUtil.byteToString(decipher));
                    System.out.println("KEY(hex): "+ SecurityUtil.byteArrayToHex(decipher));
                    //System.out.println(puzzle.toString());
                    return;//TODO
                }
            }
        }
        System.out.println("Puzzle impossible???");
    }

    /**
     * Chooses a random id from the available ones,
     * removes the chosen one from the pool
     * @return int id
     */
    private int getAvailableID() {
        return ids.remove(rand.nextInt(ids.size()));
    }
}