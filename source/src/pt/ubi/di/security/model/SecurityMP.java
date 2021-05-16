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
            puzzles.add(CreatePuzzle(512,10,2/*TODO program byte size to solving problem*/));
        }
        System.out.println("--------\n"+            puzzles.get(0).toString() + "--------\n");
        SolvePuzzle(puzzles.remove(0));
    }


    /**
     * Create a single puzzle:
     * PUZZLE(48B): puzzle message XOR noise(40B) | key(8B)
     * @param secretSize int - size of secret key
     * @param keySize int - size of key used to generate noise -> "encrypt message"
     * @param bytesToGuess int - amount of bytes to remove from key
     * @return MerklePuzzle
     */
    private MerklePuzzle CreatePuzzle(int secretSize, int keySize, int bytesToGuess) {
        byte[] key = SecurityUtil.generateNumber(keySize);
        byte[] keyShorted = new byte[key.length-bytesToGuess];
        for(int i=0;i<key.length-2;i++)
            keyShorted[i]=key[i+2];
        byte[] message = CreateMessage(secretSize);
        byte[] cipher = OneTimePadEncrypt(message,CreateNoise(key,message.length));
        byte[] puzzle = new byte[cipher.length+keyShorted.length];
        System.arraycopy(cipher,0,puzzle,0,cipher.length);
        System.arraycopy(keyShorted,0,puzzle,cipher.length,keyShorted.length);

        System.out.println("KEY:"+SecurityUtil.byteArrayToString(key));
        System.out.println("KEY SIZE:"+key.length);
        System.out.println("KEY S:"+SecurityUtil.byteArrayToString(keyShorted));
        System.out.println("KEY S SIZE:"+keyShorted.length);
        System.out.println("cipher:"+SecurityUtil.byteArrayToString(cipher));
        System.out.println("cipher SIZE:"+cipher.length);
        System.out.println("puzzle:"+SecurityUtil.byteArrayToString(puzzle));
        System.out.println("puzzle SIZE:"+puzzle.length);

        return new MerklePuzzle(puzzle,cipher.length,keySize,bytesToGuess,puzzle.length,secretSize);
    }

    /**
     * Create a message to encrypt and send as a puzzle
     * Example: MESSAGE(40B): secret(16B) | index(4B) | SHA1(secret|index)(20B)
     * @param byteSize int - size of the secure key
     * @return message byte[] - in byte array
     */
    private byte[] CreateMessage(int byteSize) {
        byte[] secret = SecurityUtil.generateNumber(byteSize);
        byte[] index = SecurityUtil.IntToByte(getAvailableID());
        byte[] digest = SecurityUtil.Hash("SHA1",secret);
        byte[] message = new byte[secret.length+index.length+digest.length];
        System.arraycopy(secret,0,message,0,secret.length);
        System.arraycopy(index,0,message,secret.length,index.length);
        System.arraycopy(digest,0,message,secret.length+index.length,digest.length);//TODO need to add index
        System.out.println("Message unencrypted(byte):"+SecurityUtil.byteArrayToString(message));
        System.out.println("Message unencrypted(hex):"+SecurityUtil.byteArrayToHex(message));
        System.out.println("Message size:"+message.length);
        System.out.println("Secret size:"+secret.length);
        System.out.println("Index size:"+index.length);
        System.out.println("msgDigest size:"+digest.length);
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

        System.out.println("puzzle(SOLVING):"+SecurityUtil.byteArrayToString(puzzle.getPuzzle()));
        System.out.println("partKey(SOLVING):"+SecurityUtil.byteArrayToString(partKey));

        for(int i =-128;i<128;i++) {
            for(int j =-128;j<128;j++) {
                partKey[0] = (byte) i;
                partKey[1] = (byte) j;

                byte[] noise = CreateNoise(partKey,puzzle.getSizeCipherMessage());

                byte[] cipher = new byte[puzzle.getSizeCipherMessage()];
                System.arraycopy(puzzle.getPuzzle(),0,cipher,0,cipher.length);

                byte[] decipher = OneTimePadEncrypt(cipher,noise);//TODO fucking stupid variable name change it later


                byte[] messageDigestExpected = new byte[20/*TODO SHA1 size*/];
                System.arraycopy(decipher,decipher.length-20/*TODO SHA1 size*/,messageDigestExpected,0,messageDigestExpected.length);

                byte[] secret = new byte[puzzle.getSizeSecret()];
                System.arraycopy(decipher,0,secret,0,secret.length);
                byte[] messageDigestActual = SecurityUtil.Hash("SHA1",secret);

                if(MessageDigest.isEqual(messageDigestActual,messageDigestExpected)) {
                    System.out.println("Puzzle solved");
                    System.out.println("KEY(byte): "+ SecurityUtil.byteArrayToString(decipher));
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