package pt.ubi.di.security.model;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.HashSet;
import java.util.Random;

/**
 * Class for utilities to be used along the program.
 * Provides encryption methods, number generators and others ....
 */
public class SecurityUtil {

    static SecureRandom secureRandomGenerator = new SecureRandom(); // uses SHA1PRNG
    static Random random = new Random();
    private static final int HASHSIZE=20; // size of the hash produced by SHA1
    private static final int BOCK_SIZE = 16;

    /**
     * Generates a prime number
     * @param bitLength int - amount of bits desired
     * @param verbose boolean - print messages
     * @return BigInteger - (probably) prime number
     */
    public static BigInteger generatePrime(int bitLength, boolean verbose) {
        BigInteger prime = BigInteger.probablePrime(bitLength,secureRandomGenerator);
        if (verbose)
            System.out.println("Random prime(" +bitLength+ "bits)(p): "+prime.toString());
        return prime;
    }

    /**
     * Generates a safe prime number<p>
     * Harder to attack -> Takes longer to generate
     * @param bitLength int - amount of bits desired
     * @param verbose  boolean - print messages
     * @return BigInteger (probably) prime number
     */
    public static BigInteger generateSafePrime(int bitLength, boolean verbose) {
        boolean flag;
        int count = 0;
        do {
            if (verbose)
                System.out.print(".");
            BigInteger prime = generatePrime(bitLength,false);
            if (verbose)
                System.out.print("*");
            flag = checkIfSafePrime(prime, 1,false);
            if (verbose) {
                System.out.print("+");
                count++;
            }
            if (flag) {
                System.out.print("\n");
                return prime;
            }
            if(count % 50 == 0)
                System.out.print("\n");
        } while (true);
    }

    /**
     * Generate a random BigInteger by giving a maxValue<p>
     *     0<=random<maxValue
     * Uses java.util.Random
     * @param maxValue BigInteger - max number
     * @param verbose boolean - print messages
     * @return BigInteger - random number BigInteger
     */
    public static BigInteger generateNumber(BigInteger maxValue, boolean verbose) {
        BigInteger number;
        do {
            number = new BigInteger(maxValue.bitLength(), random);
        } while (number.compareTo(maxValue) >= 0);
        if (verbose)
            System.out.println("Random number: "+number.toString());
        return number;
    }

    /**
     * Generate a random number in byte array format
     * @param byteSize - amount of bytes wanted
     * @return byte[] - natural number in byte array format
     */
    public static byte[] generateNumber(int byteSize) {
        byte[] bytesArray = new byte[byteSize];
        for (int i=0;i<byteSize;i++) {
            byte[] tmp = new byte[1];
            secureRandomGenerator.nextBytes(tmp);
            if ((int)tmp[0]<0) { // if the number is negative turn it positive
                tmp[0] += 128;
            }
            bytesArray[i]=tmp[0];
        }
        return bytesArray;
    }

    /**
     * Function to check if a given value is a prime or not
     * @param value BigInteger - value to test if prime
     * @param verbose boolean - print messages
     * @return boolean - true if value is prime, false if value is not prime
     */
    public static boolean checkIfPrime(BigInteger value, boolean verbose) {
        if (value.isProbablePrime(5)) { //kinda useless
            if (verbose)
                System.out.println("Value: " + value + "\n    is a prime.");
            return true;
        }
        if (verbose)
            System.out.println("Value: " + value + "\n    is not a prime.");
        return false;
    }

    /**
     * Function to check if a given value is a safe prime or not - NOT AS SLOW<p>
     * provides 2 different methods
     * @param value BigInteger - value to test if it is a safe prime
     * @param verbose boolean - print messages
     * @return boolean true if value is a safe prime, false if value is not a safe prime
     */
    public static boolean checkIfSafePrime(BigInteger value, int method, boolean verbose) {
        BigInteger result;
        if (method == 1) {
            result = value.subtract(BigInteger.ONE).divide(BigInteger.TWO);
        }
        else {
            result = value.multiply(BigInteger.TWO).add(BigInteger.ONE);
        }
        if (checkIfPrime(result,verbose)) {
            if (verbose)
                System.out.println("Value: " + value + "\n    is a safe prime.");
            return true;
        }
        if (verbose)
            System.out.println("Value: " + value + "\n    is not a safe prime.");
        return false;
    }

    /**
     * Function to find prime factors of a prime number, used to find a generator, Alternative Version, LESS time consuming<p>
     * It finds one or two prime factors only!!!!
     * @param storage HashSet<BigInteger> - hash storage
     * @param value BigInteger - prime to look for factors for
     */
    private static void findPrimeFactors(HashSet<BigInteger> storage, BigInteger value) {
        boolean flag = false;
        int count = 0;
        int arbitraryNumber = 1;
        while (value.mod(BigInteger.TWO).compareTo(BigInteger.ZERO) == 0) {//if value mod 2 == 0
            storage.add(BigInteger.TWO);
            value = value.divide(BigInteger.TWO);
        }
        for (BigInteger i = BigInteger.valueOf(3);i.compareTo(value.sqrt())<=0;i=i.add(BigInteger.TWO)) {
            if (flag) {
                break;
            }
            if (i.isProbablePrime(5)) {//if value mod i == 0
                storage.add(i);
                value = value.divide(i);
                if (count>=arbitraryNumber) {
                    flag = true;
                    break;
                }
                count++;
            }
        }
        if (value.compareTo(BigInteger.TWO)>0) {
            storage.add(value);
        }
    }

    /**
     * For Diffie-Hellman Zp*={1,2,....,p-1} theres a value g that for all g^0, g^1, .... g^(p-1) <p>
     * generates all Zp*, its always possible to find at least one g for Z*p <p><p>
     *
     * For now not confirming if they are safe primes so that (p-1)/2 is also a prime (allowing g=2) <p><p>
     *
     * PS: lets never do this again
     *
     * @param p BigInteger - assume its prime
     * @param verbose boolean - print messages
     * @return BigInteger - generator
     */
    public static BigInteger findGenerator(BigInteger p, boolean verbose) {
        HashSet<BigInteger> storage = new HashSet<>();
        BigInteger phi = p.subtract(BigInteger.ONE);
        BigInteger result;

        findPrimeFactors(storage,phi);

        if (verbose)
            System.out.println("Finished finding prime factors.");

        for (BigInteger r = BigInteger.TWO;r.compareTo(phi)<=0;r=r.add(BigInteger.ONE)) {
            boolean flag = false;
            for (BigInteger value : storage) {
                result=(r.modPow((phi.divide(value)),p));
                if (result.compareTo(BigInteger.ONE)==0) {
                    flag = true;
                    break;
                }
            }
            if (!flag) {
                if (verbose)
                    System.out.println("Smallest generator g found: "+r.toString());
                return r;
            }
        }
        if (verbose)
            System.out.println("Could not find a suitable generator :(");
        return BigInteger.ZERO;
    }

    /**
     * @param byteArr byte array to be converted to a hex String
     * @return String representation of hex value.
     * <p>
     * source: https://howtodoinjava.com/java/java-security/how-to-generate-secure-password-hash-md5-sha-pbkdf2-bcrypt-examples/
     */
    public static String byteArrayToHex(byte[] byteArr) {
        BigInteger value = new BigInteger(1, byteArr);
        String hex = value.toString(16);

        int paddingLength = (byteArr.length * 2) - hex.length();
        if (paddingLength > 0) {
            return String.format("%0" + paddingLength + "d", 0) + hex;
        } else {
            return hex;
        }
    }

    /**
     * Transform a byte array to String -> UTF_8
     * @param byteArray byte [] - byte array to transform
     * @return String - return the byte array equivalent in string format UTF8
     */
    public static String byteArrayToString(byte[] byteArray) {
        return new String(byteArray,StandardCharsets.UTF_8);
    }

    /**
     * Function to create a hash of a message<p>
     * md = MessageDigest.getInstance(algo);<p>
     * md.update(message);<p>
     * md.digest();
     * @param algo String - String of algorithm to use
     * @param message byte[] - byte array of message to digest
     * @return byte[] - array of bytes of the message digest (hash)
     */
    public static byte[] hash(String algo,byte[] message) {
        MessageDigest md = null;
        try {
            md = MessageDigest.getInstance(algo);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        assert md != null;
        md.update(message);
        return md.digest();
    }

    /**
     * Function to compare hashes and check if they are equal
     * @param hash1 byte[] - byte array of first hash
     * @param hash2 byte[] - byte array of second hash
     * @return boolean - true if they are equal false if not
     */
    public static boolean checkHash(byte[] hash1,byte[] hash2) {
        return MessageDigest.isEqual(hash1,hash2);
    }

    /**
     * Convert an int number to its byte[] representation
     * @param number int - number to convert
     * @return byte[] - array byte representation of the int number
     */
    public static byte[] intToByte(int number) {
        return BigInteger.valueOf(number).toByteArray();
    }

    /**
     * Convert an byte[] number to its int representation
     * @param number byte[] - number to convert
     * @return int - int representation of the byte[] number
     */
    public static int byteToInt(byte[] number) {
        return new BigInteger(number).intValue();
    }

    //------------------------------------------------------------------------------------------------------------------
    //-----------------------------------------------Encryption Functions-----------------------------------------------

    /**
     * Check if a byte array key is valid for use with AES-CBC (16/24/32 Bytes)
     * @param key byte[] - key to check size
     * @return true if key is okay to use else false
     */
    private static boolean checkKeyAES(byte[] key) {
        return key.length == 16 || key.length == 24 || key.length == 32;
    }

    /**
     * Function to encrypt a message.
     * Uses AES-CBC
     * iv is a 16 byte array that is appended at the start of the cipher
     * @param message byte[] - message desired to encrypt
     * @param key byte[] - byte array key
     * @return byte[] -  encrypted message, return empty array if unable to cipher
     */
    public static byte[] encryptSecurity(byte[] message,byte[] key) {
        if(!checkKeyAES(key)){
            System.out.println("(ENCRYPTION) -> Key length not valid, needs to be 16,24 or 32 Bytes.\nKey length: "+ key.length);
            return new  byte[0];
        }
        else if(message == null) {
            System.out.println("(ENCRYPTION) -> Message not valid");
            return new  byte[0];
        }
        else if(message.length==0){
            System.out.println("(ENCRYPTION) -> Message not valid");
            return new  byte[0];
        }
        SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");
        IvParameterSpec ivParameterSpec = generateIv();
        try {
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec);
            byte[] cipherBytes = cipher.doFinal(message);
            byte[] finalCipher = new byte[cipherBytes.length+ivParameterSpec.getIV().length];
            System.arraycopy(ivParameterSpec.getIV(),0,finalCipher,0,ivParameterSpec.getIV().length);
            System.arraycopy(cipherBytes,0,finalCipher,ivParameterSpec.getIV().length,cipherBytes.length);
            return finalCipher;
        } catch (Exception e) {
            System.out.println("Error encrypting message (AES): " + e.getMessage());
        }
        System.out.println(">Error encrypting.");
        return new byte[0];
    }

    /**
     * Function to decipher a cipher.
     * Uses AES-CBC to decipher
     * iv is a 16 byte array that is kept at the start of the cipher
     * @param finalCipher byte[] - cipher in byte array format
     * @param key byte[] - byte array key
     * @return byte[] -  decrypted cipher, return empty array if unable to decipher
     */
    public static byte[] decipherSecurity(byte[] finalCipher,byte[] key) {
        if(!checkKeyAES(key)){
            System.out.println("(ENCRYPTION) -> Key length not valid, needs to be 16,24 or 32 Bytes.\nKey length: "+ key.length);
            return new  byte[0];
        }
        else if(finalCipher == null) {
            System.out.println("(ENCRYPTION) -> Cipher not valid");
            return new  byte[0];
        }
        else if(finalCipher.length==0){
            System.out.println("(DECRYPTION) -> Cipher not valid");
            return new  byte[0];
        }
        SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");
        IvParameterSpec ivParameterSpec = new IvParameterSpec(finalCipher,0,BOCK_SIZE);
        try {
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
            cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivParameterSpec);
            return cipher.doFinal(finalCipher,BOCK_SIZE,finalCipher.length - BOCK_SIZE);
        } catch (Exception e) {
            System.out.println("Error decrypting cipher (AES): " + e.getMessage());
        }
        System.out.println(">Error decrypting.");
        return new byte[0];
    }

    /**
     * Create noise to encrypt message with
     * Example: NOISE(40B): SHA1(key)(20B) | SHA1(SHA1(key))(20B)
     * @param key byte[] - array of bytes to be used to generate noise
     * @param sizeBytes int - size in bytes of the noise
     * @return byte[]- noise in byte array
     */
    private static byte[] createNoise(byte[] key, int sizeBytes) {
        int index = 0;
        int n = sizeBytes /HASHSIZE;
        byte[] prevDigest = SecurityUtil.hash("SHA1",key);
        byte[] noise = new byte[sizeBytes];
        System.arraycopy(prevDigest,0,noise,index,(sizeBytes <HASHSIZE) ? noise.length : prevDigest.length);
        index = prevDigest.length;
        for(int i=1;i<n;i++) {
            byte[] digest = SecurityUtil.hash("SHA1",prevDigest);
            System.arraycopy(digest,0,noise,index,(index <HASHSIZE) ? noise.length : digest.length);
            index += digest.length;
            prevDigest = digest;
        }
        return noise;
    }

    /**
     * One time pad encryption by doing --> message XOR key
     * @param message byte[] - message to encrypt/decipher
     * @param key byte[] - array of bytes to be used to generate noise
     * @return byte[] of encrypted/decrypted message
     */
    public static byte[] oneTimePadEncrypt(byte[] message, byte[] key) {
        byte[] noise = createNoise(key,message.length);
        if (message.length != noise.length) {
            System.out.println("OneTimePadEncrypt -> Error Key not same size as message");
            return new byte[0];
        }
        byte[] cipherBytes = new byte[message.length];
        for(int i=0;i<message.length;i++) {
            cipherBytes[i] = (byte) (message[i] ^ noise[i]);
        }
        return cipherBytes;
    }

    /**
     * Function to initialize an byte array to be used as iv for AES encryption
     * array size = 16Bytes
     * @return IvParameterSpec - returns the iv in the required state
     */
    private static IvParameterSpec generateIv() {
        byte[] iv = new byte[BOCK_SIZE];
        secureRandomGenerator.nextBytes(iv);
        return new IvParameterSpec(iv);
    }

    /*----------------------------------------------------------------------------------------------------------------*/

    private static final int KAP_DH = 0;
    private static final int KAP_MP = 1;
    private static final int KAP_RSA = 2;
    private static final int FAIL = -1;
    private static final int OK = 0;

    /**
     * @param outputStream ObjectOutputStream - output information to send information
     * @param inputStream ObjectInputStream - inputStream to receive information
     * @param sessionKey byte[] - session key wished to be shared
     * @return byte[] - returns the key in byte array format
     */
    public static byte[] shareSessionKeys(ObjectOutputStream outputStream, ObjectInputStream inputStream, String[] options, byte[] sessionKey) {
        int KAP =KAP_DH;
        boolean hmacStatus = false;
        int index = SecurityUtil.lookOptions(options,new String[]{"-mkp"});
        if(index != -1) {
            System.out.println(">Starting Session Key distribution using Merkle Puzzle");
            KAP =KAP_MP;
        }
        if(KAP==KAP_DH) {
            System.out.println(">Starting Session Key distribution using Diffie-Hellman");
        }
        index = SecurityUtil.lookOptions(options,new String[]{"-hmac"});
        if (index!=-1)
            hmacStatus = true;
        try {
            outputStream.writeInt(KAP);
            outputStream.writeObject(hmacStatus);
        } catch (Exception e) {
            System.out.println("Error sending KAP: "+ e.getMessage());
        }

        byte[] cipherKey = new byte[32];
        byte[] hmac = new byte[512/8];

        if(KAP == KAP_DH) {
            cipherKey =  SecurityDH.startExchange(outputStream,inputStream,new String[]{"-l","256"});
        }
        else if(KAP == KAP_MP) {
            cipherKey = SecurityMP.startExchange(outputStream, inputStream,new String[]{"-l","32"});
        }

        if(cipherKey.length == 0) {
            System.out.println("Error with cipher key.");
            return new byte[0];
        }

        byte[] cipher = SecurityUtil.encryptSecurity(sessionKey, cipherKey);

        if(hmacStatus)
            hmac = SecurityUtil.hmac(cipher,cipherKey);
        try {
            outputStream.writeObject(cipher);
            if(hmacStatus) {
                System.out.println(">Using hmac.");
                outputStream.writeObject(hmac);
            }
        } catch (Exception e) {
            System.out.println("Error sending cipher: "+ e.getMessage());
        }
        try {
            int messageIntegrity =(int) inputStream.readObject();
            if(messageIntegrity == OK)
                return SecurityUtil.decipherSecurity(cipher, cipherKey);
            else if(messageIntegrity == FAIL){
                System.out.println(">HMAC invalid, message integrity not confirmed.");
                return new byte[0];
            }
        } catch (Exception e) {
            System.out.println("Error sending status: "+ e.getMessage());
        }
        return new byte[0];
    }

    /**
     * @param outputStream ObjectOutputStream - output information to send information
     * @param inputStream ObjectInputStream - inputStream to receive information
     * @return byte[] - returns the key in byte array format
     */
    public static byte[] shareSessionKeys(ObjectOutputStream outputStream, ObjectInputStream inputStream, String[] options) {
        int lengthByte = 64;
        int index = SecurityUtil.lookOptions(options,new String[]{"-l","-length","--length"});
        if (index!=-1) {
            try {
                lengthByte = Integer.parseInt(options[index + 1]);
                if(lengthByte<=0)
                    lengthByte = 64;
            } catch (Exception e) {
                System.out.println("Error on length: " + e.getMessage() + " 64 being used as default.");
            }
        }
        return shareSessionKeys(outputStream,inputStream,options,SecurityUtil.generateNumber(lengthByte));
    }

    /**
     * @param outputStream ObjectOutputStream - output information to send information
     * @param inputStream ObjectInputStream - inputStream to receive information
     * @return byte[] - returns the key in byte array format
     */
    public static byte[] participateSessionKeys(ObjectOutputStream outputStream, ObjectInputStream inputStream) {
        int KAP = KAP_DH;
        boolean hmacStatus = false;
        boolean hmacCheck = true;
        try {
            KAP = inputStream.readInt();
            hmacStatus =(boolean) inputStream.readObject();

        } catch (Exception e) {
            System.out.println("Error receiving KAP: "+ e.getMessage());
        }
        byte[] cipherKey = new byte[32];
        if(KAP == KAP_DH) {
            cipherKey =  SecurityDH.receiveExchange(outputStream,inputStream);
        }
        else if(KAP == KAP_MP) {
            cipherKey =  SecurityMP.receiveExchange(outputStream,inputStream);
        }
        byte[] cipher = new byte[0];
        try {
            cipher = (byte[]) inputStream.readObject();
            if(hmacStatus) {
                System.out.println(">Using hmac.");
                byte[] hmac =(byte[]) inputStream.readObject();
                hmacCheck = hmacCheck(hmac,cipher,cipherKey);
            }
        } catch (Exception e) {
            System.out.println("Error receiving cipher: "+ e.getMessage());
        }
        try {
            if(hmacCheck) {
                outputStream.writeObject(OK);
                return SecurityUtil.decipherSecurity(cipher, cipherKey);
            }
            else {
                System.out.println(">HMAC invalid, message integrity not confirmed.");
                outputStream.writeObject(FAIL);
                return new byte[0];
            }
        } catch (Exception e) {
            System.out.println("Error sending status: "+ e.getMessage());
        }
        return new byte[0];
    }

    /**
     *
     * @param outputStream ObjectOutputStream - output information to send information
     * @param inputStream ObjectInputStream - inputStream to receive information
     * @param message String - the clean message desired to be encrypted and sent
     * @param key byte[] - the key in byte array format
     * @param options String[] - array of options
     */
    public static void sendMessage(ObjectOutputStream outputStream, ObjectInputStream inputStream,String message,byte[] key, String[] options) {
        byte[] cipher;
        if(checkKeyAES(key))
            cipher = encryptSecurity(message.getBytes(),key);
        else {
            cipher = oneTimePadEncrypt(message.getBytes(),key);
        }
        try {
            outputStream.writeObject(cipher);
        } catch (Exception e) {
            System.out.println("Error sending message: "+ e.getMessage());
        }
        System.out.println(">Message sent.");
    }

    /**
     * Receive incrypted text message and decrypt them sending the clean text.
     * Uses AES-CBC
     * @param outputStream ObjectOutputStream - output information to send information
     * @param inputStream ObjectInputStream - inputStream to receive information
     * @param key byte[] - the key in byte array format
     * @return String - returns the clean message in String format
     */
    public static String receiveMessage(ObjectOutputStream outputStream, ObjectInputStream inputStream,byte[] key) {
        try {
            byte[] cipher = (byte[]) inputStream.readObject();
            byte[] message;
            if(checkKeyAES(key))
                message = decipherSecurity(cipher,key);
            else {
                message = oneTimePadEncrypt(cipher,key);
            }
            System.out.print(">Message received: ");
            return byteArrayToString(message);

        } catch (Exception e) {
            System.out.println("Error receiving message: "+ e.getMessage());
        }
        return "";
    }

    public static void checkSharedKey(ObjectOutputStream outputStream, ObjectInputStream inputStream,byte[] key) {
        byte[] ephemeralKey = SecurityDH.startExchange(outputStream,inputStream,new String[]{"-l","256"});
        try {
            outputStream.writeObject(hmac(key,ephemeralKey));
            int v = (int) inputStream.readObject();
            if(v == OK) {
                System.out.println(">Key is the same.");
            }
            else if(v == FAIL){
                System.out.println(">Key is not the same recommend changing it.");
            }
        } catch (Exception e) {
            System.out.println("Error sending message: "+ e.getMessage());
        }
    }

    public static void checkSharedKey2(ObjectOutputStream outputStream, ObjectInputStream inputStream,byte[] key) {
        byte[] ephemeralKey = SecurityDH.receiveExchange(outputStream,inputStream);
        try {
            byte[] hmac = (byte[]) inputStream.readObject();
            if(hmacCheck(hmac,key,ephemeralKey)) {
                System.out.println(">Key is the same.");
                outputStream.writeObject(OK);
            }
            else {
                System.out.println(">Key is not the same recommend changing it.");
                outputStream.writeObject(FAIL);
            }

        } catch (Exception e) {
            System.out.println("Error sending message: "+ e.getMessage());
        }
    }

    public static byte[] hmac(byte[] message,byte[] key) {
        byte[] msd = hash("SHA3-512", message);
        return  encryptSecurity(msd, key);
    }

    public static boolean hmacCheck(byte[] hmac,byte[] message, byte[] key) {
        byte[] msg = decipherSecurity(hmac, key);
        byte[] msd = hash("SHA3-512", message);
        return checkHash(msg, msd);
    }

    /**
     * This function returns the index (position) on the String array where any word from the words array was found
     * @param options String[] - array where to look for words
     * @param words String[] - array of the words to look for
     * @return int - index of the position where the word was found, returns -1 if no word was found
     */
    public static int lookOptions(String[] options,String[] words) {
        for(int i=0;i<options.length;i++) {
            for(String word : words) {
                if(options[i].equals(word))
                    return i;
            }
        }
        return -1;
    }

    public static void shareSessionHelp() {
        System.out.println(
                """
                        Session Key sharing Commands =====================================================================================
                        -l -length --length \033[3mlengthByte\033[0m, length of the key to share (byte), default is 64
                        -dh -mkp, algorithm to use for key pre-distribution
                        -hmac, use hmac to verify integrity of session key exchange
                        -v -verbose --verbose, shows verbose
                        ==================================================================================================================
                        """
        );
    }
}