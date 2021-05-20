package pt.ubi.di.security.model;

import java.io.Serializable;
/**
 * Class to store information about and individual puzzle (and the puzzle itself)
 * Or to store the encrypted index to return to puzzles creator, also stores and encrypted hash of the index
 *  plaintext   |        |       XB                   |
 *  message     | secret | index | SHA1(secret|index) |
 *
 *  random     |            XB                        |
 *   noise     | SHA1(key) | SHA1(SHA1(key)) | .....  |
 *
 *  puzzle     |        XB         |                 |
 *             | message XOR noise | key(incomplete) |
 */
public class MerklePuzzle implements Serializable {
    /**
     * puzzle with the this format:|cipher(secret)|key(incomplete)|<p>
     * cipher=secret+index+SHA1(secret) XOR noise
     */
    private final byte[] puzzle;
    /**
     * Byte size of the cipher
     */
    private final int sizeCipherMessage;
    /**
     * Byte size of the secret key
     */
    private final int sizeSecret;
    /**
     * Byte size of the cipher key
     * to make noise
     */
    private final int sizeKey;
    /**
     * Total byte size of the puzzle
     */
    private final int totalSize;
    /**
     * Amounts of bytes needed to guess in the incomplete key
     */
    private final int bytesToGuess;
    /**
     * Encrypted index of the chosen puzzle (Encrypted with the Key found)
     */
    private final byte[] indexEncrypted;
    /**
     * Encrypted hash of the index
     */
    private final byte[] indexHashEncrypted;

    /**
     * Constructor for a single Merkle Puzzle with information regarding it
     * @param puzzle byte[] - array byte of the puzzle
     * @param sizeCipherMessage int - amount of bytes that the cipher occupies on the puzzle
     * @param sizeKey int - amount of bytes that the key occupies on the cipher
     * @param bytesToGuess int - amount of bytes missing from the key (bytes that need to be guessed)
     * @param totalSize int - bytes in total in the puzzle
     * @param sizeSecret int - amount of bytes for the secret key
     */
    public MerklePuzzle(byte[] puzzle, int sizeCipherMessage, int sizeKey,int bytesToGuess,int totalSize,int sizeSecret) {
        this.puzzle = puzzle;
        this.sizeCipherMessage = sizeCipherMessage;
        this.sizeSecret = sizeSecret;
        this.sizeKey = sizeKey;
        this.totalSize = totalSize;
        this.bytesToGuess = bytesToGuess;
        this.indexEncrypted = new byte[0];
        this.indexHashEncrypted = new byte[0];
    }

    /**
     * Constructor to use for storing information about the solved puzzle
     * @param indexEncrypted byte[] - array byte of the encrypted index of the solved puzzle
     * @param indexHashEncrypted byte[] - array byte of the encrypted hash of the index of the solved puzzle
     */
    public MerklePuzzle(byte[] indexEncrypted,byte[] indexHashEncrypted) {
        puzzle = new byte[0];
        this.sizeCipherMessage = 0;
        this.sizeSecret = 0;
        this.sizeKey = 0;
        this.totalSize = 0;
        this.bytesToGuess = 0;
        this.indexEncrypted = indexEncrypted;
        this.indexHashEncrypted = indexHashEncrypted;


    }

    public byte[] getPuzzle() {
        return puzzle;
    }

    public int getBytesToGuess() {
        return bytesToGuess;
    }

    public int getSizeCipherMessage() {
        return sizeCipherMessage;
    }

    public int getSizeKey() {
        return sizeKey;
    }

    public int getSizeSecret() {
        return sizeSecret;
    }

    public int getTotalSize() {
        return totalSize;
    }

    public byte[] getIndexEncrypted() {
        return indexEncrypted;
    }

    public byte[] getIndexHashEncrypted() {
        return indexHashEncrypted;
    }

    public String toStringSolved() {
        return  "indexEncrypted= " + SecurityUtil.byteArrayToString(indexEncrypted) +
                "\nindexHashEncrypted= " + SecurityUtil.byteArrayToString(indexHashEncrypted);
    }

    @Override
    public String toString() {
        return  " \npuzzle=" + SecurityUtil.byteArrayToString(puzzle) +
                " Total size=" + totalSize +
                " Cipher size=" + sizeCipherMessage +
                " Unlock key size=" + sizeKey +
                " Bytes missing=" + bytesToGuess + "\n";
    }
}
